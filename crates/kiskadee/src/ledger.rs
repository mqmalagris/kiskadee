//! `kiskadee ledger`: read-only views of `ledger.db` (ADR 0003).

use std::error::Error;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Subcommand;
use kiskadee_core::ledger::{Body, Entry, Ledger, Status};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(clap::Args)]
#[command(args_conflicts_with_subcommands = true)]
pub struct Args {
    #[command(subcommand)]
    action: Option<Action>,

    /// Show entries since a time: a duration back from now ("30m", "2h",
    /// "7d") or a timestamp ("2026-10-29T08:00:00Z"). Default: 24h.
    #[arg(long, value_name = "WHEN")]
    since: Option<String>,
}

#[derive(Subcommand)]
enum Action {
    /// Check the hash chain from the first entry to the last.
    Verify,
    /// Totals, distinct tokens, days with agent calls, and calls per day.
    Stats,
}

/// How many of the most recent active days `ledger stats` lists.
const RECENT_DAYS: usize = 30;

pub fn run(args: Args) -> Result<ExitCode> {
    let path = kiskadee_platform::paths::ledger_db()
        .ok_or("can't find a data directory; set KISKADEE_HOME")?;
    let ledger = Ledger::open_read_only(&path)?;
    match args.action {
        Some(Action::Verify) => verify(&ledger, path),
        Some(Action::Stats) => stats(&ledger),
        None => list(&ledger, args.since.as_deref().unwrap_or("24h")),
    }
}

fn verify(ledger: &Ledger, path: PathBuf) -> Result<ExitCode> {
    let report = ledger.verify()?;
    if let Some(problem) = &report.problem {
        println!("BROKEN: {problem}");
        println!(
            "{} entries verified before it, in {}",
            report.entries,
            path.display()
        );
        return Ok(ExitCode::FAILURE);
    }
    println!("ok: {} entries, chain intact", report.entries);
    println!("head {}", report.head_hex());
    if !report.orphans.is_empty() {
        println!(
            "{} call(s) without an outcome (in flight, or interrupted by a crash): {}",
            report.orphans.len(),
            report
                .orphans
                .iter()
                .map(|seq| format!("#{seq}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn stats(ledger: &Ledger) -> Result<ExitCode> {
    let stats = ledger.stats()?;
    println!("entries     {}", stats.entries);
    println!("calls       {}", stats.begins);
    for (status, count) in Status::ALL.iter().zip(stats.outcomes) {
        println!("  {:<10}{count}", status.as_str());
    }
    println!("  no outcome {}", stats.orphans);
    println!("tokens      {}", stats.tokens);
    println!(
        "agent days  {} (latest streak {})",
        stats.agent_days(),
        stats.agent_streak()
    );
    if let (Some(first), Some(last)) = (stats.first_ts_ms, stats.last_ts_ms) {
        println!("first       {}", timestamp(first));
        println!("last        {}", timestamp(last));
    }
    if !stats.days.is_empty() {
        println!();
        println!("day (UTC)   calls  agent  tokens");
        let skip = stats.days.len().saturating_sub(RECENT_DAYS);
        for day in &stats.days[skip..] {
            println!(
                "{}  {:>5}  {:>5}  {:>6}",
                date(day.start_ms),
                day.calls,
                day.agent_calls,
                day.tokens
            );
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn list(ledger: &Ledger, since: &str) -> Result<ExitCode> {
    let entries = ledger.since(parse_since(since, jiff::Timestamp::now())?)?;
    if entries.is_empty() {
        println!("no entries since {since}");
    }
    for entry in &entries {
        println!("{}", line(entry));
    }
    Ok(ExitCode::SUCCESS)
}

fn line(entry: &Entry) -> String {
    let head = format!("#{:<5} {}", entry.seq, timestamp(entry.ts_ms));
    match &entry.body {
        Body::Begin(call) => format!(
            "{head}  begin    {}  {}  {}{}",
            clean(&call.actor.to_string()),
            clean(call.account.as_deref().unwrap_or("-")),
            clean(&call.verb),
            call.target
                .as_deref()
                .map(|target| format!(" {}", clean(target)))
                .unwrap_or_default()
        ),
        Body::Outcome {
            begin_seq,
            status,
            detail,
        } => format!(
            "{head}  outcome  #{begin_seq} {}{}",
            status.as_str(),
            detail
                .as_deref()
                .map(|detail| format!(": {}", clean(detail)))
                .unwrap_or_default()
        ),
    }
}

/// Stored text goes to a terminal: replace control characters so an escape
/// sequence in an id can't drive the terminal, and invisible format
/// characters so a bidi override can't make a line read differently.
fn clean(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_control() || is_invisible_format(c) {
                '?'
            } else {
                c
            }
        })
        .collect()
}

/// Unicode format (Cf) characters a terminal renders as nothing or uses to
/// reorder text: bidi embeddings, overrides and isolates, zero-width
/// characters, the soft hyphen and the byte-order mark.
fn is_invisible_format(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{061C}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
    )
}

fn timestamp(ms: i64) -> String {
    jiff::Timestamp::from_millisecond(ms)
        .map(|ts| format!("{ts:.3}"))
        .unwrap_or_else(|_| format!("{ms}ms"))
}

fn date(ms: i64) -> String {
    jiff::Timestamp::from_millisecond(ms)
        .map(|ts| ts.to_zoned(jiff::tz::TimeZone::UTC).date().to_string())
        .unwrap_or_else(|_| format!("{ms}ms"))
}

/// "90s", "30m", "2h", "7d" back from `now`, or an RFC 3339 timestamp.
fn parse_since(value: &str, now: jiff::Timestamp) -> Result<i64> {
    if let Ok(ts) = value.parse::<jiff::Timestamp>() {
        return Ok(ts.as_millisecond());
    }
    let split = value
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(value.len());
    let (number, unit) = value.split_at(split);
    let seconds = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3_600,
        "d" => 86_400,
        _ => 0,
    };
    let amount: i64 = number.parse().unwrap_or(0);
    if seconds == 0 || amount <= 0 {
        return Err(format!(
            "--since {value:?}: use a duration like 30m, 2h, 7d or a timestamp like 2026-10-29T08:00:00Z"
        )
        .into());
    }
    let back = amount
        .checked_mul(seconds * 1_000)
        .ok_or("--since is too far back")?;
    Ok(now.as_millisecond().saturating_sub(back))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn since_accepts_durations_and_timestamps() {
        let now: jiff::Timestamp = "2026-10-29T12:00:00Z".parse().unwrap();
        let ms = now.as_millisecond();
        assert_eq!(parse_since("90s", now).unwrap(), ms - 90_000);
        assert_eq!(parse_since("2h", now).unwrap(), ms - 7_200_000);
        assert_eq!(parse_since("7d", now).unwrap(), ms - 604_800_000);
        assert_eq!(
            parse_since("2026-10-29T11:00:00Z", now).unwrap(),
            ms - 3_600_000
        );
        for bad in ["", "h", "2", "2w", "-1h", "0m", "yesterday"] {
            assert!(parse_since(bad, now).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn since_rejects_durations_that_overflow() {
        let now = jiff::Timestamp::UNIX_EPOCH;
        let error = parse_since(&format!("{}d", i64::MAX), now).unwrap_err();
        assert!(error.to_string().contains("too far back"), "{error}");
        assert!(parse_since("99999999999999999999d", now).is_err());
    }

    #[test]
    fn clean_replaces_escapes_and_bidi_overrides() {
        assert_eq!(clean("inbox\u{1b}[2J"), "inbox?[2J");
        assert_eq!(clean("abc\u{202E}fed"), "abc?fed");
        assert_eq!(clean("a\u{2066}b\u{2069}\u{200B}"), "a?b??");
        assert_eq!(clean("caf\u{e9} \u{1F426}"), "caf\u{e9} \u{1F426}");
    }
}
