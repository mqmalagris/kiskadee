//! `profiles.toml`: the human-readable file Capability tokens are minted from.

use kiskadee_core::profiles::{ProfileError, Profiles, Selector};
use kiskadee_core::verb::Verb;

#[test]
fn the_built_in_profiles_are_readonly_triage_and_drafter() {
    let profiles = Profiles::built_in();
    assert_eq!(
        profiles.names().collect::<Vec<_>>(),
        ["drafter", "readonly", "triage"]
    );
    let readonly = profiles.get("readonly").unwrap();
    assert_eq!(
        readonly.ceiling.verbs.iter().copied().collect::<Vec<_>>(),
        [Verb::List, Verb::Read, Verb::Search]
    );
    assert_eq!(readonly.ceiling.accounts, Selector::All);
    assert_eq!(readonly.max_ttl_ms, 8 * 3_600_000);
}

#[test]
fn no_built_in_profile_can_send_or_read_untrusted_content() {
    let profiles = Profiles::built_in();
    for name in ["readonly", "triage", "drafter"] {
        let verbs = &profiles.get(name).unwrap().ceiling.verbs;
        for risky in [
            Verb::SendRequest,
            Verb::ReadUntrusted,
            Verb::AttachmentFetch,
        ] {
            assert!(!verbs.contains(&risky), "{name} allows {risky}");
        }
    }
}

#[test]
fn a_missing_file_means_the_built_in_profiles() {
    let dir = tempfile::tempdir().unwrap();
    let loaded = Profiles::load(&dir.path().join("profiles.toml")).unwrap();
    assert_eq!(loaded, Profiles::built_in());
}

#[test]
fn a_file_replaces_the_defaults_instead_of_merging() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("profiles.toml");
    std::fs::write(
        &path,
        r#"
        [invoices]
        verbs = ["search", "read", "attachment.extract"]
        accounts = ["work"]
        resources = ["Invoices", "INBOX"]
        read_budget = 40
        max_ttl = "30m"
        "#,
    )
    .unwrap();
    let profiles = Profiles::load(&path).unwrap();
    assert_eq!(profiles.names().collect::<Vec<_>>(), ["invoices"]);
    let invoices = profiles.get("invoices").unwrap();
    assert_eq!(invoices.ceiling.accounts, Selector::only(["work"]));
    assert_eq!(
        invoices.ceiling.resources,
        Selector::only(["INBOX", "Invoices"])
    );
    assert_eq!(
        (invoices.ceiling.read_budget, invoices.max_ttl_ms),
        (40, 1_800_000)
    );
    assert!(profiles.get("readonly").is_none());
}

fn rejects(toml: &str, expected: &str) {
    let error = Profiles::parse(toml).expect_err(toml);
    let message = error.to_string();
    assert!(
        message.contains(expected),
        "expected {expected:?} in {message:?}"
    );
}

const VALID: &str = r#"
verbs = ["list"]
accounts = "*"
resources = "*"
read_budget = 1
max_ttl = "1h"
"#;

#[test]
fn a_verb_outside_the_verb_set_is_rejected() {
    rejects(
        &format!(
            "[p]\n{}",
            VALID.replace(r#"["list"]"#, r#"["list", "imap.raw"]"#)
        ),
        "unknown Verb \"imap.raw\"",
    );
}

#[test]
fn a_misspelled_field_is_rejected_not_ignored() {
    rejects(&format!("[p]\n{VALID}\nmax_tll = \"1d\""), "max_tll");
}

#[test]
fn an_empty_list_is_rejected_because_it_allows_nothing() {
    rejects(
        &format!(
            "[p]\n{}",
            VALID.replace(r#"accounts = "*""#, "accounts = []")
        ),
        "allows nothing",
    );
    rejects(
        &format!("[p]\n{}", VALID.replace(r#"["list"]"#, "[]")),
        "allows nothing",
    );
}

#[test]
fn only_a_star_means_everything() {
    rejects(
        &format!(
            "[p]\n{}",
            VALID.replace(r#"accounts = "*""#, r#"accounts = "all""#)
        ),
        "use \"*\"",
    );
}

#[test]
fn a_bad_max_ttl_and_a_bad_name_are_rejected() {
    rejects(
        &format!("[p]\n{}", VALID.replace("\"1h\"", "\"forever\"")),
        "max_ttl",
    );
    rejects(&format!("[\"Read Only\"]\n{VALID}"), "names use a-z");
}

#[test]
fn a_missing_field_a_wrong_type_and_broken_toml_are_rejected() {
    rejects(
        &format!("[p]\n{}", VALID.replace("max_ttl = \"1h\"", "")),
        "max_ttl",
    );
    rejects(
        &format!(
            "[p]\n{}",
            VALID.replace("read_budget = 1", "read_budget = -1")
        ),
        "read_budget",
    );
    rejects("[p\nverbs = [", "profiles:");
}

#[test]
fn a_path_that_is_a_directory_is_an_io_error() {
    let dir = tempfile::tempdir().unwrap();
    assert!(matches!(
        Profiles::load(dir.path()),
        Err(ProfileError::Io(..))
    ));
}

#[test]
fn a_file_with_no_profiles_is_rejected() {
    assert!(matches!(
        Profiles::parse("# nothing\n"),
        Err(ProfileError::Parse(_))
    ));
}
