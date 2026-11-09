//! Wall-clock time and durations, in milliseconds since the Unix epoch.

/// Now, or `None` if the system clock is before 1970 or past the `i64`
/// range. Callers fail closed on `None`.
pub(crate) fn now_ms() -> Option<i64> {
    let since_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?;
    i64::try_from(since_epoch.as_millis()).ok()
}

/// Why [`parse_duration`] refused its input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurationError {
    /// Not a positive whole number followed by `s`, `m`, `h` or `d`.
    Malformed,
    /// Well formed, but too long to count in milliseconds.
    TooLong,
}

/// `"90s"`, `"30m"`, `"8h"`, `"7d"` in milliseconds.
pub fn parse_duration(text: &str) -> Result<i64, DurationError> {
    let split = text
        .find(|c: char| !c.is_ascii_digit())
        .ok_or(DurationError::Malformed)?;
    let (number, unit) = text.split_at(split);
    let unit_ms: i64 = match unit {
        "s" => 1_000,
        "m" => 60_000,
        "h" => 3_600_000,
        "d" => 86_400_000,
        _ => return Err(DurationError::Malformed),
    };
    if number.is_empty() {
        return Err(DurationError::Malformed);
    }
    // Only digits are left, so a parse failure means the number overflowed.
    let amount: i64 = number.parse().map_err(|_| DurationError::TooLong)?;
    if amount == 0 {
        return Err(DurationError::Malformed);
    }
    amount.checked_mul(unit_ms).ok_or(DurationError::TooLong)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_parse_in_every_unit() {
        assert_eq!(parse_duration("90s"), Ok(90_000));
        assert_eq!(parse_duration("30m"), Ok(1_800_000));
        assert_eq!(parse_duration("8h"), Ok(28_800_000));
        assert_eq!(parse_duration("7d"), Ok(604_800_000));
        assert_eq!(parse_duration("08h"), Ok(28_800_000));
    }

    #[test]
    fn malformed_and_zero_durations_are_rejected() {
        for bad in [
            "", "8", "h", "0h", "-1h", "+1h", "8w", "1.5h", "8H", "1hh", "1 h",
        ] {
            assert_eq!(
                parse_duration(bad),
                Err(DurationError::Malformed),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn durations_too_long_to_count_are_told_apart() {
        let too_big = format!("{}d", i64::MAX);
        for long in ["99999999999999999999h", too_big.as_str()] {
            assert_eq!(
                parse_duration(long),
                Err(DurationError::TooLong),
                "{long:?}"
            );
        }
        let largest = format!("{}s", i64::MAX / 1_000);
        assert_eq!(parse_duration(&largest), Ok(i64::MAX / 1_000 * 1_000));
    }
}
