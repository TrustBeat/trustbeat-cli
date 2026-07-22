//! Terminal output.
//!
//! Colour is applied only when stdout is a TTY and `NO_COLOR` is unset
//! (https://no-color.org). Every command also has a `--json` mode whose output
//! is the contract for scripts — keep it stable.

use std::io::IsTerminal;
use std::sync::OnceLock;

fn colour_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED
        .get_or_init(|| std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal())
}

fn paint(code: &str, s: &str) -> String {
    if colour_enabled() {
        format!("\x1b[{code}m{s}\x1b[0m")
    } else {
        s.to_string()
    }
}

pub fn green(s: &str) -> String {
    paint("32", s)
}
pub fn red(s: &str) -> String {
    paint("31", s)
}
pub fn yellow(s: &str) -> String {
    paint("33", s)
}
pub fn dim(s: &str) -> String {
    paint("2", s)
}
pub fn bold(s: &str) -> String {
    paint("1", s)
}

pub fn tick() -> String {
    green("✓")
}
pub fn cross() -> String {
    red("✗")
}
pub fn skip() -> String {
    yellow("−")
}

/// Formats a Unix timestamp as RFC 3339 UTC without pulling in a date crate.
pub fn format_unix_utc(secs: i64) -> String {
    // days since epoch → civil date (Howard Hinnant's algorithm)
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);

    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_known_timestamps() {
        assert_eq!(format_unix_utc(0), "1970-01-01T00:00:00Z");
        // the demo proof's genTime
        assert_eq!(format_unix_utc(1_775_289_228), "2026-04-04T07:53:48Z");
        assert_eq!(format_unix_utc(1_000_000_000), "2001-09-09T01:46:40Z");
        // leap day
        assert_eq!(format_unix_utc(1_709_164_800), "2024-02-29T00:00:00Z");
    }

    #[test]
    fn colour_is_suppressed_when_not_a_tty() {
        // Tests do not run against a terminal, so painting must be a no-op.
        assert_eq!(green("ok"), "ok");
        assert_eq!(bold("ok"), "ok");
    }
}
