//! Wall-clock times in the machine's own time zone, for the dashboard.
//!
//! The zone comes from the C library, which is how every other program on
//! the machine finds it; the arithmetic is done here so it can be tested.

use std::os::raw::{c_char, c_int, c_long};

/// The C library's broken-down time, as laid out on macOS and Linux.
#[repr(C)]
struct Tm {
    fields: [c_int; 9],
    gmtoff: c_long,
    zone: *const c_char,
}

extern "C" {
    fn localtime_r(time: *const i64, result: *mut Tm) -> *mut Tm;
}

/// How many seconds local time is ahead of UTC at the given moment (given
/// as seconds since the Unix epoch), daylight saving included. Zero if the
/// C library cannot say.
pub fn local_offset(unix_secs: u64) -> i64 {
    let time = i64::try_from(unix_secs).unwrap_or(0);
    let mut tm = Tm { fields: [0; 9], gmtoff: 0, zone: std::ptr::null() };
    // SAFETY: both pointers are valid for the call, and `localtime_r` only
    // writes a `struct tm` through the second.
    let filled = unsafe { localtime_r(&time, &mut tm) };
    if filled.is_null() {
        0
    } else {
        tm.gmtoff as i64
    }
}

const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/// Day number since the epoch, and the second within that day, in the zone
/// that is `offset` seconds ahead of UTC.
fn local_day(unix_secs: u64, offset: i64) -> (i64, i64) {
    let local = i64::try_from(unix_secs).unwrap_or(0).saturating_add(offset);
    (local.div_euclid(86400), local.rem_euclid(86400))
}

/// Month (1 to 12) and day of the month for a day number since the epoch.
fn month_day(days: i64) -> (usize, i64) {
    // The usual civil-from-days arithmetic, on years that begin in March.
    let z = days + 719_468;
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 { shifted_month + 3 } else { shifted_month - 9 };
    (month as usize, day)
}

/// `14:03:22`, in the zone that is `offset` seconds ahead of UTC.
pub fn time_of_day(unix_secs: u64, offset: i64) -> String {
    let (_, second) = local_day(unix_secs, offset);
    format!("{:02}:{:02}:{:02}", second / 3600, second % 3600 / 60, second % 60)
}

/// The time of day if `unix_secs` falls on the same local day as `now`,
/// and otherwise the date as well, as in `Nov 10 14:03`.
pub fn stamp(unix_secs: u64, now: u64, zone: fn(u64) -> i64) -> String {
    let offset = zone(unix_secs);
    let (day, second) = local_day(unix_secs, offset);
    if day == local_day(now, zone(now)).0 {
        return time_of_day(unix_secs, offset);
    }
    let (month, day_of_month) = month_day(day);
    format!("{} {} {:02}:{:02}", MONTHS[month - 1], day_of_month, second / 3600, second % 3600 / 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pacific(_: u64) -> i64 {
        -8 * 3600
    }

    #[test]
    fn times_are_shifted_into_the_local_zone() {
        // 2023-11-14 22:13:20 UTC.
        let t = 1_700_000_000;
        assert_eq!(time_of_day(t, 0), "22:13:20");
        assert_eq!(time_of_day(t, -8 * 3600), "14:13:20");
        assert_eq!(time_of_day(t, 5 * 3600 + 1800), "03:43:20", "half-hour zones, past midnight");
        assert_eq!(time_of_day(0, -3600), "23:00:00", "before the epoch in local time");
    }

    #[test]
    fn other_days_show_the_date() {
        let t = 1_700_000_000;
        assert_eq!(stamp(t, t + 600, pacific), "14:13:20");
        assert_eq!(stamp(t, t + 86400, pacific), "Nov 14 14:13");
        // 06:13 UTC on the 15th is still the 14th in California.
        assert_eq!(stamp(t + 8 * 3600, t, pacific), "22:13:20");
        // Leap day and year ends.
        assert_eq!(stamp(1_709_208_000, 0, |_| 0), "Feb 29 12:00");
        assert_eq!(stamp(1_704_067_199, 0, |_| 0), "Dec 31 23:59");
        assert_eq!(stamp(1_704_067_200, 0, |_| 0), "Jan 1 00:00");
    }

    #[test]
    fn local_offset_is_a_plausible_zone() {
        let offset = local_offset(1_700_000_000);
        assert!((-14 * 3600..=14 * 3600).contains(&offset), "{offset}");
        assert_eq!(offset % 60, 0);
    }

    /// The machine's own `date` must agree about its time zone, in winter
    /// and in summer.
    #[cfg(target_os = "macos")]
    #[test]
    fn agrees_with_the_system_date_command() {
        for t in [1_700_000_000u64, 1_720_000_000] {
            let output = std::process::Command::new("date").args(["-r", &t.to_string(), "+%H:%M:%S"]).output();
            let Ok(output) = output else { return };
            assert_eq!(time_of_day(t, local_offset(t)), String::from_utf8_lossy(&output.stdout).trim());
        }
    }
}
