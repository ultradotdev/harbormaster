//! Asking for a password on the terminal without showing it.

use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::os::fd::AsRawFd;

use anyhow::{bail, Context, Result};
use zeroize::Zeroize;

use crate::password::Secret;

/// The terminal's settings from before echo was switched off, for the
/// interrupt handler to put back. Written before the handler is installed.
static mut SAVED: Option<(libc::c_int, libc::termios)> = None;

/// Ctrl-C while typing: put echo back before going, or the shell that
/// started us is left typing blind.
extern "C" fn restore_and_exit(_signal: libc::c_int) {
    // SAFETY: only async-signal-safe calls, and `SAVED` is not written
    // while this handler is installed.
    unsafe {
        if let Some((fd, settings)) = *std::ptr::addr_of!(SAVED) {
            libc::tcsetattr(fd, libc::TCSAFLUSH, &settings);
            libc::write(fd, b"\n".as_ptr().cast(), 1);
        }
        libc::_exit(130);
    }
}

/// Shows `prompt` on the controlling terminal and reads one line with echo
/// off. It uses the terminal itself, not stdin, so it works however the
/// command's input and output are redirected.
pub fn read_password(prompt: &str) -> Result<Secret> {
    let mut tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .context("there is no terminal to ask for the password on (over SSH use `ssh -t`, or pass --stdin)")?;
    let fd = tty.as_raw_fd();
    // SAFETY: `fd` is an open terminal and `settings` is a valid place for
    // its settings; the handler is removed before `SAVED` is cleared.
    let mut settings: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &mut settings) } != 0 {
        bail!("could not read the terminal's settings: {}", std::io::Error::last_os_error());
    }
    let mut quiet = settings;
    quiet.c_lflag &= !libc::ECHO;
    quiet.c_lflag |= libc::ECHONL | libc::ICANON;
    let before = unsafe {
        *std::ptr::addr_of_mut!(SAVED) = Some((fd, settings));
        let before = libc::signal(libc::SIGINT, restore_and_exit as extern "C" fn(libc::c_int) as libc::sighandler_t);
        libc::tcsetattr(fd, libc::TCSAFLUSH, &quiet);
        before
    };
    let mut line = String::new();
    let read = tty.write_all(prompt.as_bytes()).and_then(|()| BufReader::new(&tty).read_line(&mut line));
    unsafe {
        libc::tcsetattr(fd, libc::TCSAFLUSH, &settings);
        libc::signal(libc::SIGINT, before);
        *std::ptr::addr_of_mut!(SAVED) = None;
    }
    let outcome = match read {
        Ok(0) => Err(anyhow::anyhow!("no password was entered")),
        Ok(_) => Ok(first_line(&line)),
        Err(e) => Err(e).context("reading the password from the terminal"),
    };
    line.zeroize();
    outcome
}

/// Reads one line from stdin, for scripts and for systems that deliver the
/// password another way.
pub fn read_stdin() -> Result<Secret> {
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line).context("reading the password from stdin")?;
    let password = first_line(&line);
    line.zeroize();
    if password.is_empty() {
        bail!("no password arrived on stdin");
    }
    Ok(password)
}

/// The line without its line ending. Spaces are part of a password.
fn first_line(line: &str) -> Secret {
    Secret::new(line.trim_end_matches(['\n', '\r']).to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_line_ending_is_removed() {
        assert_eq!(first_line(" correct horse \r\n").expose(), " correct horse ");
        assert_eq!(first_line("no newline").expose(), "no newline");
        assert!(first_line("\n").is_empty());
    }
}
