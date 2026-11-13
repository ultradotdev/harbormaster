# Security

Harbormaster holds the keys to your HomeKit pairing and signs in to your
camera system, so reports of security problems are taken seriously.

## Reporting a problem

Please report it privately, not in a public issue: on GitHub, open the
repository's Security tab and choose "Report a vulnerability". Say what you
found and how to reproduce it. You will get an answer, and credit in the
fix if you want it.

## What Harbormaster is built to hold to

- The UniFi Protect password is never written to disk by Harbormaster. It
  is read from your Keychain or typed, and kept in memory only.
- It talks only to a console that presents the exact certificate you
  confirmed during setup. Credentials are never sent to anything else.
- Its files, including the HomeKit pairing keys, are readable only by you.
- The dashboard talks to the service over a socket that only you can open.
- Stream keys, passwords and session cookies are never logged.
- It listens for HomeKit on your local network and makes no connections
  beyond your console. It has no telemetry and no update check.

## What it does not protect against

- Other people logged in to the same Mac. While someone watches a camera
  live, the key that encrypts that one stream is passed to ffmpeg on its
  command line, where any user of the machine can read it for as long as
  the stream runs. Harbormaster is meant for a machine that only its owner
  logs in to.

## How releases are checked

- Every change is built, linted and tested, and its dependencies checked
  for known vulnerabilities, license problems and unexpected sources.
- Release binaries are signed with an Apple Developer ID.
- Each release publishes SHA-256 checksums. The install script and the
  Homebrew formula both refuse a download that does not match. The install
  script also refuses a program that was not signed by this project's
  Developer ID.
