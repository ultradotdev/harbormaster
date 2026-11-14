# Trying Harbormaster against a mock console

`harbormaster mock-console` is a pretend UniFi Protect console that can
be built into the `harbormaster` program. It lets you test a fresh install end to end
(setup, sign-in, certificate pinning, the dashboard, motion and doorbell
events, snapshots and live video) on a spare Mac or a virtual machine,
without a real console and without touching your real one.

It is a development aid. Released builds (Homebrew, the install script)
do not contain it, and it is left out of `harbormaster --help`.

## Getting a build that has it

Build from source with the `mock-console` feature:

```bash
cargo build --release --features mock-console
```

That gives `target/release/harbormaster` with the `mock-console` command.
To test a real release, keep the two apart: install Harbormaster the
normal way, copy this build next to it under another name such as
`harbormaster-mock`, and use that copy only to play the console. The
commands below then start with `harbormaster-mock mock-console` for the
mock and plain `harbormaster` for everything else.

## What it pretends to be

A console called "Mock Protect" with an invented site:

| Device | Kind | What it does |
| --- | --- | --- |
| Front Porch | doorbell with a package camera and speaker | rings, recognises people and packages |
| Driveway | camera | recognises vehicles |
| Backyard | camera | recognises animals |
| Garage | camera | plain motion only |
| Side Yard Floodlight | floodlight | motion turns it on; can be switched from HomeKit |
| Back Door | door sensor | opens and closes |
| Garden Shed | climate sensor | temperature, humidity and light drift |
| Laundry Floor | leak sensor | stays dry |
| Hallway Chime | chime | listed only; Harbormaster does not publish chimes |

Something happens every few seconds, from a script that repeats about
once a minute. Cameras show ffmpeg test patterns, so live video and
snapshots need ffmpeg (`brew install ffmpeg`); without it the cameras are
still published but have no picture.

It accepts one account, `protect-mock`, with a password you choose each
time you start it. The password is kept in memory only and never written
down or printed, so there is no password for it anywhere in the code or
on disk. The username differs from the `harbormaster` that setup suggests,
so that a Keychain entry for a real console is never offered to the mock.

## Trying it

Start the mock in one terminal:

```bash
harbormaster mock-console
```

It asks you to choose a password for its account (typed unseen, twice),
then listens on `127.0.0.1:7443` and prints its certificate fingerprint.
For a scripted run, pass `--stdin` and give the password on standard input
instead. The
certificate is made on first start and kept in the `mock-console` folder of
the state directory, so the fingerprint stays the same between runs. To
listen elsewhere, pass `--listen 0.0.0.0:7443` (any address and port); to
keep its certificate somewhere else, pass `--state-dir DIR`.

In a second terminal, run setup and answer with the mock's details:

```bash
harbormaster setup
```

- Address: `127.0.0.1:7443`
- Username: `protect-mock`
- Check the fingerprint against the one the mock printed, and accept it.
- Password: the one you chose when you started the mock

Then either let setup install the service, or decline and run the bridge
yourself:

```bash
harbormaster daemon
```

```bash
harbormaster unlock
```

Open the dashboard with `harbormaster` to watch the devices and their
events. It shows the pairing code for the Home app; press `p` to hide it.

To try all this without disturbing an existing installation, give every
command the same `--state-dir`, for example `--state-dir /tmp/hm`, and pass
the daemon a free port with `--listen 0.0.0.0:51830`. Keep that path short:
the control socket inside it must fit in about 100 characters.

## What it does not do

- Only the requests Harbormaster makes are answered, in the shapes
  Harbormaster reads. It is not a model of Protect for other software.
- There is one account, no two-factor sign-in, no rate limiting and no
  session expiry.
- Devices are never added, removed, adopted or taken offline.
- What a viewer says through the doorbell is received and thrown away.
- Recognitions other than people, vehicles, animals and packages, and
  Protect's sound detections, are never sent.
