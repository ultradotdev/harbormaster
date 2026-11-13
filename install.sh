#!/bin/sh
# Installs Harbormaster from its latest GitHub release.
#
#     curl -fsSL https://raw.githubusercontent.com/ultradotdev/harbormaster/main/install.sh | sh
#
# It downloads the release for this Mac, checks it against the release's
# published checksums, and puts the one program in /usr/local/bin, or in
# ~/.local/bin if that is not yours to write to. It never asks for sudo.
# Set HARBORMASTER_VERSION=v0.1.0 to install a particular release.
set -eu

repo="ultradotdev/harbormaster"
say() { printf '%s\n' "$*"; }
fail() { say "install: $*" >&2; exit 1; }

[ "$(uname -s)" = "Darwin" ] || fail "only macOS is supported so far"
case "$(uname -m)" in
  arm64) arch="darwin-arm64" ;;
  x86_64) arch="darwin-x64" ;;
  *) fail "unsupported processor: $(uname -m)" ;;
esac

tag="${HARBORMASTER_VERSION:-}"
if [ -z "$tag" ]; then
  # The latest release's address ends in its tag.
  tag="$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$repo/releases/latest" | sed 's|.*/||')"
fi
case "$tag" in
  v[0-9]*) ;;
  *) fail "could not tell which release is the latest" ;;
esac

name="harbormaster-$tag-$arch.zip"
base="https://github.com/$repo/releases/download/$tag"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

say "Downloading Harbormaster $tag for $arch..."
curl -fsSL -o "$work/$name" "$base/$name" || fail "no download for $arch in release $tag"
curl -fsSL -o "$work/SHA256SUMS" "$base/SHA256SUMS" || fail "release $tag has no checksums"

wanted="$(sed -n "s/^\([0-9a-f]\{64\}\)  $name\$/\1/p" "$work/SHA256SUMS")"
[ -n "$wanted" ] || fail "the checksums do not list $name"
got="$(shasum -a 256 "$work/$name" | cut -d ' ' -f 1)"
[ "$wanted" = "$got" ] || fail "the download does not match its checksum; nothing was installed"

unzip -q "$work/$name" -d "$work/out"
# A signature from anyone but the publisher is not what was asked for.
codesign --verify --strict "$work/out/harbormaster" || fail "the program's signature is not valid"

dir="/usr/local/bin"
if ! { [ -d "$dir" ] && [ -w "$dir" ]; }; then
  dir="$HOME/.local/bin"
  mkdir -p "$dir"
fi
# Moved into place in one step, never written over a running program.
cp "$work/out/harbormaster" "$dir/harbormaster.new"
mv -f "$dir/harbormaster.new" "$dir/harbormaster"

say "Installed $dir/harbormaster ($("$dir/harbormaster" --version))."
case ":$PATH:" in
  *":$dir:"*) ;;
  *) say "Add $dir to your PATH to run it as plain harbormaster." ;;
esac
command -v ffmpeg >/dev/null 2>&1 || say "Video needs ffmpeg, which was not found. With Homebrew: brew install ffmpeg"
say ""
say "Next:  harbormaster setup"
say "If this replaced an older version, also run:  harbormaster service install"
