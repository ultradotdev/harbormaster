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
# The Apple developer team that signs every release. It is not a secret:
# it is written inside each released program.
team="WN53UUCY94"
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
program="$work/out/harbormaster"
codesign --verify --strict "$program" || fail "the program's signature is not valid"
# A valid signature only says the file is as its signer left it, and anyone
# can sign. The checksum came from the same place as the download, so it
# cannot vouch for the signer either. So ask for the publisher's own
# signature: a Developer ID certificate that Apple issued to this team.
publisher="anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"$team\""
codesign --verify --strict -R="$publisher" "$program" 2>/dev/null || fail "the program was not signed by Harbormaster's publisher; nothing was installed"
# The same again from what the signature says of itself, in case the
# rule above ever comes to mean something else.
signature="$(codesign -dvv "$program" 2>&1)" || fail "the program's signature could not be read"
printf '%s\n' "$signature" | grep -qx "TeamIdentifier=$team" || fail "the program was not signed by Harbormaster's publisher; nothing was installed"
printf '%s\n' "$signature" | grep -q "^Authority=Developer ID Application: " || fail "the program was not signed with a Developer ID; nothing was installed"

dir="/usr/local/bin"
if ! { [ -d "$dir" ] && [ -w "$dir" ]; }; then
  dir="$HOME/.local/bin"
  mkdir -p "$dir"
fi
# Moved into place in one step, never written over a running program.
cp "$program" "$dir/harbormaster.new"
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
