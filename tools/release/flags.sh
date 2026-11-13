# shellcheck shell=sh
# Sourced by the release scripts before they build.
#
# A program remembers the folders it was built in, and prints them when
# it reports a crash. Those are the builder's own: a home folder, a user
# name. This has the compiler record neutral names instead.
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
toolchain="$(rustc --print sysroot)"
export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$cargo_home=/cargo --remap-path-prefix=$toolchain=/rust --remap-path-prefix=$PWD=/harbormaster"
