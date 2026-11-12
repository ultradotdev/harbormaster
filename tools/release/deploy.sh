#!/bin/sh
# Signs a release build and installs it on a Mac reached over SSH, where
# Harbormaster already runs as a service. Usage: deploy.sh SSH_HOST
#
# The binary is copied under a new name and renamed into place, never
# written over a running one. The service then restarts on the new build,
# after which it needs the Protect password again: run `harbormaster unlock`.
set -eu
host="${1:?usage: deploy.sh SSH_HOST}"
cd "$(dirname "$0")/../.."
sh tools/release/sign.sh
scp -q target/release/harbormaster "$host:harbormaster.new"
ssh "$host" 'mv -f ~/harbormaster.new ~/harbormaster && ~/harbormaster service install'
echo
echo "Now give it the Protect password:"
echo "  ssh -t $host '\"\$HOME/Library/Application Support/harbormaster/bin/harbormaster\" unlock'"
