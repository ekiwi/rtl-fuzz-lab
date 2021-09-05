#!/bin/bash
#
# Prepare codebase for fuzzing

set -e

if ! [[ -p a2j ]]; then
  mkfifo a2j
fi

if ! [[ -p j2a ]]; then
  mkfifo j2a
fi

if ! [[ -d seeds ]]; then
  mkdir seeds
fi

cd fuzzing
make

echo "SETUP COMPLETE"

exit 0
