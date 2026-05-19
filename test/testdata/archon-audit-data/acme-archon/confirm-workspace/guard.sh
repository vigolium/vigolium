#!/usr/bin/env bash
set +e
trap '"/Users/<user>/Desktop/oss-to-run/acme/archon/confirm-workspace/cleanup.sh"; exit 0' EXIT INT TERM
while [ ! -f "/Users/<user>/Desktop/oss-to-run/acme/archon/confirm-workspace/.done" ]; do sleep 5; done
