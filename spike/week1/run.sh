#!/bin/sh
# THROWAWAY week-1 spike runner (docs/SPIKE-WEEK1.md).
#   ./run.sh <name> <args...>     e.g. ./run.sh check-latency check-latency
# Waits until no cargo/rustc runs and the 1-minute load is below 4.0, samples
# both every 2 s while the run goes, and writes docs/spike-week1-results/<name>.txt and
# docs/spike-week1-results/<name>.sampler.txt. Postgres must listen on 127.0.0.1:5442.
set -u
name=$1; shift
bin=./target/release/tutela-spike-week1
load1() { sysctl -n vm.loadavg | awk '{print $2}'; }
while pgrep -x cargo >/dev/null || pgrep -x rustc >/dev/null || [ "$(echo "$(load1) >= 4.0" | bc)" = 1 ]; do
  echo "waiting: load $(load1), cargo/rustc: $(pgrep -x cargo; pgrep -x rustc | tr '\n' ' ')"; sleep 30
done
out=../../docs/spike-week1-results/$name.txt; smp=../../docs/spike-week1-results/$name.sampler.txt
: > "$smp"
( while :; do echo "$(date '+%H:%M:%S') load=$(load1) cargo=$(pgrep -x cargo | tr '\n' ' ') rustc=$(pgrep -x rustc | tr '\n' ' ')" >> "$smp"; sleep 2; done ) &
sampler=$!
{
  echo "# $name: $bin $*"
  echo "# start $(date '+%Y-%m-%d %H:%M:%S %Z'), load $(load1), $(sysctl -n machdep.cpu.brand_string), git $(git rev-parse --short HEAD)"
  /usr/bin/time -l "$bin" "$@" 2>&1
  echo "# exit $?"
  echo "# end $(date '+%Y-%m-%d %H:%M:%S %Z'), load $(load1)"
} > "$out" 2>&1
kill $sampler
if grep -qE 'cargo=[0-9]|rustc=[0-9]' "$smp"; then
  echo "VOID: a cargo or rustc process ran during $name (see $smp)" | tee -a "$out"
else
  echo "valid: no cargo or rustc during $name" | tee -a "$out"
fi
