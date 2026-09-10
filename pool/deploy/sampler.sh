#!/bin/sh
# Sample the live pool once a minute. The point of a soak is the *trend*, so
# this records what leaks if anything leaks: resident memory, open descriptors,
# thread count, ledger size, and the host's own load beside it -- because a
# figure that moved while the machine was busy with Jellyfin is not evidence
# about the pool.
#
# Writes one TSV line per sample. Bounded by its own row count rather than by
# time, so it cannot outlive the test and fill anybody's disk.
set -u
OUT="${HOME}/.local/state/glados-pool/soak.tsv"
PIDFILE="${HOME}/.local/state/glados-pool/run-pool.pid"
LEDGER="${HOME}/.local/state/glados-pool/ledger.json"
MAX_ROWS=400

[ -f "$OUT" ] || printf 'iso\tpid\trss_kb\tfds\tthreads\tledger_b\tlog_b\tload1\testab\n' > "$OUT"

i=0
while [ "$i" -lt "$MAX_ROWS" ]; do
    i=$((i + 1))
    SUP=$(cat "$PIDFILE" 2>/dev/null || echo "")
    # The pool is the supervisor's child; sample the pool, not the shell loop.
    PID=$(pgrep -P "${SUP:-0}" -f 'glados-pool' 2>/dev/null | head -1)
    if [ -n "$PID" ] && [ -d "/proc/$PID" ]; then
        RSS=$(awk '/^VmRSS:/{print $2}' "/proc/$PID/status" 2>/dev/null)
        FDS=$(ls "/proc/$PID/fd" 2>/dev/null | wc -l)
        THR=$(awk '/^Threads:/{print $2}' "/proc/$PID/status" 2>/dev/null)
    else
        PID=0; RSS=0; FDS=0; THR=0
    fi
    LB=$(wc -c < "$LEDGER" 2>/dev/null || echo 0)
    GB=$(wc -c < "${HOME}/.local/state/glados-pool/pool.log" 2>/dev/null || echo 0)
    L1=$(awk '{print $1}' /proc/loadavg)
    # Established connections to the pool's port, so a descriptor climb can be
    # told apart from miners simply arriving.
    #
    # `grep -c` prints 0 *and exits 1* when it matches nothing, so the obvious
    # `|| echo 0` appended a second zero and `EST` became two lines -- which
    # printf then spread across two rows, putting a bare "0" line in the middle
    # of a TSV that everything downstream parses by column. The count is always
    # a number, so there is nothing to fall back to: take it as it comes.
    EST=$(ss -tn state established 2>/dev/null | grep -c ':3334')
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$PID" "${RSS:-0}" "$FDS" "${THR:-0}" \
        "$LB" "$GB" "$L1" "$EST" >> "$OUT"
    sleep 60
done
