# Start the GLaDOS pool if it is not already running.
#
# This is here because nothing unprivileged on this host starts at boot:
# `loginctl enable-linger` is refused by polkit and there is no cron, so the
# two ordinary answers are both unavailable. What *does* work is that logind
# runs with `KillUserProcesses=false`, so a detached process outlives logout --
# it just has to be started once after each boot, and a login is the only
# unprivileged event left to hang that on.
#
# So: survives logout indefinitely, and comes back on the first login after a
# reboot rather than at boot itself. The gap is real and is stated rather than
# papered over.
#
# **Safe to run on every login**, which matters because that is what will
# happen. `run-pool.sh` holds a pidfile and exits immediately if a live pool
# already owns it, so ten logins make one pool. The `kill -0` here is only to
# avoid the noise of starting a script that will immediately say it is already
# running.
#
# Remove this block to stop the pool coming back; kill the pidfile's PID to
# stop the one running now. Both are in ~/.local/state/glados-pool.
if [ -x "$HOME/.local/bin/run-pool.sh" ]; then
    _gp_pid=$(cat "$HOME/.local/state/glados-pool/run-pool.pid" 2>/dev/null)
    if ! { [ -n "$_gp_pid" ] && kill -0 "$_gp_pid" 2>/dev/null; }; then
        # `setsid` so it is not in this login's process group: without it the
        # pool is a child of the shell and a hangup on logout reaches it.
        setsid nohup "$HOME/.local/bin/run-pool.sh" </dev/null >/dev/null 2>&1 &
    fi
    unset _gp_pid
fi
