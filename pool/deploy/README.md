# Putting the pool on a server

The daemon is one statically linked file with no runtime dependencies, so
"deploy" is copy, install a unit, open a port. There is nothing to configure on
the host and no toolchain to install there.

## Build it here, not there

```bash
cd pool
cargo build --release --target x86_64-unknown-linux-musl
```

musl rather than gnu so the result is **static**: no glibc version to match
against whatever the host runs, no shared objects, one artefact. Verified on
the current build: 784,784 bytes, x86-64, no `PT_INTERP`, which is what "needs
no loader" looks like in the file itself.

If the server is ARM rather than x86-64 -- a Pi, an Ampere or Graviton instance
-- the target is `aarch64-unknown-linux-musl` instead, and `uname -m` on the
box settles it (`x86_64` or `aarch64`). The rest of this file is unchanged.

**Check before copying**, because the failure mode of the wrong architecture is
`cannot execute binary file` after everything else has already been set up:

```bash
file target/x86_64-unknown-linux-musl/release/glados-pool
# ELF 64-bit LSB pie executable, x86-64, static-pie linked, ...
```

## Install

```bash
# on the server, as root
useradd --system --no-create-home --shell /usr/sbin/nologin glados-pool
install -m 0755 glados-pool /usr/local/bin/glados-pool
install -m 0644 glados-pool.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now glados-pool
systemctl status glados-pool
```

Edit the `ExecStart` line first: the coins and their share targets are the only
thing in the unit that is a decision rather than a measurement.

## Check it before opening any port

The daemon can prove itself with no network and no miner:

```bash
/usr/local/bin/glados-pool --selftest
```

It stands up a listener on loopback, greets it, takes two jobs on two different
algorithms, mines them, submits, and requires the pool to have independently
recomputed both hashes and agreed. A pass means the binary is right for this
machine.

```bash
/usr/local/bin/glados-pool --bench
```

Prints what one share costs to validate here, which is the number that decides
whether the share targets in the unit are sane. Compare against `design/pool.md`;
a much slower machine wants harder targets, not a bigger box.

## The port

3334, TCP, inbound. Above 1024, so the daemon binds it without any capability.

```bash
# ufw
ufw allow 3334/tcp
# firewalld
firewall-cmd --permanent --add-port=3334/tcp && firewall-cmd --reload
```

Cloud hosts usually have a second firewall in their control panel that has
nothing to do with the one on the machine. Both have to allow it, and a
security group nobody opened looks exactly like a daemon that is not running.

From somewhere else:

```bash
printf '{"id":1,"method":"glados.hello","params":{"v":1,"worker":"probe","agent":"curl"}}\n' \
  | timeout 5 nc <host> 3334
```

A welcome and then a job or two means the whole path is open. Silence means a
firewall; a refused connection means the daemon.

## Then point the kernel at it

```
mine pool <host>:3334 glados
mine user <worker-name>
mine slices 3
mine on
mine coins
```

## What this does not do yet

**No TLS.** Worker names travel in the clear and anything on the path can
rewrite a job. The kernel has one TLS session and the updater owns it, so this
is a real limitation rather than a setting -- see `design/pool.md`. Until it is
fixed, a miner on an untrusted network is trusting the network.

**No persistence across restarts.** `--ledger` writes the share log every
minute and nothing reads it back at start, so `systemctl restart` begins the
tally at zero. Back the file up before restarting if the numbers matter.

**No chain behind any coin.** Every `Source` is `Local`: the pool builds its own
headers, so shares are real proof of work against a target nobody else
recognises. This is a working pool with nothing to mine yet, and the report says
`local` on every row rather than implying otherwise.
