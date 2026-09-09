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

## First, find out what you are deploying onto

All read-only, and `sudo -n` cannot hang on a password prompt:

```bash
uname -m; uname -r
grep PRETTY /etc/os-release
systemctl --version 2>/dev/null | head -1
sudo -n true 2>/dev/null && echo "sudo: yes" || echo "sudo: no (or wants a password)"
loginctl show-user "$USER" -p Linger 2>/dev/null
nproc; free -m | head -2
ss -ltn 2>/dev/null | grep ':3334' || echo "port 3334: free"
cat /sys/fs/cgroup/user.slice/user-$(id -u).slice/cgroup.controllers 2>/dev/null
```

What each answer changes:

- **`uname -m`** picks the build target and nothing else. `x86_64` or `aarch64`.
- **sudo** picks which unit file. With it, `glados-pool.service`; without,
  `glados-pool.user.service` and the caveats in its header.
- **`Linger=no`** with no sudo is the trap: a user service stops when you log
  out, so the pool works while you watch it and is gone by morning.
  `loginctl enable-linger $USER` fixes it, and needs sudo on some systems.
- **`cgroup.controllers`** says whether the resource limits in a *user* unit
  are enforced or merely written down. If `memory` and `cpu` are absent they
  are documentation.
- **port 3334 in use** means pick another and change it in three places: the
  unit, the firewall, and `mine pool`.

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

### Without root

```bash
mkdir -p ~/.local/bin ~/.config/systemd/user
install -m 0755 glados-pool ~/.local/bin/glados-pool
install -m 0644 glados-pool.user.service ~/.config/systemd/user/glados-pool.service
systemctl --user daemon-reload
systemctl --user enable --now glados-pool
loginctl enable-linger "$USER"    # or it stops when you log out
systemctl --user status glados-pool
```

The daemon needs no privilege: a port above 1024, one directory to write, and
nothing else. What is lost is *enforcement* of the limits, not function -- see
the header of `glados-pool.user.service`, and check `cgroup.controllers` above.

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

## If it is a home server, read this before the port section

A machine in somebody's house is not a small VPS. Four things change, and the
last one is a decision rather than a detail.

**It probably has no reachable address.** A residential connection has a
dynamic IPv4 at best and is behind carrier-grade NAT at worst, and under CGNAT
no port forward exists to make -- the address on the router is not the address
the world sees. `curl -s ifconfig.me` on the server against the WAN address in
the router's own status page settles it: if they differ, forwarding cannot
work and a tunnel is the only route in.

**A forwarded port is a hole in his house, not in a rented box.** Everything
behind that NAT is his: other machines, whatever is on the LAN, his own
traffic. A VPS that gets compromised is a VPS. This is not that, and it is his
risk rather than ours to accept on his behalf.

**A DNS record pointing at his home publishes where he lives**, to street
level, to anybody who resolves `stratum.aperture.institute`. That is a fact
about him that a mining pool has no business making public, and it does not
become reversible by deleting the record later.

**His ISP may forbid it.** Running a public server on a residential line is
against the terms of most of them, and mining-adjacent traffic is the kind
that gets noticed.

### What to do instead, for now

**Do not expose it to the internet yet**, and the reason is not caution -- it
is that doing so buys nothing. Every coin's `Source` is `Local`: the pool
builds its own headers, so there is no chain, no block, and nothing for a
stranger to mine that is worth anything to them or to us. Opening a port on a
friend's house to serve work with no value is all cost.

What the server is genuinely useful for today is being the always-on end of a
*private* link:

- **Same LAN.** If the GLaDOS machine and the server are in one house, this is
  finished: `mine pool <lan-ip>:3334 glados` and nothing is exposed at all.
- **Different houses**, which is the likely case. Put both machines on a
  WireGuard or Tailscale network and point the miner at the private address.
  The kernel has its own TCP stack and no WireGuard, so **the tunnel cannot
  run inside GLaDOS** -- it has to be the router, or the host if GLaDOS is in
  QEMU, and the kernel just sees an ordinary address it can reach.

Revisit hosting when there is something to mine. By then the two things that
make exposure defensible will exist or will not: an upstream behind at least
one coin, and TLS. Until both are true, a public endpoint is a liability with
no matching asset -- and if it still seems worth it then, a five-dollar VPS
fronting the home box keeps his address and his LAN out of it entirely.

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
