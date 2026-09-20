//! A Shodan for the machine's own segment.
//!
//! Shodan's crawler is famously four steps: generate a random IPv4, pick a port
//! from the list it understands, connect and grab a banner, repeat -- and the
//! randomness exists to cover a 32-bit address space without bias. None of that
//! transfers to a kernel that owns one NIC on one subnet. The address space
//! here is not the internet, it is the /24 the machine sits on, and it is small
//! enough to sweep rather than sample. So this is Shodan's method with its one
//! internet-scale decision removed and everything else kept: enumerate the
//! local hosts, grab a banner from each open port, name the service by what it
//! said, and index the result where the model can read it.
//!
//! ### Why it will not scan past the subnet, ever
//!
//! `hosts_in` derives its targets from the interface's own address and mask,
//! and `net::alive` refuses any address that is not on-link. There is no way to
//! hand this an internet host, by design and not by omission: a ring-0 kernel
//! with the model able to reach it must not be a general scanner, and "local"
//! in "local Shodan" is a boundary the code holds rather than a description of
//! how it is usually used. The internet-scale version is a different tool with
//! a different threat model and it is not this one.
//!
//! ### What is verified and what is not
//!
//! `hosts_in` is pure arithmetic over an address and a mask, and its every edge
//! -- the network and broadcast addresses excluded, the machine's own address
//! excluded, a mask so wide the sweep must be capped -- is asserted at boot in
//! `selftest`, because an off-by-one there scans the wrong hosts silently.
//!
//! `scan` drives the NIC, and it cannot be exercised where this is developed:
//! QEMU's user-mode network is a NAT with a gateway and a DNS server and no
//! scannable hosts behind it, so an ARP sweep of the guest's subnet finds
//! nothing to find. Like the RTL8168 driver and the WPA2 supplicant, its
//! chip-and-wire half is checked on the GF63 on a real segment and nowhere
//! else. It is written to be obviously correct and marked, in the manner this
//! tree marks everything it could not run.

use super::{Ipv4, UNSPECIFIED};
use super::fingerprint::{self, Fingerprint, PORTS};
use alloc::string::String;
use alloc::vec::Vec;

/// The most hosts one sweep will enumerate, whatever the mask says.
///
/// A /24 is 254 hosts and a sane home or lab segment; a /16 is 65,534 and a
/// sweep of it at any per-port timeout is not minutes but hours, on a kernel
/// with no way to background the work off the shell task. The cap is a bound on
/// one sweep's wall time, not a claim about the subnet, and `hosts_in` reports
/// when it bit so a wider network is a known-truncated scan rather than a
/// silently partial one.
pub const MAX_HOSTS: usize = 256;

/// Where a sweep's findings live, one blob per open port.
pub const ROOT: &str = "/ai/recon";

fn u32_of(ip: Ipv4) -> u32 {
    u32::from_be_bytes(ip)
}
fn ip_of(v: u32) -> Ipv4 {
    v.to_be_bytes()
}

/// The host addresses of the subnet an address and mask describe, with the
/// network address, the broadcast address and the machine's own address left
/// out, capped at `MAX_HOSTS`.
///
/// Returns the list and whether the cap truncated it. Pure, so every exclusion
/// is a boot assertion rather than a thing discovered when a scan skips `.1` or
/// scans `.255`.
pub fn hosts_in(ip: Ipv4, mask: Ipv4, cap: usize) -> (Vec<Ipv4>, bool) {
    let net = u32_of(ip) & u32_of(mask);
    let bcast = net | !u32_of(mask);
    let mut out = Vec::new();
    // A /31 or /32 has no host range between network and broadcast; the loop
    // below would be empty anyway, but saying so here keeps the arithmetic from
    // wrapping when `net + 1 > bcast`.
    if bcast <= net + 1 {
        return (out, false);
    }
    let mut truncated = false;
    let mut a = net + 1;
    while a < bcast {
        if a != u32_of(ip) {
            if out.len() >= cap {
                truncated = true;
                break;
            }
            out.push(ip_of(a));
        }
        a += 1;
    }
    (out, truncated)
}

/// One thing found listening: where it was, and what it turned out to be.
#[derive(Clone)]
pub struct Finding {
    pub ip: Ipv4,
    pub port: u16,
    pub fp: Fingerprint,
}

/// The address as `192-168-1-20`, so it is one path segment rather than four.
///
/// Dots are the namespace's own separator -- `tree::put` would read `192.168`
/// as two levels -- so the index would grow a directory per octet and a host
/// would not be one node. Dashes keep a host to a single name.
pub fn ip_seg(ip: Ipv4) -> String {
    let mut s = String::new();
    for (i, o) in ip.iter().enumerate() {
        if i > 0 {
            s.push('-');
        }
        push_u8(&mut s, *o);
    }
    s
}

fn push_u8(s: &mut String, mut v: u8) {
    if v >= 100 {
        s.push((b'0' + v / 100) as char);
        v %= 100;
        s.push((b'0' + v / 10) as char);
        s.push((b'0' + v % 10) as char);
    } else if v >= 10 {
        s.push((b'0' + v / 10) as char);
        s.push((b'0' + v % 10) as char);
    } else {
        s.push((b'0' + v) as char);
    }
}

/// The dotted form, for display and for the record's own body.
pub fn ip_dotted(ip: Ipv4) -> String {
    let mut s = String::new();
    for (i, o) in ip.iter().enumerate() {
        if i > 0 {
            s.push('.');
        }
        push_u8(&mut s, *o);
    }
    s
}

/// Sweep the local subnet and index what answers.
///
/// **Unverified here.** See the module header: there are no hosts behind QEMU's
/// user-mode NAT to find, so this path is exercised on the GF63 and nowhere in
/// the development loop. Its logic leans entirely on pieces that *are* checked
/// -- `hosts_in` at boot, `fingerprint::identify` at boot and under the host
/// harness -- so what is unverified is the wiring, not the judgement.
///
/// `per_port_ms` is the connect-and-read budget for one port. It is small on
/// purpose: a closed port on a live host returns `Refused` immediately, but a
/// filtered one costs the whole timeout, so the sweep's floor is roughly
/// live-hosts times open-or-filtered-ports times this number.
pub fn scan(cap: usize, per_port_ms: u64) -> Result<Vec<Finding>, &'static str> {
    let cfg = super::config();
    if cfg.ip == UNSPECIFIED {
        return Err("no address -- recon needs a configured interface (dhcp or a static ip)");
    }
    let cap = cap.min(MAX_HOSTS);
    let (hosts, truncated) = hosts_in(cfg.ip, cfg.netmask, cap);
    if truncated {
        crate::kprintln!(
            "  recon: subnet wider than {} hosts -- sweeping the first {}",
            cap, cap
        );
    }

    let mut findings = Vec::new();
    for host in hosts {
        findings.extend(scan_host(host, per_port_ms));
    }
    Ok(findings)
}

/// Sweep one host's known ports, banner-grab, name each service, index it.
///
/// The per-host body of `scan`, lifted out so the arena's guarded recon can aim
/// at a single target without re-deriving the loop -- one implementation of
/// "connect, probe, identify, record", so the operator's sweep and the model's
/// cannot drift. Returns what answered; an unreachable host yields nothing.
/// It does **not** gate the target itself: `scan` gates by `alive`/`on_subnet`
/// and the arena gates by the reach guard before calling in, so this trusts its
/// caller to have authorized the host -- stated here because it is the one place
/// that trust is assumed rather than checked.
pub fn scan_host(host: Ipv4, per_port_ms: u64) -> Vec<Finding> {
    let mut findings = Vec::new();
    // ARP first: a host that will not answer ARP will not answer anything, and
    // skipping it here is one probe against fifteen timeouts.
    if !super::alive(host) {
        return findings;
    }
    let host_str = ip_dotted(host);
    for &(port, probe) in PORTS.iter() {
        match super::tcp::connect(host, port, per_port_ms) {
            Ok(()) => {
                let req = fingerprint::probe_bytes(probe, &host_str);
                if !req.is_empty() {
                    let _ = super::tcp::send(&req, per_port_ms);
                }
                let banner = super::tcp::recv(per_port_ms.max(500));
                super::tcp::close(200);
                let fp = fingerprint::identify(port, &banner);
                record(host, port, &fp, &banner);
                findings.push(Finding { ip: host, port, fp });
            }
            // Refused means the host is up and the port is shut -- a fact, but
            // not a service, so it is not indexed. Any other error is the host
            // not answering this port at all.
            Err(_) => {}
        }
    }
    findings
}

/// Write one finding into the index: `/ai/recon/<ip>/<port>`.
///
/// The body is the rendered fingerprint and then the raw banner, so the index
/// carries both the machine's conclusion and the evidence for it -- the same
/// discipline the ledger keeps, where a verdict that cannot be re-derived from
/// what it was drawn from is a verdict nobody can check.
fn record(ip: Ipv4, port: u16, fp: &Fingerprint, banner: &[u8]) {
    let mut path = String::from(ROOT);
    path.push('/');
    path.push_str(&ip_seg(ip));
    path.push('/');
    push_u16(&mut path, port);

    let mut body = fp.render();
    body.push('\n');
    // The banner, printable bytes only, one line -- evidence, kept short.
    for &c in banner.iter().take(200) {
        if (0x20..0x7f).contains(&c) {
            body.push(c as char);
        } else if c == b'\n' || c == b'\r' {
            body.push(' ');
        }
    }
    body.push('\n');
    crate::sysbox::write_text(&path, &body);
}

pub fn push_u16(s: &mut String, v: u16) {
    if v == 0 {
        s.push('0');
        return;
    }
    let mut digits = [0u8; 5];
    let mut n = 0;
    let mut x = v;
    while x > 0 {
        digits[n] = b'0' + (x % 10) as u8;
        x /= 10;
        n += 1;
    }
    while n > 0 {
        n -= 1;
        s.push(digits[n] as char);
    }
}

/// The pure half's every edge, asserted without a NIC.
pub fn selftest() -> bool {
    let mut ok = true;
    let mut check = |cond: bool, what: &str| {
        if !cond {
            use crate::gfx::console::{self, LTGRAY, LTRED};
            use crate::kprintln;
            console::set_color(LTRED);
            kprintln!("  FAIL   recon     {}", what);
            console::set_color(LTGRAY);
            ok = false;
        }
    };

    // A /24 with the machine at .50: hosts .1..=.254, minus .50, is 253.
    let (h, trunc) = hosts_in([192, 168, 1, 50], [255, 255, 255, 0], MAX_HOSTS);
    check(h.len() == 253, "a /24 yields 254 hosts less our own");
    check(!trunc, "a /24 does not truncate under a 256 cap");
    check(!h.contains(&[192, 168, 1, 0]), "the network address is excluded");
    check(!h.contains(&[192, 168, 1, 255]), "the broadcast address is excluded");
    check(!h.contains(&[192, 168, 1, 50]), "our own address is excluded");
    check(h.contains(&[192, 168, 1, 1]) && h.contains(&[192, 168, 1, 254]), "the ends are in");

    // A /30 has two host addresses; minus our own, one remains.
    let (h30, _) = hosts_in([10, 0, 0, 1], [255, 255, 255, 252], MAX_HOSTS);
    check(h30 == alloc::vec![[10, 0, 0, 2]], "a /30 less our own is a single host");

    // A /31 and a /32 have no host range at all.
    let (h31, _) = hosts_in([10, 0, 0, 0], [255, 255, 255, 254], MAX_HOSTS);
    check(h31.is_empty(), "a /31 has no sweepable hosts");
    let (h32, _) = hosts_in([10, 0, 0, 5], [255, 255, 255, 255], MAX_HOSTS);
    check(h32.is_empty(), "a /32 has no sweepable hosts");

    // A wide mask truncates at the cap and says so, rather than enumerating
    // 65,534 addresses onto the heap.
    let (hw, tw) = hosts_in([172, 16, 5, 5], [255, 255, 0, 0], 256);
    check(hw.len() == 256, "a /16 is capped to the limit");
    check(tw, "and reports that it truncated");

    // The path segment for an address is one segment, dashed not dotted.
    check(ip_seg([192, 168, 1, 20]) == "192-168-1-20", "ip is one dashed segment");
    check(ip_dotted([10, 0, 0, 7]) == "10.0.0.7", "dotted form for display");

    ok
}
