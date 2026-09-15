//! WPA2-PSK: the key hierarchy and the four-way handshake.
//!
//! ### What this is, and what it is waiting for
//!
//! Everything here is the supplicant's *cryptography* and message handling --
//! the part that can be written and checked without any hardware, against the
//! test vectors in IEEE 802.11i. It is complete and it is verified at boot.
//!
//! What it cannot do is run, because `wlan0` has no driver. There is nothing
//! to send an EAPOL frame over. So this module is deliberately structured as
//! pure functions over byte slices with no I/O anywhere: when a driver
//! arrives, it supplies frames and this supplies answers, and none of the code
//! below changes.
//!
//! ### The key hierarchy
//!
//! ```text
//!   passphrase + SSID  --PBKDF2-SHA1, 4096 rounds-->  PMK   (32 bytes)
//!   PMK + both nonces + both MACs  --PRF-384-->       PTK   (48 bytes)
//!   PTK[0..16]   KCK   confirms the handshake messages
//!   PTK[16..32]  KEK   unwraps the group key
//!   PTK[32..48]  TK    encrypts data with CCMP
//! ```
//!
//! The nonces are what make the PTK fresh: the same passphrase on the same
//! network yields a different session key every time, so recording traffic
//! today and learning the passphrase tomorrow does not decrypt it. That
//! property is why the four-way handshake exists at all rather than simply
//! using the PMK.
//!
//! ### The known weakness, which is the protocol's and not this code's
//!
//! Anyone who captures the four-way handshake can test passphrase guesses
//! offline at 4096 PBKDF2 rounds each. That was expensive in 2004. A
//! dictionary word is not safe on WPA2 and no supplicant can fix it -- WPA3's
//! SAE replaces exactly this.

use crate::crypto::{aes, sha1};
use alloc::vec::Vec;

pub const PMK_LEN: usize = 32;
pub const PTK_LEN: usize = 48;

/// EAPOL-Key frames sit inside an EAPOL packet with this small header.
const EAPOL_VERSION: u8 = 1;
const EAPOL_TYPE_KEY: u8 = 3;
const KEY_TYPE_RSN: u8 = 2;

// Key Information bits, IEEE 802.11 table 12-8.
const KEY_INFO_PAIRWISE: u16 = 1 << 3;
const KEY_INFO_INSTALL: u16 = 1 << 6;
const KEY_INFO_ACK: u16 = 1 << 7;
const KEY_INFO_MIC: u16 = 1 << 8;
const KEY_INFO_SECURE: u16 = 1 << 9;
const KEY_INFO_ENCRYPTED: u16 = 1 << 12;

/// Derive the pairwise master key from a passphrase.
///
/// The SSID is the salt, which is why two networks with the same name and
/// password share a PMK -- and why precomputed tables for common SSIDs work.
pub fn pmk(passphrase: &str, ssid: &[u8]) -> Vec<u8> {
    sha1::pbkdf2(passphrase.as_bytes(), ssid, 4096, PMK_LEN)
}

/// The IEEE 802.11 PRF, built from HMAC-SHA1.
///
/// Each iteration hashes the label, the data, and a counter; the counter is
/// what makes the blocks differ, and it is a single byte appended *after* the
/// data rather than mixed in, which is the detail most reimplementations get
/// wrong.
fn prf(key: &[u8], label: &str, data: &[u8], out_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(out_len + sha1::HASH_LEN);
    let mut counter: u8 = 0;
    while out.len() < out_len {
        let mut input = Vec::with_capacity(label.len() + 1 + data.len() + 1);
        input.extend_from_slice(label.as_bytes());
        input.push(0);
        input.extend_from_slice(data);
        input.push(counter);
        out.extend_from_slice(&sha1::hmac(key, &input));
        counter += 1;
    }
    out.truncate(out_len);
    out
}

/// Derive the pairwise transient key.
///
/// The two MAC addresses and the two nonces each go in sorted order, smaller
/// first. Both sides therefore build the same input without having to agree
/// who is who -- and getting the ordering wrong produces a PTK that is
/// perfectly well-formed and does not match the other end's.
pub fn ptk(pmk: &[u8], aa: &[u8; 6], spa: &[u8; 6], anonce: &[u8; 32], snonce: &[u8; 32]) -> Vec<u8> {
    let mut data = Vec::with_capacity(76);
    if aa <= spa {
        data.extend_from_slice(aa);
        data.extend_from_slice(spa);
    } else {
        data.extend_from_slice(spa);
        data.extend_from_slice(aa);
    }
    if anonce <= snonce {
        data.extend_from_slice(anonce);
        data.extend_from_slice(snonce);
    } else {
        data.extend_from_slice(snonce);
        data.extend_from_slice(anonce);
    }
    prf(pmk, "Pairwise key expansion", &data, PTK_LEN)
}

pub struct Ptk<'a>(pub &'a [u8]);

impl<'a> Ptk<'a> {
    /// Key Confirmation Key -- authenticates the handshake messages.
    pub fn kck(&self) -> &[u8] {
        &self.0[0..16]
    }
    /// Key Encryption Key -- unwraps the group key in message 3.
    pub fn kek(&self) -> &[u8] {
        &self.0[16..32]
    }
    /// Temporal Key -- what CCMP actually encrypts data with.
    pub fn tk(&self) -> &[u8] {
        &self.0[32..48]
    }
}

/// A parsed EAPOL-Key frame.
pub struct KeyFrame<'a> {
    pub info: u16,
    pub replay: u64,
    pub nonce: [u8; 32],
    pub mic: [u8; 16],
    pub key_data: &'a [u8],
    /// The whole EAPOL packet, needed because the MIC covers it with the MIC
    /// field zeroed.
    pub raw: &'a [u8],
}

impl<'a> KeyFrame<'a> {
    pub fn has(&self, bit: u16) -> bool {
        self.info & bit != 0
    }
    /// Message 1 carries the ANonce and no MIC; message 3 carries both a MIC
    /// and the encrypted group key.
    pub fn is_message1(&self) -> bool {
        self.has(KEY_INFO_PAIRWISE) && self.has(KEY_INFO_ACK) && !self.has(KEY_INFO_MIC)
    }
    pub fn is_message3(&self) -> bool {
        self.has(KEY_INFO_PAIRWISE) && self.has(KEY_INFO_ACK) && self.has(KEY_INFO_MIC)
    }
}

/// The fixed part of a Key Descriptor: everything up to the key-data length.
///
/// Named because two different checks in `parse` have to be this same number,
/// and they were not.
const DESC_LEN: usize = 95;

/// Parse an EAPOL-Key packet.
pub fn parse(pkt: &[u8]) -> Option<KeyFrame<'_>> {
    // EAPOL header: version, type, length. Then the Key Descriptor.
    if pkt.len() < 4 + DESC_LEN || pkt[1] != EAPOL_TYPE_KEY {
        return None;
    }
    let body_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    // **Both directions, and only one of them was here.** The buffer has to
    // hold what the frame declares -- and the frame has to declare at least
    // the fields read below. Without the second, a packet long enough to pass
    // the length check above but declaring a shorter body sliced `b` down to
    // nothing and then indexed it: `index out of bounds: the len is 0 but the
    // index is 0`, in ring 0, with no unwinder.
    //
    // That was reachable from the air by anybody. EAPOL crosses an
    // unencrypted link *by design*, because it is what makes the link
    // encrypted, so this parser reads frames from strangers before there is
    // any key to refuse one with -- a hundred bytes and the machine stops.
    // Found by `net::hostile`, case 763.
    if body_len < DESC_LEN || 4 + body_len > pkt.len() {
        return None;
    }
    let b = &pkt[4..4 + body_len];
    if b[0] != KEY_TYPE_RSN {
        return None;
    }
    let info = u16::from_be_bytes([b[1], b[2]]);
    let replay = u64::from_be_bytes([b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12]]);
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&b[13..45]);
    let mut mic = [0u8; 16];
    mic.copy_from_slice(&b[77..93]);
    let data_len = u16::from_be_bytes([b[93], b[94]]) as usize;
    if DESC_LEN + data_len > b.len() {
        return None;
    }
    Some(KeyFrame {
        info,
        replay,
        nonce,
        mic,
        key_data: &b[DESC_LEN..DESC_LEN + data_len],
        raw: &pkt[..4 + body_len],
    })
}

/// Check the MIC on a received frame.
///
/// The MIC is computed over the whole EAPOL packet with the MIC field itself
/// zeroed -- it cannot cover its own value, and a verifier that forgets to
/// zero it rejects every frame.
pub fn verify_mic(kck: &[u8], frame: &KeyFrame) -> bool {
    let mut copy = frame.raw.to_vec();
    // The MIC sits 77 bytes into the key descriptor, which starts at 4.
    for b in copy[4 + 77..4 + 93].iter_mut() {
        *b = 0;
    }
    let computed = sha1::hmac(kck, &copy);
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= computed[i] ^ frame.mic[i];
    }
    diff == 0
}

/// One EAPOL-Key packet, whichever of the four it is.
///
/// Both ends build these and the four messages differ only in the key-info
/// bits, the replay counter, the nonce and whether there is a MIC -- so there
/// is one builder and the differences are arguments. Message 1 passes `None`
/// for the KCK, because there is no key yet to compute a MIC with, which is
/// exactly the property that lets anybody force a handshake and capture it.
fn build_key(
    info: u16,
    replay: u64,
    nonce: &[u8; 32],
    key_data: &[u8],
    kck: Option<&[u8]>,
) -> Vec<u8> {
    let body_len = DESC_LEN + key_data.len();
    let mut p = Vec::with_capacity(4 + body_len);
    p.push(EAPOL_VERSION);
    p.push(EAPOL_TYPE_KEY);
    p.extend_from_slice(&(body_len as u16).to_be_bytes());

    p.push(KEY_TYPE_RSN);
    p.extend_from_slice(&info.to_be_bytes());
    p.extend_from_slice(&16u16.to_be_bytes()); // key length
    p.extend_from_slice(&replay.to_be_bytes());
    p.extend_from_slice(nonce);
    p.extend_from_slice(&[0u8; 16]); // key IV
    p.extend_from_slice(&[0u8; 8]); // key RSC
    p.extend_from_slice(&[0u8; 8]); // reserved
    let mic_at = p.len();
    p.extend_from_slice(&[0u8; 16]); // MIC, filled below when there is a key
    p.extend_from_slice(&(key_data.len() as u16).to_be_bytes());
    p.extend_from_slice(key_data);

    if let Some(kck) = kck {
        let mic = sha1::hmac(kck, &p);
        p[mic_at..mic_at + 16].copy_from_slice(&mic[..16]);
    }
    p
}

/// Build message 2 or 4: the supplicant's replies, both MIC-protected.
pub fn build_reply(
    kck: &[u8],
    replay: u64,
    snonce: Option<&[u8; 32]>,
    key_data: &[u8],
    secure: bool,
) -> Vec<u8> {
    let mut info = KEY_INFO_PAIRWISE | KEY_INFO_MIC | 2; // 2 = HMAC-SHA1 AKM
    if secure {
        info |= KEY_INFO_SECURE;
    }
    build_key(info, replay, snonce.unwrap_or(&[0u8; 32]), key_data, Some(kck))
}

/// The access point's half of the four-way handshake.
///
/// **It is here because the supplicant had never been run.** `wpa2::selftest`
/// checked the PMK against Annex H.4 and the PTK against its own symmetry, and
/// `Supplicant::on_frame` -- the state machine that actually gets a key
/// installed -- had no frames to be fed and was executed by nothing, on a
/// machine with no wireless driver. An authenticator is the only thing that
/// can drive it without an access point in the room.
///
/// It is not a wireless access point and does not pretend to be one: no
/// beacons, no association, no group rekeying on a timer. It is the four
/// messages, built from the same `ptk` and the same `sha1::hmac` the
/// supplicant verifies with -- deliberately, because an authenticator carrying
/// its own arithmetic would agree with a supplicant that had the same bug.
pub struct Authenticator {
    pub pmk: Vec<u8>,
    pub anonce: [u8; 32],
    pub ptk: Option<Vec<u8>>,
    pub gtk: [u8; 16],
    pub aa: [u8; 6],
    pub spa: [u8; 6],
    replay: u64,
    pub done: bool,
}

impl Authenticator {
    pub fn new(passphrase: &str, ssid: &[u8], aa: [u8; 6], spa: [u8; 6]) -> Self {
        let mut anonce = [0u8; 32];
        for i in 0..4 {
            let t = crate::time::rdtsc().rotate_left((i * 7 + 3) as u32);
            anonce[i * 8..i * 8 + 8].copy_from_slice(&t.to_le_bytes());
        }
        Authenticator {
            pmk: pmk(passphrase, ssid),
            anonce,
            ptk: None,
            gtk: [0x47; 16],
            aa,
            spa,
            replay: 0,
            done: false,
        }
    }

    /// Message 1: the ANonce, in the clear and unauthenticated.
    pub fn message1(&mut self) -> Vec<u8> {
        self.replay += 1;
        let anonce = self.anonce;
        build_key(KEY_INFO_PAIRWISE | KEY_INFO_ACK | 2, self.replay, &anonce, &[], None)
    }

    /// Feed message 2 or 4. Answers message 3 after the second, nothing after
    /// the fourth -- at which point `tk` is what the link encrypts with.
    ///
    /// The two are told apart by the Secure bit rather than by a counter, for
    /// the reason the supplicant tells 1 from 3 the same way: a state machine
    /// that trusted its own idea of which message should arrive next would be
    /// driven by whatever arrived out of order.
    pub fn on_frame(&mut self, pkt: &[u8]) -> Option<Vec<u8>> {
        let f = parse(pkt)?;
        if !f.has(KEY_INFO_MIC) || f.has(KEY_INFO_ACK) {
            return None;
        }

        if !f.has(KEY_INFO_SECURE) {
            // Message 2 carries the SNonce, which is the last thing needed to
            // derive the PTK -- so the MIC on it can only be checked *after*
            // deriving one from the very nonce the frame is carrying.
            let ptk = ptk(&self.pmk, &self.aa, &self.spa, &self.anonce, &f.nonce);
            if !verify_mic(Ptk(&ptk).kck(), &f) {
                return None;
            }
            let k = Ptk(&ptk);
            // The group key travels wrapped under the KEK, which is what makes
            // message 3 worth encrypting at all: the pairwise key is derived at
            // both ends and never sent, and the group key is sent.
            let wrapped = aes::key_wrap(k.kek(), &gtk_kde(&self.gtk))?;
            self.replay += 1;
            let info = KEY_INFO_PAIRWISE
                | KEY_INFO_ACK
                | KEY_INFO_MIC
                | KEY_INFO_SECURE
                | KEY_INFO_INSTALL
                | KEY_INFO_ENCRYPTED
                | 2;
            let anonce = self.anonce;
            let m3 = build_key(info, self.replay, &anonce, &wrapped, Some(k.kck()));
            self.ptk = Some(ptk);
            return Some(m3);
        }

        // Message 4 is an acknowledgement and carries nothing but its MIC.
        let ptk = self.ptk.clone()?;
        if !verify_mic(Ptk(&ptk).kck(), &f) {
            return None;
        }
        self.done = true;
        None
    }

    /// The temporal key, once the handshake has finished.
    pub fn tk(&self) -> Option<Vec<u8>> {
        self.ptk.as_ref().map(|p| Ptk(p).tk().to_vec())
    }
}

/// Wrap a group key in the encapsulation `group_key` reads back: the RSN OUI,
/// data type 1, a key id, then the key, padded to a multiple of eight because
/// RFC 3394 wraps nothing else.
fn gtk_kde(gtk: &[u8; 16]) -> Vec<u8> {
    let mut d = Vec::with_capacity(24);
    d.push(0xDD); // vendor-specific KDE
    d.push(6 + gtk.len() as u8);
    d.extend_from_slice(&[0x00, 0x0F, 0xAC, 0x01]); // RSN OUI, data type 1 (GTK)
    d.extend_from_slice(&[0x01, 0x00]); // key id 1, reserved
    d.extend_from_slice(gtk);
    while d.len() % 8 != 0 {
        d.push(0xDD); // the padding RFC 4017 specifies, and it is not zero
    }
    d
}

/// Pull the group key out of message 3's encrypted key data.
pub fn group_key(kek: &[u8], key_data: &[u8]) -> Option<Vec<u8>> {
    let unwrapped = aes::key_unwrap(kek, key_data)?;
    // The result is a sequence of RSN key-data encapsulations; the GTK is the
    // one with OUI 00-0F-AC and data type 1.
    let mut at = 0;
    while at + 6 <= unwrapped.len() {
        let len = unwrapped[at + 1] as usize;
        if len < 4 || at + 2 + len > unwrapped.len() {
            break;
        }
        let oui = &unwrapped[at + 2..at + 5];
        let dtype = unwrapped[at + 5];
        if oui == [0x00, 0x0F, 0xAC] && dtype == 1 && len >= 6 {
            // Two bytes of key id and reserved precede the key itself.
            return Some(unwrapped[at + 8..at + 2 + len].to_vec());
        }
        at += 2 + len;
        // Encapsulations are padded to a multiple of eight.
        while at % 8 != 0 && at < unwrapped.len() {
            at += 1;
        }
    }
    None
}

/// The supplicant's side of the exchange, as a state machine over frames.
pub struct Supplicant {
    pub pmk: Vec<u8>,
    pub ptk: Option<Vec<u8>>,
    pub gtk: Option<Vec<u8>>,
    pub snonce: [u8; 32],
    pub aa: [u8; 6],
    pub spa: [u8; 6],
    pub done: bool,
}

impl Supplicant {
    pub fn new(passphrase: &str, ssid: &[u8], aa: [u8; 6], spa: [u8; 6]) -> Self {
        let mut snonce = [0u8; 32];
        for i in 0..4 {
            let t = crate::time::rdtsc().rotate_left((i * 13) as u32);
            snonce[i * 8..i * 8 + 8].copy_from_slice(&t.to_le_bytes());
        }
        Supplicant {
            pmk: pmk(passphrase, ssid),
            ptk: None,
            gtk: None,
            snonce,
            aa,
            spa,
            done: false,
        }
    }

    /// Feed a received EAPOL-Key frame, get back what to send.
    pub fn on_frame(&mut self, pkt: &[u8]) -> Option<Vec<u8>> {
        let f = parse(pkt)?;

        if f.is_message1() {
            // Message 1 has no MIC -- there is no key yet to compute one with,
            // which is why an attacker can force a handshake and capture it.
            let ptk = ptk(&self.pmk, &self.aa, &self.spa, &f.nonce, &self.snonce);
            let reply = build_reply(Ptk(&ptk).kck(), f.replay, Some(&self.snonce), &[], false);
            self.ptk = Some(ptk);
            return Some(reply);
        }

        if f.is_message3() {
            let ptk = self.ptk.clone()?;
            let k = Ptk(&ptk);
            // Message 3 is the first frame that proves the AP knows the PMK.
            // A failed MIC here means the passphrase is wrong -- or someone is
            // impersonating the network.
            if !verify_mic(k.kck(), &f) {
                return None;
            }
            if f.has(KEY_INFO_ENCRYPTED) {
                self.gtk = group_key(k.kek(), f.key_data);
            }
            let reply = build_reply(k.kck(), f.replay, None, &[], true);
            self.done = true;
            let _ = KEY_INFO_INSTALL;
            return Some(reply);
        }

        None
    }
}

/// The four handshake messages at fixed nonces, for `tools/dot11check.py`.
///
/// The key descriptor is 95 bytes of fields in a fixed order and **nothing in
/// this tree reads one that this tree did not write**, so the layout has
/// exactly as much evidence behind it as one person's reading of the standard.
/// Scapy's `EAPOL_KEY` is a second reading.
///
/// The nonces are overwritten with constants after construction, because they
/// come from `rdtsc` and a dump nobody can reproduce is not a fixture.
pub fn dump() {
    use crate::kprintln;
    let aa: [u8; 6] = [0x02, 0, 0, 0, 0, 0xAA];
    let spa: [u8; 6] = [0x02, 0, 0, 0, 0, 0x11];

    let line = |name: &str, f: &[u8]| {
        let mut hex = alloc::string::String::with_capacity(f.len() * 2);
        for b in f {
            hex.push(char::from_digit((b >> 4) as u32, 16).unwrap_or('0'));
            hex.push(char::from_digit((b & 0xF) as u32, 16).unwrap_or('0'));
        }
        kprintln!("frame {} {}", name, hex);
    };

    let mut auth = Authenticator::new("correct horse", b"glados", aa, spa);
    auth.anonce = [0x11; 32];
    let m1 = auth.message1();
    line("eapol_m1", &m1);

    let mut sup = Supplicant::new("correct horse", b"glados", aa, spa);
    sup.snonce = [0x22; 32];
    if let Some(m2) = sup.on_frame(&m1) {
        line("eapol_m2", &m2);
        if let Some(m3) = auth.on_frame(&m2) {
            line("eapol_m3", &m3);
            if let Some(m4) = sup.on_frame(&m3) {
                line("eapol_m4", &m4);
            }
        }
    }
}

pub fn selftest() -> bool {
    // IEEE 802.11i Annex H.4: passphrase "password", SSID "IEEE".
    let k = pmk("password", b"IEEE");
    let want: [u8; 32] = [
        0xf4, 0x2c, 0x6f, 0xc5, 0x2d, 0xf0, 0xeb, 0xef, 0x9e, 0xbb, 0x4b, 0x90, 0xb3, 0x8a, 0x5f,
        0x90, 0x2e, 0x83, 0xfe, 0x1b, 0x13, 0x5a, 0x70, 0xe2, 0x3a, 0xed, 0x76, 0x2e, 0x97, 0x10,
        0xa1, 0x2e,
    ];
    if k[..] != want[..] {
        return false;
    }

    // The PTK must not depend on which side is called which: swapping the
    // roles has to produce the same key, or the two ends never agree.
    let aa = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    let spa = [0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB];
    let an = [0xAA; 32];
    let sn = [0xBB; 32];
    let a = ptk(&k, &aa, &spa, &an, &sn);
    let b = ptk(&k, &spa, &aa, &sn, &an);
    if a != b || a.len() != PTK_LEN {
        return false;
    }
    // And a different nonce must give a different key, which is the freshness
    // property the whole handshake exists to provide.
    let c = ptk(&k, &aa, &spa, &an, &[0xCC; 32]);
    a != c
}

pub fn report() {
    use crate::gfx::console::{self, LTGRAY, LTGREEN, YELLOW};
    use crate::kprintln;

    console::set_color(YELLOW);
    kprintln!("[wpa2]");
    console::set_color(LTGRAY);
    let ok = selftest() && aes::selftest() && sha1::selftest();
    console::set_color(if ok { LTGREEN } else { crate::gfx::console::LTRED });
    kprintln!(
        "  supplicant crypto {}",
        if ok { "matches the IEEE vectors" } else { "IS WRONG" }
    );
    console::set_color(LTGRAY);
    kprintln!("  pmk  pbkdf2-hmac-sha1, 4096 rounds, ssid as salt");
    kprintln!("  ptk  802.11 prf-384 over both nonces and both macs");
    kprintln!("  gtk  rfc 3394 key unwrap under the kek");
    console::set_color(YELLOW);
    kprintln!("  nothing to run it on: wlan0 has no driver.");
    console::set_color(LTGRAY);
    kprintln!("  this is pure functions over byte slices by design -- a driver");
    kprintln!("  supplies frames, this supplies answers, and none of it changes.");
}
