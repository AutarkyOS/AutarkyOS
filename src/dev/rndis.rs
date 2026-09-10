//! RNDIS: Microsoft's remote NDIS, which is how a phone shares its network.
//!
//! **This is a class driver and that is the whole reason it exists.** Wireless
//! hardware has no common register interface -- every vendor's MAC is its own,
//! which is why Linux carries dozens of 802.11 drivers and why the RTL8188EU
//! work in this tree buys exactly one dongle. RNDIS is the opposite shape: an
//! interface class, `E0/01/03`, that almost every Android phone presents in USB
//! tethering mode. Driving it puts *any* machine on a network through *any*
//! such phone's radio, with no radio code and no firmware blob anywhere.
//!
//! It sits beside CDC-ECM (`02/06/00`), which this kernel already drives for
//! the same reason and by the same route. Between them they cover most of the
//! USB networking hardware in the world.
//!
//! ### Why it needs a module where ECM needed none
//!
//! ECM hands you an interface that carries bare Ethernet frames: configure the
//! endpoints and write. RNDIS puts a control protocol in front, and until you
//! have spoken it the device **accepts bulk writes and silently passes
//! nothing**. `xhci::parse_config` already carries a note about exactly that,
//! from the day QEMU's `usb-net` offered RNDIS as its first configuration and
//! taking it cost "a send that worked and a receive that never fired".
//!
//! So there are two things here: the control messages, and a 44-byte header
//! that wraps every frame in both directions.
//!
//! ### What is pure and what is not
//!
//! Everything in this file is a pure function over byte slices, and every one
//! is checked at boot. The transfers that carry these bytes live in
//! `xhci`, because that is where a control transfer is. A protocol whose
//! encoding can only be tested by owning the hardware is a protocol nobody
//! checks, and this one is entirely arithmetic on little-endian `u32`s.

use alloc::vec::Vec;

// ---------------------------------------------------------------- messages

pub const MSG_PACKET: u32 = 0x0000_0001;
pub const MSG_INITIALIZE: u32 = 0x0000_0002;
pub const MSG_QUERY: u32 = 0x0000_0004;
pub const MSG_SET: u32 = 0x0000_0005;

pub const CMPLT_INITIALIZE: u32 = 0x8000_0002;
pub const CMPLT_QUERY: u32 = 0x8000_0004;
pub const CMPLT_SET: u32 = 0x8000_0005;

pub const STATUS_SUCCESS: u32 = 0x0000_0000;

/// The permanent hardware address, which is what a tethering phone reports as
/// its own MAC rather than the handset's Wi-Fi one.
pub const OID_802_3_PERMANENT_ADDRESS: u32 = 0x0101_0101;
/// Which frames the device should pass up. Until this is set the device is
/// initialised, answering queries, and delivering nothing.
pub const OID_GEN_CURRENT_PACKET_FILTER: u32 = 0x0001_010E;

/// Directed, multicast and broadcast. Not promiscuous: this machine has one
/// address and asking a tethering phone for everybody else's traffic is a
/// request it may refuse outright.
pub const FILTER_NORMAL: u32 = 0x0000_000B;

/// The header on every data transfer, in both directions.
pub const PACKET_HEADER: usize = 44;

/// What `MaxTransferSize` is negotiated as. One Ethernet frame plus the header
/// and room to spare, rather than the 16 KiB some drivers ask for: this
/// receives into a fixed buffer and a device that took the larger figure at its
/// word could hand back more than there is room for.
pub const MAX_TRANSFER: u32 = 2048;

fn put(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

pub fn get(b: &[u8], at: usize) -> Option<u32> {
    if at + 4 > b.len() {
        return None;
    }
    Some(u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]))
}

/// `REMOTE_NDIS_INITIALIZE_MSG`. The first thing said, and until its completion
/// arrives nothing else may be.
pub fn initialize(request_id: u32) -> Vec<u8> {
    let mut m = Vec::new();
    put(&mut m, MSG_INITIALIZE);
    put(&mut m, 24);
    put(&mut m, request_id);
    put(&mut m, 1); // major
    put(&mut m, 0); // minor
    put(&mut m, MAX_TRANSFER);
    m
}

/// `REMOTE_NDIS_QUERY_MSG` with an empty information buffer.
///
/// The offset field is measured from byte 8 of the message rather than from
/// its start, which is the detail that makes a hand-written parser read the
/// wrong sixteen bytes and conclude the device answered garbage.
pub fn query(request_id: u32, oid: u32) -> Vec<u8> {
    let mut m = Vec::new();
    put(&mut m, MSG_QUERY);
    put(&mut m, 28);
    put(&mut m, request_id);
    put(&mut m, oid);
    put(&mut m, 0); // information buffer length
    put(&mut m, 0); // information buffer offset
    put(&mut m, 0); // device vc handle
    m
}

/// `REMOTE_NDIS_SET_MSG` carrying one `u32`, which is every set this driver
/// needs to make.
pub fn set_u32(request_id: u32, oid: u32, value: u32) -> Vec<u8> {
    let mut m = Vec::new();
    put(&mut m, MSG_SET);
    put(&mut m, 32);
    put(&mut m, request_id);
    put(&mut m, oid);
    put(&mut m, 4); // information buffer length
    put(&mut m, 20); // offset, from byte 8
    put(&mut m, 0); // device vc handle
    put(&mut m, value);
    m
}

/// The status of a completion, or `None` if this is not the completion asked
/// for.
///
/// **The request id is checked and that is not pedantry.** A completion is read
/// by polling a control endpoint, so a slow device's answer to the *previous*
/// message is what arrives first; accepting it means reading an INITIALIZE
/// result as a SET result and concluding the filter was accepted when nothing
/// was sent.
pub fn completion(buf: &[u8], want_type: u32, want_id: u32) -> Option<u32> {
    let ty = get(buf, 0)?;
    let id = get(buf, 8)?;
    if ty != want_type || id != want_id {
        return None;
    }
    get(buf, 12)
}

/// The information buffer of a `QUERY_CMPLT`, if it carries one.
///
/// Offsets in this protocol are from byte 8, so the eight is added here in the
/// one place that reads one.
pub fn query_info(buf: &[u8]) -> Option<&[u8]> {
    let len = get(buf, 16)? as usize;
    let off = get(buf, 20)? as usize;
    let at = off.checked_add(8)?;
    let end = at.checked_add(len)?;
    if end > buf.len() {
        return None;
    }
    Some(&buf[at..end])
}

/// The MAC out of a `QUERY_CMPLT` for `OID_802_3_PERMANENT_ADDRESS`.
pub fn mac_of(buf: &[u8]) -> Option<[u8; 6]> {
    let info = query_info(buf)?;
    if info.len() < 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&info[..6]);
    // All-zero is what a device answers when it has no address rather than an
    // address of zero, and using it produces an interface nothing can reach
    // with no error anywhere.
    if mac == [0; 6] {
        return None;
    }
    Some(mac)
}

// ------------------------------------------------------------------- frames

/// Wrap an Ethernet frame for transmission.
///
/// Written into a caller-provided buffer rather than returning a `Vec`,
/// because the only caller already owns a DMA buffer and a second copy per
/// frame is the sort of thing that never shows up in a profile and is there in
/// every packet.
pub fn wrap(frame: &[u8], out: &mut [u8]) -> Option<usize> {
    let total = PACKET_HEADER + frame.len();
    if out.len() < total {
        return None;
    }
    for b in out[..PACKET_HEADER].iter_mut() {
        *b = 0;
    }
    out[0..4].copy_from_slice(&MSG_PACKET.to_le_bytes());
    out[4..8].copy_from_slice(&(total as u32).to_le_bytes());
    // From byte 8, so the header's own 44 becomes 36.
    out[8..12].copy_from_slice(&((PACKET_HEADER - 8) as u32).to_le_bytes());
    out[12..16].copy_from_slice(&(frame.len() as u32).to_le_bytes());
    out[PACKET_HEADER..total].copy_from_slice(frame);
    Some(total)
}

/// The Ethernet frame inside a received transfer.
///
/// Every bound is checked against the buffer actually received rather than
/// against the length the device claims, because the device is on the far side
/// of a cable and this is the one place its numbers are believed.
pub fn unwrap(buf: &[u8]) -> Option<&[u8]> {
    if get(buf, 0)? != MSG_PACKET {
        return None;
    }
    let off = get(buf, 8)? as usize;
    let len = get(buf, 12)? as usize;
    let at = off.checked_add(8)?;
    let end = at.checked_add(len)?;
    if end > buf.len() || len == 0 {
        return None;
    }
    Some(&buf[at..end])
}

// ------------------------------------------------------------------ checks

pub fn checks() -> Vec<(&'static str, bool)> {
    let mut v = Vec::new();

    let init = initialize(1);
    v.push(("an initialize message is 24 bytes", init.len() == 24));
    v.push(("and says so in its length field", get(&init, 4) == Some(24)));
    v.push(("its type is INITIALIZE", get(&init, 0) == Some(MSG_INITIALIZE)));

    let q = query(7, OID_802_3_PERMANENT_ADDRESS);
    v.push(("a query is 28 bytes", q.len() == 28));
    v.push(("and carries the oid asked for", get(&q, 12) == Some(OID_802_3_PERMANENT_ADDRESS)));

    let s = set_u32(9, OID_GEN_CURRENT_PACKET_FILTER, FILTER_NORMAL);
    v.push(("a set is 32 bytes", s.len() == 32));
    v.push(("its value follows the header", get(&s, 28) == Some(FILTER_NORMAL)));
    // The offset is from byte 8, so a value at byte 28 is at offset 20. Getting
    // this wrong points the device at the message header and it sets whatever
    // it finds there.
    v.push(("and its offset is measured from byte 8", get(&s, 20) == Some(20)));

    // A completion for the wrong request must not be taken for this one.
    let mut c = Vec::new();
    put(&mut c, CMPLT_SET);
    put(&mut c, 16);
    put(&mut c, 9);
    put(&mut c, STATUS_SUCCESS);
    v.push(("a matching completion answers its status",
            completion(&c, CMPLT_SET, 9) == Some(STATUS_SUCCESS)));
    v.push(("a completion for another request is refused",
            completion(&c, CMPLT_SET, 8).is_none()));
    v.push(("and so is one of another type",
            completion(&c, CMPLT_QUERY, 9).is_none()));
    v.push(("a truncated completion is refused", completion(&c[..8], CMPLT_SET, 9).is_none()));

    // A query completion carrying a MAC.
    let mut qc = Vec::new();
    put(&mut qc, CMPLT_QUERY);
    put(&mut qc, 32);
    put(&mut qc, 3);
    put(&mut qc, STATUS_SUCCESS);
    put(&mut qc, 6); // information length
    put(&mut qc, 16); // offset from byte 8, so byte 24
    qc.extend_from_slice(&[0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);
    v.push(("a mac is read from the information buffer",
            mac_of(&qc) == Some([0x02, 0x11, 0x22, 0x33, 0x44, 0x55])));

    // The same completion claiming a buffer past the end of itself.
    let mut bad = qc.clone();
    bad[16..20].copy_from_slice(&64u32.to_le_bytes());
    v.push(("an information length past the buffer is refused", mac_of(&bad).is_none()));
    let mut far = qc.clone();
    far[20..24].copy_from_slice(&0xFFFF_FFF0u32.to_le_bytes());
    v.push(("and an offset that would overflow is refused", mac_of(&far).is_none()));

    let mut zero = qc.clone();
    let n = zero.len();
    for b in zero[n - 6..].iter_mut() {
        *b = 0;
    }
    v.push(("an all-zero mac is refused rather than used", mac_of(&zero).is_none()));

    // Framing, both ways, and the round trip.
    let frame = [0xAAu8; 60];
    let mut out = [0u8; 256];
    let n = wrap(&frame, &mut out).unwrap_or(0);
    v.push(("a wrapped frame is 44 bytes longer", n == frame.len() + PACKET_HEADER));
    v.push(("its data offset is 36, being from byte 8", get(&out, 8) == Some(36)));
    v.push(("unwrapping gives back what went in", unwrap(&out[..n]) == Some(&frame[..])));

    v.push(("a buffer too small to wrap into is refused",
            wrap(&frame, &mut [0u8; 8]).is_none()));
    let mut short = out;
    short[12..16].copy_from_slice(&9999u32.to_le_bytes());
    v.push(("a data length past the transfer is refused", unwrap(&short[..n]).is_none()));
    let mut wrong = out;
    wrong[0..4].copy_from_slice(&MSG_QUERY.to_le_bytes());
    v.push(("a transfer that is not a packet message is refused",
            unwrap(&wrong[..n]).is_none()));
    let mut empty = out;
    empty[12..16].copy_from_slice(&0u32.to_le_bytes());
    v.push(("and a zero-length frame is refused", unwrap(&empty[..n]).is_none()));

    v
}
