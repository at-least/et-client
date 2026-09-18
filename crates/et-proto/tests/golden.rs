//! Golden wire-format tests: the expected byte strings below are the
//! hand-encoded protobuf wire format for the given messages, matching what
//! the C++ implementation (protobuf, proto2, ordered fields) puts on the
//! wire. They lock the Rust encoding against drift. Field-by-field:
//! `<tag byte> <len varint> <bytes>` for length-delimited, `<tag> <varint>`
//! for ints; proto2 optional fields explicitly set to a default value must
//! still be emitted (e.g. `08 00` for `jumphost = false`).

use et_proto::messages::*;
use et_proto::*;
use prost::Message;

#[test]
fn connect_request_golden() {
    let req = ConnectRequest {
        client_id: Some("XXX0123456789abcd".into()),
        version: Some(PROTOCOL_VERSION),
    };
    let mut expected = Vec::new();
    expected.push(0x0A);
    expected.push(17); // len("XXX0123456789abcd") = 3 + 10 + 4
    expected.extend_from_slice(b"XXX0123456789abcd");
    expected.extend_from_slice(&[0x10, 0x06]); // version = 6
    assert_eq!(req.encode_to_vec(), expected);
    assert_eq!(ConnectRequest::decode(&expected[..]).unwrap(), req);
}

#[test]
fn connect_response_golden() {
    let resp = ConnectResponse {
        status: Some(ConnectStatus::ReturningClient as i32),
        error: None,
    };
    assert_eq!(resp.encode_to_vec(), vec![0x08, 0x02]);

    let err = ConnectResponse {
        status: Some(ConnectStatus::MismatchedProtocol as i32),
        error: Some("boom".into()),
    };
    assert_eq!(err.encode_to_vec(), vec![0x08, 0x04, 0x12, 0x04, b'b', b'o', b'o', b'm']);
}

#[test]
fn sequence_header_and_catchup_golden() {
    let sh = SequenceHeader { sequence_number: Some(5) };
    assert_eq!(sh.encode_to_vec(), vec![0x08, 0x05]);

    let cb = CatchupBuffer {
        buffer: vec![b"a".to_vec(), vec![0x01, 0x02]],
    };
    assert_eq!(cb.encode_to_vec(), vec![0x0A, 0x01, b'a', 0x0A, 0x02, 0x01, 0x02]);
}

#[test]
fn proto2_default_presence_is_serialized() {
    // Some(false) must stay on the wire (proto2 explicit presence).
    let p = InitialPayload {
        jumphost: Some(false),
        reversetunnels: Vec::new(),
        environmentvariables: Default::default(),
    };
    assert_eq!(p.encode_to_vec(), vec![0x08, 0x00]);
    // None must be absent.
    let p = InitialPayload { jumphost: None, ..p };
    assert_eq!(p.encode_to_vec(), Vec::<u8>::new());
}

#[test]
fn initial_payload_with_map_golden() {
    let payload = InitialPayload {
        jumphost: Some(false),
        environmentvariables: [("TERM".to_string(), "xterm".to_string())].into_iter().collect(),
        ..InitialPayload::default()
    };
    // map entry: tag 3 (1A), len 11, key: 0A 04 TERM, value: 12 05 xterm
    // entry: 0x1A (tag 3, wire 2), len 13 = (0A 04 + "TERM") + (12 05 + "xterm")
    let expected = [
        0x08, 0x00, 0x1A, 0x0D, 0x0A, 0x04, b'T', b'E', b'R', b'M', 0x12, 0x05, b'x', b't', b'e',
        b'r', b'm',
    ];
    assert_eq!(payload.encode_to_vec(), expected);
}

#[test]
fn terminal_buffer_golden() {
    let tb = TerminalBuffer { buffer: Some(b"hi".to_vec()) };
    assert_eq!(tb.encode_to_vec(), vec![0x0A, 0x02, b'h', b'i']);
}

#[test]
fn term_init_golden() {
    let ti = TermInit {
        environmentnames: vec!["TERM".into()],
        environmentvalues: vec!["xterm-256color".into()],
    };
    let mut expected = vec![0x0A, 0x04];
    expected.extend_from_slice(b"TERM");
    expected.extend_from_slice(&[0x12, 0x0E]);
    expected.extend_from_slice(b"xterm-256color");
    assert_eq!(ti.encode_to_vec(), expected);
}

#[test]
fn terminal_user_info_golden() {
    let tui = TerminalUserInfo {
        id: Some("abc".into()),
        passkey: Some("def".into()),
        uid: Some(1000),
        gid: Some(20),
        fd: None,
    };
    let expected = [
        0x0A, 0x03, b'a', b'b', b'c', // id
        0x12, 0x03, b'd', b'e', b'f', // passkey
        0x18, 0xE8, 0x07, // uid = 1000 varint
        0x20, 0x14, // gid = 20
    ];
    assert_eq!(tui.encode_to_vec(), expected);
}

#[test]
fn terminal_info_golden() {
    let ti = TerminalInfo {
        id: Some("".into()),
        row: Some(24),
        column: Some(80),
        width: Some(0),
        height: Some(0),
    };
    let expected = [
        0x0A, 0x00, // id = ""
        0x10, 0x18, // row = 24
        0x18, 0x50, // column = 80
        0x20, 0x00, // width = 0 (explicit default)
        0x28, 0x00, // height = 0 (explicit default)
    ];
    assert_eq!(ti.encode_to_vec(), expected);
}

#[test]
fn packet_and_frames_golden() {
    // [encrypted][header][payload] layout.
    let p = Packet::new(terminal_packet_type::KEEP_ALIVE, Vec::new());
    assert_eq!(p.serialize(), vec![0, 0]);
    let p = Packet::new(et_packet_type::INITIAL_PAYLOAD, b"z".to_vec());
    assert_eq!(p.serialize(), vec![0, 253, b'z']);

    // TCP-leg frame: u32 BE length prefix.
    let framed = [0, 0, 0, 3, 0, 253, b'z'];
    let parsed = Packet::parse(&framed[4..]).unwrap();
    assert_eq!(parsed, p);
    assert_eq!(parsed.header(), et_packet_type::INITIAL_PAYLOAD);

    // Unix-leg frame: i64 LE length prefix.
    let mut unix = 3i64.to_le_bytes().to_vec();
    unix.extend_from_slice(&[0, 253, b'z']);
    assert_eq!(Packet::parse(&unix[8..]).unwrap(), p);
}
