#![cfg(all(feature = "tcp", feature = "ipv4", feature = "medium-ip"))]

use xarxa::Stack;
use xarxa::driver::PacketBuf;
use xarxa::iface::Medium;
use xarxa::tcp::State;
use xarxa::time::Instant;
#[cfg(feature = "tcp-sack")]
use xarxa::wire::TcpOption;
use xarxa::wire::{
    HardwareAddress, IPV4_HEADER_LEN, IpCidr, IpProtocol, Ipv4Addr, Ipv4Packet, TCP_HEADER_LEN, TcpPacket, TcpSeqNumber,
};

#[path = "../src/test_device.rs"]
mod test_device;
use test_device::TestDevice;

const LOCAL: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);
const REMOTE: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 2);

fn incoming(local_port: u16, ack: TcpSeqNumber, seq: i32, syn: bool, payload: &[u8]) -> Vec<u8> {
    let options_len = if syn && cfg!(feature = "tcp-sack") { 4 } else { 0 };
    let tcp_len = TCP_HEADER_LEN + options_len + payload.len();
    let mut bytes = vec![0; IPV4_HEADER_LEN + tcp_len];
    {
        let mut ip = Ipv4Packet::new_unchecked(&mut bytes);
        ip.set_version(4);
        ip.set_header_len(IPV4_HEADER_LEN as u8);
        ip.set_total_len((IPV4_HEADER_LEN + tcp_len) as u16);
        ip.set_next_header(IpProtocol::Tcp);
        ip.set_hop_limit(64);
        ip.set_src_addr(REMOTE);
        ip.set_dst_addr(LOCAL);
        ip.fill_checksum();
    }
    {
        let mut tcp = TcpPacket::new_unchecked(&mut bytes[IPV4_HEADER_LEN..]);
        tcp.set_src_port(80);
        tcp.set_dst_port(local_port);
        tcp.set_seq_number(TcpSeqNumber(seq));
        tcp.set_ack_number(ack);
        tcp.set_header_len((TCP_HEADER_LEN + options_len) as u8);
        tcp.set_syn(syn);
        tcp.set_ack(true);
        tcp.set_window_len(64000);
        if options_len != 0 {
            tcp.options_mut().copy_from_slice(&[4, 2, 0, 0]);
        }
        tcp.payload_mut().copy_from_slice(payload);
        tcp.fill_checksum(&REMOTE.into(), &LOCAL.into());
    }
    bytes
}

fn check_ack(bytes: &mut [u8], local_seq: TcpSeqNumber, ack: i32, sack: Option<(u32, u32)>) {
    let tcp = TcpPacket::new_checked(&mut bytes[IPV4_HEADER_LEN..]).unwrap();
    assert!(tcp.ack());
    assert!(!tcp.syn() && !tcp.fin() && !tcp.rst());
    assert_eq!(tcp.seq_number(), local_seq);
    assert_eq!(tcp.ack_number(), TcpSeqNumber(ack));
    assert!(tcp.payload().is_empty());
    assert!(tcp.verify_checksum(&LOCAL.into(), &REMOTE.into()));
    #[cfg(feature = "tcp-sack")]
    {
        let mut options = tcp.options();
        let mut ranges = [None; 3];
        while !options.is_empty() {
            let (rest, option) = TcpOption::parse(options).unwrap();
            if let TcpOption::SackRange(value) = option {
                ranges = value;
            }
            options = rest;
        }
        assert_eq!(ranges, [sack, None, None]);
    }
    #[cfg(not(feature = "tcp-sack"))]
    let _ = sack;
}

#[test]
fn immediate_ack_survives_device_backpressure() {
    let mut stack = Stack::new(0x1234_5678_dead_beef);
    let device = TestDevice::new(Medium::Ip);
    let iface = device.install(&mut stack, HardwareAddress::Ip);
    stack.iface(iface).add_ip_addr(IpCidr::new(LOCAL.into(), 24)).unwrap();
    let socket = stack
        .add_tcp_socket_with_bufs(vec![0; 4096].leak(), vec![0; 4096].leak())
        .unwrap();
    stack.tcp_socket(socket).connect((REMOTE, 80), 0).unwrap();
    stack.poll(Instant::ZERO);
    let (port, local_seq) = {
        let mut frames = device.tx.borrow_mut();
        assert_eq!(frames.len(), 1);
        let tcp = TcpPacket::new_checked(&mut frames[0][IPV4_HEADER_LEN..]).unwrap();
        (tcp.src_port(), tcp.seq_number() + 1)
    };
    device.tx.borrow_mut().clear();
    device
        .rx
        .borrow_mut()
        .push_back(incoming(port, local_seq, 10000, true, b""));
    stack.poll(Instant::from_millis(1));
    assert_eq!(stack.tcp_socket(socket).state(), State::Established);
    {
        let mut frames = device.tx.borrow_mut();
        assert_eq!(frames.len(), 1);
        check_ack(&mut frames[0], local_seq, 10001, None);
        frames.clear();
    }

    // With room, each out-of-order arrival still gets its own immediate loss
    // signal. Do not coalesce these merely because both arrive in one poll.
    device
        .rx
        .borrow_mut()
        .push_back(incoming(port, local_seq, 10005, false, b"efgh"));
    device
        .rx
        .borrow_mut()
        .push_back(incoming(port, local_seq, 10009, false, b"ijkl"));
    stack.poll(Instant::from_millis(2));
    {
        let mut frames = device.tx.borrow_mut();
        assert_eq!(frames.len(), 2);
        check_ack(&mut frames[0], local_seq, 10001, Some((10005, 10009)));
        check_ack(&mut frames[1], local_seq, 10001, Some((10005, 10013)));
        frames.clear();
    }

    // A full device may still deliver ingress. These duplicate ACKs cannot be
    // admitted yet; retain one pending ACK with the current receive/SACK state.
    device.room.set(Some(0));
    device
        .rx
        .borrow_mut()
        .push_back(incoming(port, local_seq, 10013, false, b"mnop"));
    device
        .rx
        .borrow_mut()
        .push_back(incoming(port, local_seq, 10017, false, b"qrst"));
    let now = Instant::from_millis(3);
    assert!(
        stack.poll(now) > now,
        "wait for driver readiness rather than busy-polling"
    );
    assert!(device.tx.borrow().is_empty());
    device.room.set(Some(1));
    stack.poll(Instant::from_millis(4));
    {
        let mut frames = device.tx.borrow_mut();
        assert_eq!(
            frames.len(),
            1,
            "retry the blocked duplicate ACK without another incoming segment"
        );
        check_ack(&mut frames[0], local_seq, 10001, Some((10005, 10021)));
        frames.clear();
    }
    device.room.set(None);
    stack.poll(Instant::from_millis(5));
    assert!(
        device.tx.borrow().is_empty(),
        "successful admission clears the pending ACK"
    );

    // Filling the gap advances the cumulative ACK. Even though the assembler
    // becomes empty, a blocked immediate ACK must not be forgotten until RTO.
    device.room.set(Some(0));
    device
        .rx
        .borrow_mut()
        .push_back(incoming(port, local_seq, 10001, false, b"abcd"));
    stack.poll(Instant::from_millis(6));
    assert!(device.tx.borrow().is_empty());
    device.room.set(Some(1));
    stack.poll(Instant::from_millis(7));
    {
        let mut frames = device.tx.borrow_mut();
        assert_eq!(frames.len(), 1, "retry the blocked gap-filling cumulative ACK");
        check_ack(&mut frames[0], local_seq, 10021, None);
        frames.clear();
    }
    // A single free pool buffer admits ingress but cannot build its immediate
    // ACK. Dropping that ingress frame frees room for dispatch to retry it.
    device.room.set(None);
    let mut held = Vec::new();
    while let Some(buf) = PacketBuf::try_new() {
        held.push(buf);
    }
    drop(held.pop().unwrap());
    device
        .rx
        .borrow_mut()
        .push_back(incoming(port, local_seq, 10001, false, b"abcd"));
    stack.poll(Instant::from_millis(8));
    {
        let mut frames = device.tx.borrow_mut();
        assert_eq!(
            frames.len(),
            1,
            "retry after the ingress frame releases its packet buffer"
        );
        check_ack(&mut frames[0], local_seq, 10021, None);
        frames.clear();
    }
    drop(held);

    let mut data = [0; 20];
    assert_eq!(stack.tcp_socket(socket).recv_slice(&mut data), Ok(20));
    assert_eq!(&data, b"abcdefghijklmnopqrst");

    syn_received_challenge_ack_keeps_control();
}

fn syn_received_challenge_ack_keeps_control() {
    let mut stack = Stack::new(0x9876_5432_dead_beef);
    let device = TestDevice::new(Medium::Ip);
    let iface = device.install(&mut stack, HardwareAddress::Ip);
    stack.iface(iface).add_ip_addr(IpCidr::new(LOCAL.into(), 24)).unwrap();
    let socket = stack
        .add_tcp_socket_with_bufs(vec![0; 4096].leak(), vec![0; 4096].leak())
        .unwrap();
    stack.tcp_socket(socket).connect((REMOTE, 80), 0).unwrap();
    stack.poll(Instant::ZERO);
    let (port, local_seq) = {
        let mut frames = device.tx.borrow_mut();
        let tcp = TcpPacket::new_checked(&mut frames[0][IPV4_HEADER_LEN..]).unwrap();
        (tcp.src_port(), tcp.seq_number() + 1)
    };
    device.tx.borrow_mut().clear();

    // Simultaneous open leaves the connection in SYN-RECEIVED after SYN|ACK.
    let mut syn = incoming(port, local_seq, 10000, true, b"");
    {
        let mut tcp = TcpPacket::new_unchecked(&mut syn[IPV4_HEADER_LEN..]);
        tcp.set_ack(false);
        tcp.fill_checksum(&REMOTE.into(), &LOCAL.into());
    }
    device.rx.borrow_mut().push_back(syn);
    stack.poll(Instant::from_millis(1));
    assert_eq!(stack.tcp_socket(socket).state(), State::SynReceived);
    {
        let mut frames = device.tx.borrow_mut();
        assert_eq!(frames.len(), 1);
        let tcp = TcpPacket::new_checked(&mut frames[0][IPV4_HEADER_LEN..]).unwrap();
        assert!(tcp.syn() && tcp.ack());
        frames.clear();
    }

    // Correct ACK number but unacceptable sequence: the response is a plain
    // challenge ACK, not a retransmitted SYN|ACK, even when initially blocked.
    device.room.set(Some(0));
    device
        .rx
        .borrow_mut()
        .push_back(incoming(port, local_seq, 20000, false, b""));
    stack.poll(Instant::from_millis(2));
    assert!(device.tx.borrow().is_empty());
    device.room.set(Some(1));
    stack.poll(Instant::from_millis(3));
    {
        let mut frames = device.tx.borrow_mut();
        assert_eq!(frames.len(), 1);
        check_ack(&mut frames[0], local_seq, 10001, None);
    }
    assert_eq!(stack.tcp_socket(socket).state(), State::SynReceived);
}
