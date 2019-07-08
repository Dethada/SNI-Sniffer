use std::error::Error;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

use pcap_parser::Capture;

use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;

use std::net::IpAddr;

use crate::common::parse_tls;

fn parse(data:&[u8]) {
    if data.is_empty() { return; }

    // check L3 protocol
    match data[0] & 0xf0 {
        0x40 => { // IPv4
            let ipv4 = &Ipv4Packet::new(data).unwrap();

            let src = IpAddr::V4(ipv4.get_source());
            let dst = IpAddr::V4(ipv4.get_destination());

            match ipv4.get_next_level_protocol() {
                IpNextHeaderProtocols::Tcp => {
                    if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                        parse_tls(src, dst, &tcp);
                    }
                },
                _ => ()
            }
        },
        0x60 => { // IPv6
            let ipv6 = &Ipv6Packet::new(data).unwrap();
            let src = IpAddr::V6(ipv6.get_source());
            let dst = IpAddr::V6(ipv6.get_destination());
            match ipv6.get_next_header() {
                IpNextHeaderProtocols::Tcp => {
                    if let Some(tcp) = TcpPacket::new(ipv6.payload()) {
                        parse_tls(src, dst, &tcp);
                    }
                },
                _ => ()
            }
        },
        _ => { error!("Unknown layer 3 protocol") }
    }
}

fn get_data_raw<'a>(packet: &'a pcap_parser::Packet) -> &'a[u8] {
    // println!("data.len: {}, caplen: {}", packet.data.len(), packet.header.caplen);
    let maxlen = packet.header.caplen as usize;
    &packet.data[..maxlen]
}

/// See http://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html
fn get_data_linux_cooked<'a>(packet: &'a pcap_parser::Packet) -> &'a[u8] {
    // println!("data.len: {}, caplen: {}", packet.data.len(), packet.header.caplen);
    let maxlen = packet.header.caplen as usize;
    &packet.data[16..maxlen]
}

fn get_data_raw_ipv4<'a>(packet: &'a pcap_parser::Packet) -> &'a[u8] {
    // println!("data.len: {}, caplen: {}", packet.data.len(), packet.header.caplen);
    let maxlen = packet.header.caplen as usize;
    &packet.data[..maxlen]
}

// BSD loopback encapsulation; the link layer header is a 4-byte field, in host byte order,
// containing a value of 2 for IPv4 packets, a value of either 24, 28, or 30 for IPv6 packets, a
// value of 7 for OSI packets, or a value of 23 for IPX packets. All of the IPv6 values correspond
// to IPv6 packets; code reading files should check for all of them.
// Note that ``host byte order'' is the byte order of the machine on which the packets are
// captured; if a live capture is being done, ``host byte order'' is the byte order of the machine
// capturing the packets, but if a ``savefile'' is being read, the byte order is not necessarily
// that of the machine reading the capture file.
fn get_data_null<'a>(packet: &'a pcap_parser::Packet) -> &'a[u8] {
    let maxlen = packet.header.caplen as usize;
    &packet.data[4..maxlen]
}

fn get_data_ethernet<'a>(packet: &'a pcap_parser::Packet) -> &'a[u8] {
    let maxlen = packet.header.caplen as usize;
    &packet.data[14..maxlen]
}

fn iter_capture(cap: &mut Capture) {
    let get_data = match cap.get_datalink() {
        pcap_parser::Linktype(0)   => get_data_null,
        pcap_parser::Linktype(1)   => get_data_ethernet,
        pcap_parser::Linktype(101) => get_data_raw,
        pcap_parser::Linktype(113) => get_data_linux_cooked,
        pcap_parser::Linktype(228) => get_data_raw_ipv4,
        pcap_parser::Linktype(239) => pcap_parser::get_data_nflog,
        pcap_parser::Linktype(x)   => panic!("Unsupported link type {}", x),
    };
    //
    for packet in cap.iter_packets() {
        let data = get_data(&packet);
        parse(data);
    }
}

fn try_open_capture<'a>(buffer: &'a[u8]) -> Result<Box<Capture + 'a>,&'static str> {
    // try pcap first
    match pcap_parser::PcapCapture::from_file(&buffer) {
        Ok(cap) => {
            println!("PCAP found");
            return Ok(Box::new(cap));
        },
        _e => (), // println!("probing for PCAP failed: {:?}", e),
    }

    // try pcapng
    match pcap_parser::PcapNGCapture::from_file(&buffer) {
        Ok(cap) => {
            return Ok(Box::new(cap));
        },
        _e  => (),
    }

    Err("Format not recognized")
}

pub fn process(filename: &str) {
    let path = Path::new(&filename);
    let display = path.display();
    let mut file = match File::open(path) {
        // The `description` method of `io::Error` returns a string that
        // describes the error
        Err(why) => panic!("couldn't open {}: {}", display,
                           why.description()),
        Ok(file) => file,
    };

    let mut buffer = Vec::new();
    match file.read_to_end(&mut buffer) {
        Err(why) => panic!("couldn't open {}: {}", display,
                           why.description()),
        Ok(_) => (),
    };

    match try_open_capture(&buffer) {
        Ok(mut cap) => {
            iter_capture(cap.as_mut());
        },
        Err(e) => println!("Failed to open file: {:?}", e),
    };
}
