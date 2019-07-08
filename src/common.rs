use std::net::IpAddr;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use crate::tls::{self,TlsParser,STREAM_TOSERVER};

/// Print SNI if exists
pub fn parse_tls(src: IpAddr, dst: IpAddr, tcp: &TcpPacket) {
    let payload = tcp.payload();
    if payload.len() == 0 { return; }

    if tls::tls_probe(&payload) {
        let mut parser = TlsParser::new(&payload);

        parser.parse(&payload, STREAM_TOSERVER);
        if parser.sni.len() > 0 {
            println!("TCP {:?}:{} -> {:?}:{}",
                src, tcp.get_source(),
                dst, tcp.get_destination());
            println!("SNI: {:#?}", parser.sni);
        }
    }
}