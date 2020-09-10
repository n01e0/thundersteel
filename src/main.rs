#[macro_use]
extern crate log;

#[macro_use]
extern crate clap;

use std::{env, process, fs, thread};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{self, MutableTcpPacket, TcpFlags};
use pnet::transport::{
    self, 
    TransportChannelType, 
    TransportProtocol,
    TransportReceiver,
    TransportSender,
};

const TCP_SIZE: usize = 20;

struct PacketInfo {
    my_ipaddr:      Ipv4Addr,
    target_ipaddr:  Ipv4Addr,
    my_port:        u16,
    maximun_port:   u16,
    scan_type:      ScanType,
}

#[derive(Copy, Clone)]
enum ScanType {
    Syn   = TcpFlags::SYN as isize,
    Fin   = TcpFlags::FIN as isize,
    Xmas  = (TcpFlags::FIN | TcpFlags::URG | TcpFlags::PSH) as isize,
    Null  = 0,
}

fn main() {
    if let Err(_) = env::var("RUST_LOG") {
        env::set_var("RUST_LOG", "debug");
    }
    env_logger::init();
    let matches = clap_app!(thundersteel =>
        (version:       crate_version!())
        (author:        crate_authors!())
        (about:         crate_description!())
        (@arg target_ip: +required "target ip address")
        (@arg type: "scan type [sS|sF|sX|sN](SYN|FIN|Xmas|Null)")
    ).get_matches();

    let packet_info = {
        let contents = fs::read_to_string(".env").expect("Failed to read file");
        let lines = contents.split('\n').collect::<Vec<_>>();
        let mut map = HashMap::new();
        for line in lines {
            let elm = line.split('=').map(str::trim).collect::<Vec<_>>();
            if elm.len() == 2 {
                map.insert(elm[0], elm[1]);
            }
        }

        PacketInfo {
            my_ipaddr:      map["MY_IPADDR"].parse().expect("invalid ipaddr"),
            target_ipaddr:  matches.value_of("target_ip").unwrap().parse().expect("invalid target ip addr"),
            my_port:        map["MY_PORT"].parse().expect("invalid port number"),
            maximun_port:   map["MAXIMUM_PORT_NUM"].parse().expect("invalid port num"),
            scan_type:      match matches.value_of("type").unwrap_or("sS") {
                "sS" => ScanType::Syn,
                "sF" => ScanType::Fin,
                "sX" => ScanType::Xmas,
                "sN" => ScanType::Null,
                _ => {
                    error!("Undefined scan method, only accept [sS|sF|sX|sN].");
                    process::exit(1);
                }
            },
        }
    };

    let (mut ts, mut tr) = transport::transport_channel(
        1024,
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp)),
    ).unwrap_or_else(|err|
        match err.kind() {
            std::io::ErrorKind::PermissionDenied => {
                eprintln!("Syn scan need root permission");
                eprintln!("usage: sudo {} <target_ip>", 
                    std::env::args().collect::<Vec<String>>().first().unwrap()
                );
                std::process::exit(1);
            },
            other => panic!(other),
        }
    );

    let (send_err, recv_err) = rayon::join(
        || send_packet(&mut ts, &packet_info),
        || receive_packets(&mut tr, &packet_info),
    );

    if let Err(e) = send_err {
        eprintln!("{}", e);
    }
    if let Err(e) = recv_err {
        eprintln!("{}", e);
    }
}

fn build_packet(packet_info: &PacketInfo) -> [u8; TCP_SIZE] {
    let mut tcp_buffer = [0u8; TCP_SIZE];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buffer[..]).unwrap();
    tcp_header.set_source(packet_info.my_port);
    tcp_header.set_data_offset(5);
    tcp_header.set_flags(packet_info.scan_type as u16);
    let checksum = tcp::ipv4_checksum(
            &tcp_header.to_immutable(),
            &packet_info.my_ipaddr,
            &packet_info.target_ipaddr,
    );
    tcp_header.set_checksum(checksum);

    tcp_buffer
}

fn send_packet(ts: &mut TransportSender, packet_info: &PacketInfo) -> Result<(), failure::Error> {
    let mut packet = build_packet(packet_info);
    for i in 1..=packet_info.maximun_port {
        let mut tcp_header = MutableTcpPacket::new(&mut packet)
            .ok_or_else(|| failure::err_msg("invalid packet"))?;

        reregister_destination_port(i, &mut tcp_header, packet_info);
        thread::sleep(Duration::from_nanos(1));
        ts.send_to(tcp_header, IpAddr::V4(packet_info.target_ipaddr))?;
    }
    Ok(())
}

fn reregister_destination_port(target: u16, tcp_header: &mut MutableTcpPacket, packet_info: &PacketInfo) {
    tcp_header.set_destination(target);
    let checksum = tcp::ipv4_checksum(
        &tcp_header.to_immutable(),
        &packet_info.my_ipaddr,
        &packet_info.target_ipaddr
    );
    tcp_header.set_checksum(checksum);
}

fn receive_packets(tr: &mut TransportReceiver, packet_info: &PacketInfo) -> Result<(), failure::Error> {
    let mut reply_ports = Vec::new();
    let mut packet_iter = transport::tcp_packet_iter(tr);
    loop {
        let tcp_packet = match packet_iter.next() {
            Ok((tcp_packet, _)) => {
                if tcp_packet.get_destination() == packet_info.my_port {
                    tcp_packet
                } else {
                    continue;
                }
            },
            Err(_) => continue,
        };

        let target_port = tcp_packet.get_source();
        match packet_info.scan_type {
            ScanType::Syn => {
                if tcp_packet.get_flags() == TcpFlags::SYN | TcpFlags::ACK {
                    println!("port {} is open", target_port);
                }
            },
            ScanType::Fin | ScanType::Xmas | ScanType::Null => reply_ports.push(target_port),
        }

        if target_port != packet_info.maximun_port {
            continue;
        }
        match packet_info.scan_type {
            ScanType::Fin | ScanType::Xmas | ScanType::Null => {
                for i in 1..=packet_info.maximun_port {
                    if reply_ports.iter().find(|&&x| x == i).is_none() {
                        println!("port {} is open", i);
                    }
                }
            },
            _ => {},
        }
        return Ok(());
    }
}
