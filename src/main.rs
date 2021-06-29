use std::io;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::collections::hash_map::Entry;

mod tcp;

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
struct Quad {
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
}
fn main() -> io::Result<()>{
    let mut connections: HashMap<Quad, tcp::Connection> = Default::default();
    let mut nic = tun_tap::Iface::without_packet_info("tun0", tun_tap::Mode::Tun)?;
    let mut buf = [0u8; 1504];
    loop {
        let nbytes = nic.recv(&mut buf[..])?;
        // if s/withoud_packet_info/new/:
        //
        // let _eth_flags = u16::from_be_bytes([buf[0], buf[1]]);
        // let eth_proto = u16::from_be_bytes([buf[2], buf[3]]);
        // if eth_proto != 0x0800 {
        //     // no ipv4 packet
        //     continue;
        // }
        // and also include on send

        match etherparse::Ipv4HeaderSlice::from_slice(&buf[..nbytes]) {
            Ok(iph) => {
                let src = iph.source_addr();
                let destination = iph.destination_addr();
                if iph.protocol() != 0x06 {
                    // not tcp
                    continue;
                }
                
                match etherparse::TcpHeaderSlice::from_slice(&buf[iph.slice().len()..nbytes]) {
                    Ok(tcph) => {
                        
                        let datai = iph.slice().len() + tcph.slice().len(); 
                        // (srcip, srcport, dstip, dstport)
                        match connections.entry(Quad {
                            src: (src, tcph.source_port()),
                            dst: (destination, tcph.destination_port()),
                        }) {
                            Entry::Occupied(mut c) => {
                                c.get_mut().on_packet(&mut nic, iph, tcph, &buf[datai..nbytes])?;
                            },
                            Entry::Vacant(e) => {
                                if let Some(c) = tcp::Connection::accept(&mut nic, iph, tcph, &buf[datai..nbytes])? {
                                    e.insert(c);
                                }
                            }
                        }
                    },
                    Err(e) => {
                        eprintln!("Ignoring tcp packet {:?}", e);
                    }
                }
            },
            Err(e) => {
                eprintln!("Ignoring ipv4 packet {:?}", e);
            }
        }

    }
}
