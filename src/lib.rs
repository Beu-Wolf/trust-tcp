use std::io;
use std::io::prelude::*;
use std::sync::{Arc, Mutex, Condvar};
use std::collections::{HashMap, VecDeque, hash_map::Entry};
use std::net::Ipv4Addr;
use std::thread;

mod tcp;

const SENDQUEUE_SIZE: usize = 1024;

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
struct Quad {
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
}

#[derive(Default)]
struct C {
    manager: Mutex<ConnectionManager>,
    pending_var: Condvar,
}

type InterfaceHandle = Arc<C>;

pub struct Interface {
    ih: Option<InterfaceHandle>,
    jh: Option<thread::JoinHandle<io::Result<()>>>,
}


#[derive(Default)]
struct ConnectionManager {
    terminate: bool,
    connections: HashMap<Quad, tcp::Connection>,
    pending: HashMap<u16, VecDeque<Quad>>
}

fn packet_loop(mut nic: tun_tap::Iface, ih: InterfaceHandle) -> io::Result<()> {
    let mut buf = [0u8; 1504];
    loop {
        // TODO: set timeout for recv for TCP timers or ConnectionManager::terminate
        let nbytes = nic.recv(&mut buf[..])?;

        // TODO: if self.terminate && arc.get_Strong_refs(ih) == 1; then tear down all connections and return


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
                        let mut cmg = ih.manager.lock().unwrap();
                        let cm = &mut *cmg;

                        let quad = Quad {
                            src: (src, tcph.source_port()),
                            dst: (destination, tcph.destination_port()),
                        };

                        match cm.connections.entry(quad) {
                            Entry::Occupied(mut c) => {
                                c.get_mut().on_packet(&mut nic, iph, tcph, &buf[datai..nbytes])?;
                            },
                            Entry::Vacant(e) => {
                                if let Some(pending) = cm.pending.get_mut(&tcph.destination_port()) {
                                    if let Some(c) = tcp::Connection::accept(&mut nic, iph, tcph, &buf[datai..nbytes])? {
                                        e.insert(c);
                                        pending.push_back(quad);
                                        drop(cmg);
                                        ih.pending_var.notify_all();
                                        // TODO: Wake up pending accept()
                                    }
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


impl Interface {
    pub fn new() -> io::Result<Self> {
        let nic = tun_tap::Iface::without_packet_info("tun0", tun_tap::Mode::Tun)?;

        let ih: InterfaceHandle = Arc::default();

        let jh =  {
            let ih = ih.clone();
            thread::spawn(move || {
            let nic = nic;
            let ih = ih;
            let buf = [0u8; 1504];

            // do what main does
            packet_loop(nic, ih)
            })
        };

        Ok(Interface {
            ih: Some(ih),
            jh: Some(jh)
        })
    }

    pub fn bind(&mut self, port: u16) -> io::Result<TcpListener> {
        let mut cm = self.ih.as_mut().unwrap().manager.lock().unwrap();
        match cm.pending.entry(port) {
            Entry::Vacant(v) => {
                v.insert(VecDeque::new());
            },
            Entry::Occupied(_) => {
                return Err(io::Error::new(io::ErrorKind::AddrInUse, "port already bound"));
            }
        }

        drop(cm);
        Ok(TcpListener {
            port, 
            h: self.ih.as_mut().unwrap().clone()
        })
    }
}


impl Drop for Interface {
    fn drop(&mut self) {
        self.ih.as_mut().unwrap().manager.lock().unwrap().terminate = true;

        drop(self.ih.take());
        self.jh.take().expect("Interface dropped more than one").join().unwrap().unwrap();
    }
}

pub struct TcpStream {
    quad: Quad, 
    h: InterfaceHandle
}

impl Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut cm = self.h.manager.lock().unwrap();
        let c = cm.connections.get_mut(&self.quad).ok_or_else(|| io::Error::new(io::ErrorKind::ConnectionAborted, "stream was terminated unexpectedly"))?;

        if c.incoming.is_empty() {
            // TODO: block
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "no bytes to read"));
        }

        // TODO: detect FIN and return nread == 0

        let mut nread = 0;
        let (head, tail) = c.incoming.as_slices();
        let hread = std::cmp::min(buf.len(), head.len());
        buf.copy_from_slice(&head[..hread]);
        nread += hread;

        let tread = std::cmp::min(buf.len() - nread, tail.len());
        buf.copy_from_slice(&tail[..tread]);
        nread += tread;
        drop(c.incoming.drain(..nread));

        Ok(nread)
    }
}

impl Write for TcpStream { 
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut cm = self.h.manager.lock().unwrap();
        let c = cm.connections.get_mut(&self.quad).ok_or_else(|| io::Error::new(io::ErrorKind::ConnectionAborted, "stream was terminated unexpectedly"))?;

        if c.unacked.len() >= SENDQUEUE_SIZE {
            // TODO: block
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "too many bytes buffered"));
        }

        let nwrite = std::cmp::min(buf.len(), SENDQUEUE_SIZE - c.unacked.len());
        c.unacked.extend(buf[..nwrite].iter());

        // TODO: wake up writer

        Ok(nwrite)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut cm = self.h.manager.lock().unwrap();
        let c = cm.connections.get_mut(&self.quad).ok_or_else(|| io::Error::new(io::ErrorKind::ConnectionAborted, "stream was terminated unexpectedly"))?;

        if c.unacked.is_empty()  {
            // TODO: block
            return Ok(())
        } else {
            // TODO: block
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "outgoing not empty"))
        }
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        let mut cm = self.h.manager.lock().unwrap();
        // TODO: send FYN on cm.connections[quad]
        // TODO: _eventually_ remove self.quad from cm.connections
    }
}

impl TcpStream {
    pub fn shutdown(&self, how: std::net::Shutdown) -> io::Result<()> {
        // TODO: send FYN
        unimplemented!();
    }
}

pub struct TcpListener {
    port: u16, 
    h: InterfaceHandle
}

impl TcpListener {
    pub fn accept(&mut self) -> io::Result<TcpStream> {
        let mut cm = self.h.manager.lock().unwrap();

        loop {
            if let Some(quad) = cm.pending.get_mut(&self.port).expect("port closed while listener active").pop_front() {
                return Ok(TcpStream {
                    quad, 
                    h: self.h.clone()
                });
            } 
            
            cm = self.h.pending_var.wait(cm).unwrap();
                
        }

       
    }
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        let mut cm = self.h.manager.lock().unwrap();
        let pending = cm.pending.remove(&self.port).expect("Port closed");
        
        for _quad in pending {
            // TODO: terminate cm.connections[quad]
            unimplemented!();
        }
    }
}