use std::io;
use std::io::Write;
use std::cmp::Ordering;

enum State {
    //Closed,
    //Listen,
    SynRcvd,
    Estab,
    FinWait1,
    FinWait2,
    TimeWait,
}

impl State {
    fn is_synchronized(&self) -> bool {
        match *self {
            State::SynRcvd => false,
            State::Estab | State::FinWait1 | State::FinWait2 | State::TimeWait => true,
        }
    }
}

pub struct Connection {
    state: State,
    recv: RecvSequenceSpace,
    send: SendSequenceSpace,
    ip: etherparse::Ipv4Header,
    tcp: etherparse::TcpHeader,
}

/// State of Send Sequence Space (RFC 793 S3.2 F4)
///
/// ```
///         1         2          3          4
///     ----------|----------|----------|----------
///             SND.UNA    SND.NXT    SND.UNA
///                                   +SND.WND
///
/// 1 - old sequence numbers which have been acknowledged
/// 2 - sequence numbers of unacknowledged data
/// 3 - sequence numbers allowed for new data transmission
/// 4 - future sequence numbers which are not yet allowed
/// ```
#[derive(Default)]
struct SendSequenceSpace {
    /// send unacknowledged
    una: u32, 
    /// send next
    nxt: u32, 
    /// send window
    wnd: u16, 
    /// send urgent pointer
    up: bool,  
    /// SSeqNumber for last window update 
    wl1: u32,
    /// SAckNumber for last window update
    wl2: u32, 
    /// intial send sequence number
    iss: u32, 
}


/// State of Receive Sequence Space (RFC 793 S3.2 F5)
///
/// ```
///                        1          2          3
///                    ----------|----------|----------
///                           RCV.NXT    RCV.NXT
///                                     +RCV.WND
///
///         1 - old sequence numbers which have been acknowledged
///         2 - sequence numbers allowed for new reception
///         3 - future sequence numbers which are not yet allowed
/// ```
#[derive(Default)]
struct RecvSequenceSpace {
    /// receive next
    nxt: u32,
    /// receive window
    wnd: u16,
    /// receive urgent pointer
    up: bool,
    /// initial receive sequence number
    irs: u32,
}

impl Connection {
    pub fn accept<'a>(
        nic: &mut tun_tap::Iface, 
        iph: etherparse::Ipv4HeaderSlice<'a>, 
        tcph: etherparse::TcpHeaderSlice<'a>, 
        data: &'a [u8]) -> io::Result<Option<Self>> {

        let mut buf = [0u8; 1500];
            
            if !tcph.syn() {
                // only expecting SYN packet
                return Ok(None);
            }
            
            let iss = 0;
            let wnd = 1024;

            let mut c = Connection {
                state: State::SynRcvd,
                recv: RecvSequenceSpace {
                    irs: tcph.sequence_number(),
                    nxt: tcph.sequence_number() + 1,
                    wnd: tcph.window_size(),
                    up: false,
                },
                send: SendSequenceSpace {
                    iss,
                    una: iss,
                    nxt: iss,
                    wnd: wnd,
                    up: false,
                    wl1: 0,
                    wl2: 0
                }, 
                ip: etherparse::Ipv4Header::new(
                    0,
                    64, 
                    etherparse::IpTrafficClass::Tcp, 
                    iph.destination_addr().octets(), 
                    iph.source_addr().octets()),
                tcp: etherparse::TcpHeader::new(
                    tcph.destination_port(), 
                    tcph.source_port(), 
                    iss, 
                    wnd),
            };
            // keep track of sender info
            

            // decide on what to send
            

            // start establishing connection
            c.tcp.syn = true;
            c.tcp.ack = true;
            c.write(nic, &[])?;
            Ok(Some(c))
    }

    fn write(&mut self, nic: &mut tun_tap::Iface, payload: &[u8]) -> io::Result<usize> {
        let mut buf = [0u8; 1500];
        
        self.tcp.sequence_number = self.send.nxt;
        self.tcp.acknowledgment_number = self.recv.nxt;

        let size = std::cmp::min(buf.len(), self.tcp.header_len() as usize + self.ip.header_len() as usize + payload.len());

        self.ip.set_payload_len(size - self.ip.header_len()).expect("Could not set payload len");

        // the kernel computes checksum for us
        self.tcp.checksum = self.tcp.calc_checksum_ipv4(&self.ip, &[]).expect("Failed to compute checksum");

        // write out the headers
        let mut unwritten = &mut buf[..];
        self.ip.write(&mut unwritten).expect("Can't write ip header");
        self.tcp.write(&mut unwritten)?;
        let payload_bytes = unwritten.write(payload)?;
        let unwritten = unwritten.len();
        self.send.nxt = self.send.nxt.wrapping_add(payload_bytes as u32);

        if self.tcp.syn {
            self.send.nxt = self.send.nxt.wrapping_add(1);
            self.tcp.syn = false;
        }
        if self.tcp.fin {
            self.send.nxt = self.send.nxt.wrapping_add(1);
            self.tcp.fin = false;
        }

        nic.send(&buf[..buf.len() - unwritten])?;
        Ok(payload_bytes)
    }

    fn send_rst(&mut self, nic: &mut tun_tap::Iface) -> io::Result<()> {
        // TODO: Fix Sequence numbers here
        // TODO: hande synchronized reset
        self.tcp.rst = true;
        self.tcp.sequence_number = 0;
        self.tcp.acknowledgment_number = 0;
        self.write(nic, &[])?;
        Ok(())

    }

    pub fn on_packet<'a>(
        &mut self,
        nic: &mut tun_tap::Iface, 
        iph: etherparse::Ipv4HeaderSlice<'a>, 
        tcph: etherparse::TcpHeaderSlice<'a>, 
        data: &'a [u8]) -> io::Result<()> {
        // check sequence numbers are valid (RFC 793 S3.3)
        // valid segment check
        // Ok if it ACKs at least one byte
        let seqn = tcph.sequence_number();
        let mut slen = data.len() as u32;
        if tcph.fin() { slen += 1; }
        if tcph.syn() { slen += 1; }
        let wend = self.recv.nxt.wrapping_add(self.recv.wnd as u32);
        let okay = if slen == 0 {
            // 0-length segments has own rules for acceptance
            if self.recv.wnd == 0 {
                if seqn != self.recv.nxt {
                    false
                } else {
                    true
                }
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend) {
                    false
            } else {
                true
            }
        } else {
            if self.recv.wnd == 0 {
                false
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend) &&
                    !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn.wrapping_add(slen - 1), wend) {
            
                false
            } else {
                true
            }
        };

        if !okay {
            self.write(nic,&[])?;
            return Ok(());
        }

        self.recv.nxt = seqn.wrapping_add(slen);
        // TODO if not acceptable, send ACK

        if !tcph.ack() {
            return Ok(());
        }

        // acceptable ack check
        // SND.UNA < SEG.ACK =< SND.NXT --- WRAPPING
        let ackn = tcph.acknowledgment_number();

        if let State::SynRcvd = self.state {
            if is_between_wrapped(self.send.una.wrapping_sub(1) , ackn, self.send.nxt.wrapping_add(1)) {
                // must have ACKed our SYN, since we detected at least one ACKed byte and we just sent one packet (SYN)
                self.state = State::Estab;
            } else {
                // TODO: RST
            }
        }

        if let  State::Estab | State::FinWait1 | State::FinWait2 = self.state {
            
            if !is_between_wrapped(self.send.una , ackn, self.send.nxt.wrapping_add(1)) {
                return Ok(());
            }
            self.send.una = ackn;
            // TODO
            assert!(data.is_empty());

            if let State::Estab = self.state {
                // terminate connection FOR NOW TODO!
                // TODO needs to be stored in the restransmission queue
                self.tcp.fin = true;
                self.write(nic, &[])?;
                self.state = State::FinWait1;
            }          
        }

        if let State::FinWait1 = self.state {
            if self.send.una == self.send.iss + 2 {
                // our FIN has been ACKed
                self.state = State::FinWait2;
            }
        }

        if tcph.fin() {
            match self.state {
                State::FinWait2 => {
                    // we're done with connection
                    self.write(nic, &[])?;
                    self.state = State::TimeWait;
                }
                _ => unimplemented!()
            }
        }
        
        Ok(())
    }
}

fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
    match start.cmp(&x) {
        Ordering::Equal => return false,
        Ordering::Less => {
            // check violated iff end between start and x
            if end >= start && end <= x {
                return false;
            }
        },
        Ordering::Greater => {
            // check violated iff x is not between start and end
            if !(end > x && end < start) {
                return false;
            }
        }
    }
    true
}