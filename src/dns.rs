use std::fmt;
use std::net::Ipv4Addr;
use std::time::Duration;

#[derive(Debug, Copy, Clone)]
pub enum RRType {
    A = 0x1,
    NS = 0x2,
    MD = 0x3,
    MF = 0x4,
    CNAME = 0x5,
    SOA = 0x6,
    MB = 0x7,
    MG = 0x8,
    MR = 0x9,
    NULL = 0xA,
    WKS = 0xB,
    PTR = 0xC,
    HINFO = 0xD,
    MINFO = 0xE,
    MX = 0xF,
    TXT = 0x10,
    AAAA = 0x1c,
    SRV = 0x21,
}

#[derive(Debug, Copy, Clone)]
pub enum QClass {
    IN = 0x1,
    CS = 0x2,
    CH = 0x3,
    HS = 0x4,
}

pub enum Answer<'a> {
    PTR {
        name: &'a str,
        ptr: &'a str,
        ttl: Duration,
    },
    SRV {
        port: u16,
        priority: u16,
        weight: u16,
        target: &'a str,
        ttl: Duration,
        name: &'a str,
    },
    A {
        addr: Ipv4Addr,
        name: &'a str,
        ttl: Duration,
    },
    TXT {
        entries: &'a [&'a str],
        ttl: Duration,
        name: &'a str,
    },
}

impl<'a> Answer<'a> {
    fn append_bytes(self, out: &mut Vec<u8>) {
        match self {
            Self::PTR { name, ptr, ttl } => {
                append_qname(out, name.as_bytes());
                append_u16(out, RRType::PTR as u16);
                append_u16(out, QClass::IN as u16 | 0x8000);
                let ttl_secs = duration_to_secs(ttl);
                append_u32(out, ttl_secs);
                append_u16(out, ptr.as_bytes().len() as u16 + 2);
                append_qname(out, ptr.as_bytes());
            }
            Self::SRV {
                name,
                ttl,
                priority,
                target,
                weight,
                port,
            } => {
                append_qname(out, name.as_bytes());
                let ttl_secs = duration_to_secs(ttl);
                append_u16(out, RRType::SRV as u16);
                append_u16(out, QClass::IN as u16);
                append_u32(out, ttl_secs);
                append_u16(out, 2 + 2 + 2 + target.len() as u16 + 2);
                append_u16(out, priority);
                append_u16(out, weight);
                append_u16(out, port);
                append_qname(out, target.as_bytes());
            }
            Self::A { addr, name, ttl } => {
                append_qname(out, name.as_bytes());
                append_u16(out, RRType::A as u16);
                append_u16(out, QClass::IN as u16);
                let ttl_secs = duration_to_secs(ttl);
                append_u32(out, ttl_secs);
                append_u16(out, 4);
                append_u32(out, addr.into());
            }
            Self::TXT { name, ttl, entries } => {
                let ttl_secs = duration_to_secs(ttl);
                append_txt_record(out, name, ttl_secs, entries.iter().map(|e| *e)).unwrap();
            }
        }
    }

    fn bytes_size(&self) -> usize {
        match self {
            Answer::PTR { name, ptr, .. } => name.as_bytes().len() + ptr.as_bytes().len() + 14,
            Answer::SRV { target, name, .. } => name.as_bytes().len() +  target.as_bytes().len() + 20,
            Answer::A { name, .. } => name.as_bytes().len() + 16,
            Answer::TXT { entries, ttl, name } => name.as_bytes().len() + entries.iter().map(|e| e.as_bytes().len() + 3).sum::<usize>() + 12,
        }
    }
}

#[repr(C)]
#[derive(Default)]
pub struct PacketHeader {
    id: u16,
    flags: u16,
    qd_count: u16,
    an_count: u16,
    ns_count: u16,
    ar_count: u16,
}

impl PacketHeader {
    pub fn set_id(&mut self, id: u16) -> &mut Self {
        self.id = id;
        self
    }

    pub fn id(&self) -> u16 {
        self.id
    }

    pub fn set_qr(&mut self, set: bool) -> &mut Self {
        self.flags = ((-(set as i16) ^ self.flags as i16) & (1 << 15)) as u16;
        self
    }

    pub fn qr(&self) -> bool {
        self.flags & 1 << 15 != 0
    }

    pub fn set_opcode(&mut self, code: OpCode) -> &mut Self {
        // clear previous value
        self.flags &= 0x87ff;
        // set new value
        self.flags |= (code as u16) << 11;
        self
    }

    pub fn set_aa(&mut self, set: bool) -> &mut Self {
        self.flags = ((-(set as i16) ^ self.flags as i16) & (1 << 10)) as u16;
        self
    }

    pub fn aa(&self) -> bool {
        self.flags & 1 << 10 != 0
    }

    pub fn set_tc(&mut self, set: bool) -> &mut Self {
        self.flags = ((-(set as i16) ^ self.flags as i16) & (1 << 9)) as u16;
        self
    }

    pub fn tc(&self) -> bool {
        self.flags & 1 << 9 != 0
    }

    pub fn set_rd(&mut self, set: bool) -> &mut Self {
        self.flags = ((-(set as i16) ^ self.flags as i16) & (1 << 8)) as u16;
        self
    }

    pub fn rd(&self) -> bool {
        self.flags & 1 << 8 != 0
    }

    pub fn set_ra(&mut self, set: bool) -> &mut Self {
        self.flags = ((-(set as i16) ^ self.flags as i16) & (1 << 7)) as u16;
        self
    }

    pub fn ra(&self) -> bool {
        self.flags & 1 << 7 != 0
    }

    pub fn set_rcode(&mut self, code: RCode) -> &mut Self {
        // clear previous value
        self.flags &= 0xfff8;
        // set new value
        self.flags |= code as u16;
        self
    }

    pub fn set_an_count(&mut self, count: u16) -> &mut Self {
        self.an_count = count;
        self
    }
    pub fn set_ns_count(&mut self, count: u16) -> &mut Self {
        self.ns_count = count;
        self
    }
    pub fn set_ar_count(&mut self, count: u16) -> &mut Self {
        self.ar_count = count;
        self
    }
    pub fn an_count(self) -> u16 {
        self.an_count
    }
    pub fn ns_count(self) -> u16 {
        self.ns_count
    }
    pub fn ar_count(self) -> u16 {
        self.ar_count
    }

    pub fn byte_size(&self) -> usize {
        12
    }

    fn append_bytes(&self, out: &mut Vec<u8>) {
        append_u16(out, self.id);
        append_u16(out, self.flags);
        append_u16(out, self.qd_count);
        append_u16(out, self.an_count);
        append_u16(out, self.ns_count);
        append_u16(out, self.ar_count);
    }
}

pub enum OpCode {
    QUERY = 0x0,
    IQUERY = 0x2,
    STATUS = 0x3,
}

pub enum RCode {
    NoError = 0,
    FormatError = 1,
    ServerFailure = 2,
    NameError = 3,
    NotImplemmented = 4,
    Refused = 5,
}

pub struct Question<'a> {
    pub name: &'a str,
    pub qtype: RRType,
    pub qclass: QClass,
}

impl<'a> Question<'a> {
    fn append_bytes(&self, out: &mut Vec<u8>) {
        append_qname(out, self.name.as_bytes());
        append_u16(out, self.qtype as u16);
        append_u16(out, self.qclass as u16);
    }

    fn byte_size(&self) -> usize {
        2 + 2 + self.name.as_bytes().len() + 2
    }
}

pub struct PacketBuilder<'a> {
    header: PacketHeader,
    questions: Vec<Question<'a>>,
    answers: Vec<Answer<'a>>,
}

// Builder for mDNS packets
impl<'a> PacketBuilder<'a> {
    /// Creates a new instance of a packet builder.
    pub fn new() -> Self {
        Self {
            header: PacketHeader::default(),
            questions: Vec::new(),
            answers: Vec::new(),
        }
    }

    /// Returns a reference to the header of the packet.
    pub fn header(&self) -> &PacketHeader {
        &self.header
    }

    /// Returns a mutable reference to the header of the packet.
    pub fn header_mut(&mut self) -> &mut PacketHeader {
        &mut self.header
    }

    /// Add a question to the packet
    pub fn add_question(&mut self, question: Question<'a>) -> &mut Self {
        self.questions.push(question);
        self
    }

    /// Adds an answer to the packet
    pub fn add_answer(&mut self, answer: Answer<'a>) -> &mut Self {
        self.answers.push(answer);
        self
    }

    /// Builds the packet and returns the bytes for that packet.
    pub fn build(self) -> Vec<u8> {
        todo!();
    }

}

fn append_u16(out: &mut Vec<u8>, value: u16) {
    out.push(((value >> 8) & 0xff) as u8);
    out.push((value & 0xff) as u8);
}

fn append_u32(out: &mut Vec<u8>, value: u32) {
    out.push(((value >> 24) & 0xff) as u8);
    out.push(((value >> 16) & 0xff) as u8);
    out.push(((value >> 8) & 0xff) as u8);
    out.push((value & 0xff) as u8);
}

fn append_qname(out: &mut Vec<u8>, name: &[u8]) {
    debug_assert!(name.is_ascii());

    for element in name.split(|&c| c == b'.') {
        assert!(element.len() < 64, "Service name has a label too long");
        assert_ne!(element.len(), 0, "Service name contains zero length label");
        out.push(element.len() as u8);
        for chr in element.iter() {
            out.push(*chr);
        }
    }

    out.push(0);
}

/// Appends a TXT record to the answer in `out`.
fn append_txt_record<'a>(
    out: &mut Vec<u8>,
    service_name: &str,
    ttl_secs: u32,
    entries: impl IntoIterator<Item = &'a str>,
) -> Result<(), MdnsResponseError> {
    // The name.
    append_qname(out, service_name.as_bytes());

    // Flags.
    out.push(0x00);
    out.push(0x10); // TXT record.
    out.push(0x80);
    out.push(0x01);

    // TTL for the answer
    append_u32(out, ttl_secs);

    // Add the strings.
    let mut buffer = Vec::new();
    for entry in entries {
        if entry.len() > u8::max_value() as usize {
            return Err(MdnsResponseError::TxtRecordTooLong);
        }
        buffer.push(entry.len() as u8);
        append_qname(&mut buffer, entry.as_bytes());
    }

    // It is illegal to have an empty TXT record, but we can have one zero-bytes entry, which does
    // the same.
    if buffer.is_empty() {
        buffer.push(0);
    }

    if buffer.len() > u16::max_value() as usize {
        return Err(MdnsResponseError::TxtRecordTooLong);
    }
    append_u16(out, buffer.len() as u16);
    out.extend_from_slice(&buffer);
    Ok(())
}

fn duration_to_secs(duration: Duration) -> u32 {
    let secs = duration
        .as_secs()
        .saturating_add(if duration.subsec_nanos() > 0 { 1 } else { 0 });
    std::cmp::min(secs, From::from(u32::max_value())) as u32
}

/// Error that can happen when producing a DNS response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MdnsResponseError {
    TxtRecordTooLong,
    NonAsciiMultiaddr,
    ResponseTooLong,
}

impl fmt::Display for MdnsResponseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MdnsResponseError::TxtRecordTooLong => {
                write!(f, "TXT record invalid because it is too long")
            }
            MdnsResponseError::NonAsciiMultiaddr => write!(
                f,
                "A multiaddr contains non-ASCII characters when serializd"
            ),
            MdnsResponseError::ResponseTooLong => write!(f, "DNS response is too long"),
        }
    }
}

impl std::error::Error for MdnsResponseError {}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_size_answer() {
        let mut out = Vec::new();
        let answer = Answer::A { name: "_service._tcp.local", addr: [192, 168, 0, 1].into(), ttl: Duration::from_secs(4500) };
        let size = answer.bytes_size();
        answer.append_bytes(&mut out);
        assert_eq!(size, out.len());
        out.clear();

        let answer = Answer::SRV { ttl: Duration::from_secs(4500), port: 42, priority: 0, weight: 0, name: "_service._tcp.local", target: "march.local" };
        let size = answer.bytes_size();
        answer.append_bytes(&mut out);
        assert_eq!(size, out.len());
        out.clear();

        let answer = Answer::PTR { ttl: Duration::from_secs(4500), name: "_service._tcp.local", ptr: "march.local" };
        let size = answer.bytes_size();
        answer.append_bytes(&mut out);
        assert_eq!(size, out.len());
        out.clear();

        let answer = Answer::TXT { ttl: Duration::from_secs(4500), name: "_service._tcp.local", entries: &["foo", "bar"] };
        let size = answer.bytes_size();
        answer.append_bytes(&mut out);
        assert_eq!(size, out.len());
        out.clear();
    }
}
