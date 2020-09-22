use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use crate::error::Error;

pub struct PTRRecord(pub(crate) String);
pub struct A(pub(crate) Ipv4Addr);
pub struct AAAA(pub(crate) Ipv6Addr);
pub struct TXT(pub(crate) Vec<String>);

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
}

pub enum QClass {
    IN = 0x1,
    CS = 0x2,
    CH = 0x3,
    HS = 0x4,
}

pub struct PacketBuilder {
    questions: Vec<Vec<u8>>,
    answers: Vec<Vec<u8>>,
}

impl PacketBuilder {
    pub fn new() -> Self {
        Self {
            questions: Vec::new(),
            answers: Vec::new(),
        }
    }

    pub fn add_question(&mut self, name: &str, qtype: RRType) -> &mut Self {
        let mut buffer = Vec::new();
        append_qname(&mut buffer, name.as_bytes());
        append_u16(&mut buffer, qtype as u16);
        append_u16(&mut buffer, QClass::IN as u16);
        self.questions.push(buffer);
        self
    }

    pub fn add_txt<'a>(
        &mut self,
        service_name: &str,
        txt: impl Iterator<Item = &'a str>,
        ttl: Duration,
    ) -> Result<&mut Self, Error> {
        let mut buffer = Vec::new();
        let ttl_secs = duration_to_secs(ttl);
        append_txt_record(&mut buffer, service_name, ttl_secs, txt)?;
        Ok(self)
    }

    /// adds a ptr answer to the Response
    pub fn add_ptr(&mut self, service_name: &str, ptr: &str, ttl: Duration) -> &mut Self {
        let mut buffer = Vec::new();
        append_qname(&mut buffer, service_name.as_bytes());
        append_u16(&mut buffer, RRType::PTR as u16);
        append_u16(&mut buffer, QClass::IN as u16 | 0x8000);
        let ttl_secs = duration_to_secs(ttl);
        append_u32(&mut buffer, ttl_secs);
        let mut buf = Vec::new();
        append_qname(&mut buf, ptr.as_bytes());
        append_u16(&mut buffer, buf.len() as u16);
        buffer.extend_from_slice(&buf);
        self.answers.push(buffer);
        self
    }

    pub fn build_answer(&self, id: u16) -> Vec<u8> {
        let mut out = Vec::new();

        // Program-generated transaction ID; unused by our implementation.
        append_u16(&mut out, id);
        // 0x0 flag for a regular query.
        append_u16(&mut out, 0x8400);

        // Number of questions.
        append_u16(&mut out, 0x0);

        // Number of answers, authorities, and additionals.
        append_u16(&mut out, self.answers.len() as u16);
        append_u16(&mut out, 0x0);
        append_u16(&mut out, 0x0);

        for question in &self.questions {
            out.extend_from_slice(&question);
        }

        for answer in &self.answers {
            out.extend_from_slice(&answer);
        }
        out
    }

    pub fn build_question(&self, id: u16) -> Vec<u8> {
        let mut out = Vec::new();

        // Program-generated transaction ID; unused by our implementation.
        append_u16(&mut out, id);
        // 0x0 flag for a regular query.
        append_u16(&mut out, 0x0);

        // Number of questions.
        append_u16(&mut out, self.questions.len() as u16);

        // Number of answers, authorities, and additionals.
        append_u16(&mut out, 0x0);
        append_u16(&mut out, 0x0);
        append_u16(&mut out, 0x0);

        for question in &self.questions {
            out.extend_from_slice(&question);
        }

        for answer in &self.answers {
            out.extend_from_slice(&answer);
        }
        out
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
