use super::header::PacketHeader;
use super::{append_qname, append_u16};
use super::traits::AppendBytes;
use super::ResourceRecord;
pub use dns_parser::{QueryType, QueryClass};

struct Question<'a> {
    pub name: &'a str,
    pub prefer_unicast: bool,
    pub qtype: QueryType,
    pub qclass: QueryClass,
}

impl AppendBytes for Question<'_> {
    fn append_bytes(&self, out: &mut Vec<u8>) {
        append_qname(out, self.name.as_bytes());
        append_u16(out, self.qtype as u16);
        append_u16(out, self.qclass as u16);
    }
}

pub struct PacketBuilder<'a> {
    header: PacketHeader,
    questions: Vec<Question<'a>>,
    answers: Vec<ResourceRecord<'a>>,
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
    pub fn add_question(&mut self, prefer_unicast: bool, name: &'a str, qclass: QueryClass, qtype: QueryType) -> &mut Self {
        self.questions.push(Question { name, prefer_unicast, qtype, qclass});
        self.header.qd_count += 1;
        self
    }

    /// Adds an answer to the packet
    pub fn add_answer(&mut self, answer: ResourceRecord<'a>) -> &mut Self {
        self.answers.push(answer);
        self.header.an_count += 1;
        self
    }

    /// Builds the packet and returns the bytes for that packet.
    pub fn build(self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(4096);
        self.header.append_bytes(&mut buffer);
        self.questions.iter().for_each(|q| q.append_bytes(&mut buffer));
        self.answers.iter().for_each(|q| q.append_bytes(&mut buffer));
        buffer
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use dns_parser::Class;
    use std::time::Duration;
    use std::net::Ipv4Addr;
    use super::super::rdata::a::Record as A;
    use super::super::rdata::txt::Record as Txt;
    use dns_parser::Packet;

    #[test]
    fn build_packet() {
        let answer1 = ResourceRecord {
            name: "_service._tcp.local",
            ttl: Duration::from_secs(4500),
            class: Class::IN,
            data: crate::dns::RData::A(A(Ipv4Addr::new(0, 0, 0, 0))),
        };
        let answer2 = ResourceRecord {
            name: "_service._tcp.local",
            ttl: Duration::from_secs(4500),
            class: Class::IN,
            data: crate::dns::RData::TXT(Txt("foobar")),
        };

        let mut packet = PacketBuilder::new();

        packet.header_mut().set_id(12);
        packet
            .add_answer(answer1)
            .add_answer(answer2);
        let packet = packet.build();
        let parsed = Packet::parse(&packet).unwrap();
        let packet = mdns::Response::from_packet(&parsed);
        println!("{:#?}", packet);
    }
}
