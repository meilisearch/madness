use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use super::rdata::a::Record as A;
use super::rdata::aaaa::Record as AAAA;
use super::rdata::ptr::Record as Ptr;
use super::rdata::srv::Record as Srv;
use super::rdata::txt::Record as Txt;
use super::traits::AppendBytes;
use super::{append_qname, append_u16, append_u32, duration_to_secs};
use dns_parser::Class;

#[derive(Debug)]
pub struct ResourceRecord<'a> {
    pub(crate) name: &'a str,
    pub(crate) ttl: Duration,
    pub(crate) class: Class,
    pub(crate) data: RData<'a>,
}

macro_rules! create_class_fn {
    ($class:ident) => {
        #[allow(non_snake_case)]
        /// Creates a `ResourceRecord` with a class of the same name, and a default ttl to 4500s.
        pub fn $class(name: &'a str, data: RData<'a>) -> Self {
            Self {
                class: Class::$class,
                name,
                data,
                ttl: Duration::from_secs(4500),
            }
        }
    };
}

impl<'a> ResourceRecord<'a> {
    pub fn new(name: &'a str, ttl: Duration, class: Class, data: RData<'a>) -> Self {
        Self {
            name,
            ttl,
            class,
            data,
        }
    }

    create_class_fn!(IN);
    create_class_fn!(CS);
    create_class_fn!(HS);
    create_class_fn!(CH);

    pub fn set_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }
}

fn append_data<T: AppendBytes>(out: &mut Vec<u8>, data: &T) {
    let idx = out.len();
    append_u16(out, 0);
    data.append_bytes(out);
    let len = out[idx..].len() - 2;
    out[idx] = ((len >> 8) & 0xff) as u8;
    out[idx + 1] = (len & 0xff) as u8;
}

impl<'a> AppendBytes for ResourceRecord<'a> {
    fn append_bytes(&self, out: &mut Vec<u8>) {
        append_qname(out, self.name.as_bytes());
        append_u16(out, self.data.code());
        append_u16(out, self.class as u16);
        let ttl_secs = duration_to_secs(self.ttl);
        append_u32(out, ttl_secs);
        append_data(out, &self.data);
    }
}

#[derive(Debug)]
pub enum RData<'a> {
    A(A),
    AAAA(AAAA),
    PTR(Ptr<'a>),
    SRV(Srv<'a>),
    TXT(Txt<'a>),
}

impl<'a> RData<'a> {
    pub fn ptr(ptr: &'a str) -> Self {
        Self::PTR(Ptr(ptr))
    }

    pub fn a(addr: Ipv4Addr) -> Self {
        Self::A(A(addr))
    }

    pub fn aaaa(addr: Ipv6Addr) -> Self {
        Self::AAAA(AAAA(addr))
    }

    pub fn srv(port: u16, priority: u16, weight: u16, target: &'a str) -> Self {
        Self::SRV(Srv {
            port,
            weight,
            priority,
            target,
        })
    }

    pub fn txt(txt: &'a [&'a str]) -> Self {
        Self::TXT(Txt(txt))
    }
}

impl AppendBytes for RData<'_> {
    fn append_bytes(&self, out: &mut Vec<u8>) {
        match self {
            RData::A(data) => data.append_bytes(out),
            RData::AAAA(data) => data.append_bytes(out),
            RData::PTR(data) => data.append_bytes(out),
            RData::SRV(data) => data.append_bytes(out),
            RData::TXT(data) => data.append_bytes(out),
        }
    }
}

impl RData<'_> {
    fn code(&self) -> u16 {
        match self {
            RData::A(_) => A::TYPE as u16,
            RData::AAAA(_) => AAAA::TYPE as u16,
            RData::PTR(_) => Ptr::TYPE as u16,
            RData::SRV(_) => Srv::TYPE as u16,
            RData::TXT(_) => Txt::TYPE as u16,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn build_resource_record() {
        let data = RData::A(A(Ipv4Addr::new(0, 0, 0, 0)));
        let record = ResourceRecord {
            name: "_service._tcp.local",
            ttl: Duration::from_secs(4500),
            class: Class::IN,
            data,
        };
        let mut buffer = Vec::new();
        record.append_bytes(&mut buffer);
    }
}
