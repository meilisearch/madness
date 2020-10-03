use super::super::append_u32;
use std::net::Ipv4Addr;
use super::super::traits::AppendBytes;

#[derive(Debug)]
pub struct Record(pub Ipv4Addr);

impl Record {
    pub const TYPE: usize =  1;
}

impl AppendBytes for Record {
    fn append_bytes(&self, out: &mut Vec<u8>) {
        append_u32(out, self.0.into());
    }
}
