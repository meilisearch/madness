use super::super::traits::AppendBytes;
use std::net::Ipv6Addr;

#[derive(Debug)]
pub struct Record(pub Ipv6Addr);

impl Record {
    pub const TYPE: usize = 28;
}

impl AppendBytes for Record {
    fn append_bytes(&self, out: &mut Vec<u8>) {
        for b in u128::to_be_bytes(self.0.into()).iter() {
            out.push(*b);
        }
    }
}
