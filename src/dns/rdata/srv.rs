use super::super::{append_qname, append_u16};
use super::super::traits::AppendBytes;

#[derive(Debug)]
pub struct Record<'a> {
    pub port: u16,
    pub weight: u16,
    pub priority: u16,
    pub target: &'a str,
}

impl<'a> Record<'a> {
    pub const TYPE: usize =  33;
}

impl AppendBytes for Record<'_> {
    fn append_bytes(&self, out: &mut Vec<u8>) {
        append_u16(out, self.priority);
        append_u16(out, self.weight);
        append_u16(out, self.port);
        append_qname(out, self.target.as_bytes());
    }
}
