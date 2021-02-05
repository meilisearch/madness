use super::super::append_qname;
use super::super::traits::AppendBytes;

#[derive(Debug)]
pub struct Record<'a>(pub &'a str);

impl<'a> Record<'a> {
    pub const TYPE: usize = 12;
}

impl AppendBytes for Record<'_> {
    fn append_bytes(&self, out: &mut Vec<u8>) {
        append_qname(out, self.0.as_bytes());
    }
}
