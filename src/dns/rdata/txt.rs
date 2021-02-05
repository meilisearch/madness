use super::super::traits::AppendBytes;

#[derive(Debug)]
pub struct Record<'a>(pub &'a [&'a str]);

impl<'a> Record<'a> {
    pub const TYPE: usize = 16;
}

impl AppendBytes for Record<'_> {
    fn append_bytes(&self, out: &mut Vec<u8>) {
        for s in self.0 {
            out.push(s.len() as u8);
            out.extend_from_slice(s.as_bytes());
        }
    }
}
