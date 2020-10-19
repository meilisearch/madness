use super::super::append_u16;
use super::super::traits::AppendBytes;

#[derive(Debug)]
pub struct Record<'a>(pub &'a str);

impl<'a> Record<'a> {
    pub const TYPE: usize =  16;
}

impl AppendBytes for Record<'_> {
    fn append_bytes(&self, out: &mut Vec<u8>) {
        let idx = out.len();
        append_u16(out, 0);
        for c in self.0.bytes() {
            out.push(c);
        }
        let len = out[idx..].len() - 2;
        out[idx] = ((len >> 8) & 0xff) as u8;
        out[idx + 1] = (len & 0xff) as u8;
    }
}
