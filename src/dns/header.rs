use super::append_u16;
use super::traits::AppendBytes;

#[derive(Default)]
pub struct PacketHeader {
    id: u16,
    flags: u16,
    pub(crate) qd_count: u16,
    pub(crate) an_count: u16,
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

    /// Set the `QR` bit. Specifies whether the message is a query (true) or a response (false).
    /// Defaults to true.
    pub fn set_query(&mut self, set: bool) -> &mut Self {
        self.flags = ((-(!set as i16) ^ self.flags as i16) & (1 << 15)) as u16;
        self
    }

    pub fn is_query(&self) -> bool {
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

    pub fn an_count(self) -> u16 {
        self.an_count
    }
    pub fn ns_count(self) -> u16 {
        self.ns_count
    }
    pub fn ar_count(self) -> u16 {
        self.ar_count
    }
}

impl AppendBytes for PacketHeader {
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
