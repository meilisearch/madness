pub mod dns;
pub mod error;
pub mod service;

pub use service::{MdnsService, Packet};

pub const META_QUERY_SERVICE: &str = "_services._dns-sd._udp.local";
