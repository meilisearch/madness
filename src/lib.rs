pub mod dns;
pub mod error;
pub mod packet;
pub mod service;

const META_QUERY_SERVICE: &str = "_services._dns-sd._udp.local";
