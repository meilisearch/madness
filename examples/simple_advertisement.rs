use std::time::Duration;
use std::net::Ipv4Addr;

use madness::{Packet, MdnsService, META_QUERY_SERVICE};
use madness::dns::{PacketBuilder, ResourceRecord, Class, RData};

const SERVICE_NAME: &str = "_myservice._tcp.local";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut service = MdnsService::new(true)?;
    service.register(SERVICE_NAME);
    loop {
        let packet = service.next().await;
        match packet {
            Packet::Query(queries) => {
                for query in queries {
                    if query.is_meta_service_query() {
                        let mut packet = PacketBuilder::new();
                        packet.header_mut()
                            .set_id(rand::random())
                            .set_query(false);
                        packet.add_answer(ResourceRecord::new(
                                META_QUERY_SERVICE,
                                Duration::from_secs(4500),
                                Class::IN,
                                RData::ptr(SERVICE_NAME)));
                        let packet = packet.build();
                        service.enqueue_response(packet);
                    } else {
                        match query.name.as_str() {
                            SERVICE_NAME => {
                                let mut packet = PacketBuilder::new();
                                packet.header_mut()
                                    .set_id(rand::random())
                                    .set_query(false);
                                packet.add_answer(ResourceRecord::new(
                                        SERVICE_NAME,
                                        Duration::from_secs(4500),
                                        Class::IN,
                                        RData::ptr("marin._myservice._tcp.local")));
                                packet.add_answer(ResourceRecord::new(
                                        "marin._myservice._tcp.local",
                                        Duration::from_secs(4500),
                                        Class::IN,
                                        RData::srv(8594, 0, 0, "marin.local")));
                                packet.add_answer(ResourceRecord::new(
                                        "marin.local",
                                        Duration::from_secs(4500),
                                        Class::IN,
                                        RData::a(Ipv4Addr::new(0, 0, 0, 0))));
                                let packet = packet.build();
                                service.enqueue_response(packet);
                            }
                            _ => (),
                        }
                    }
                }
            }
            Packet::Response(_response) => {
                //println!("response: {:?}", response);
            }
        }
    }
}
