use std::net::Ipv4Addr;
use std::time::Duration;

use madness::{Packet, MdnsService, META_QUERY_SERVICE};
use madness::dns::{PacketBuilder, ResourceRecord, RData};

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
                        packet.add_answer(ResourceRecord::IN(
                                META_QUERY_SERVICE,
                                RData::ptr(SERVICE_NAME)));
                        let packet = packet.build();
                        service.enqueue_response(packet);
                    } else {
                        match query.name.as_str() {
                            SERVICE_NAME => {
                                let mut packet = PacketBuilder::new();
                                packet
                                    .add_answer(ResourceRecord::IN(
                                            SERVICE_NAME,
                                            RData::ptr("marin._myservice._tcp.local")))
                                    .add_answer(ResourceRecord::IN(
                                            "marin._myservice._tcp.local",
                                            RData::srv(8594, 0, 0, "marin.local")))
                                    .add_answer(ResourceRecord::IN(
                                            "marin.local",
                                            RData::a(Ipv4Addr::new(192,168,31,78)))
                                        .set_ttl(Duration::from_secs(1000)))
                                    .add_answer(ResourceRecord::IN(
                                            "marin._myservice._tcp.local",
                                            RData::txt("foobar")))
                                    .header_mut()
                                    .set_id(rand::random())
                                    .set_query(false);
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
