use tokio_mdns::service::MdnsService;
use tokio_mdns::packet::MdnsPacket;
use tokio_mdns::dns::PacketBuilder;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut service = MdnsService::new(true)?;
    service.register("_myservice._tcp.local");
    loop {
        let (mut svc, packets) = service.next().await;
        for packet in packets {
            match packet {
                MdnsPacket::Query(query) => {
                    match query.service_name.as_str() {
                        "_myservice._tcp.local" => {
                            let mut packet = PacketBuilder::new();
                            packet.add_ptr("_myservice._tcp.local", "6000._myservice._tcp.local", Duration::from_secs(2));
                            let packet = packet.build_answer(rand::random());
                            svc.enqueue_response(packet);
                        }
                        _ => ()
                    }
                }
                MdnsPacket::ServiceDiscovery(_disc) => {
                    let mut packet = PacketBuilder::new();
                    packet.add_ptr("_services._dns-sd._udp.local", "_myservice._tcp.local", Duration::from_secs(20));
                    let packet = packet.build_answer(rand::random());
                    svc.enqueue_response(packet);
                }
                MdnsPacket::Response(_resp) => {
                    //println!("got a response: {:#?}", _resp);
                }
            }
        }
        service = svc;
    }
}
