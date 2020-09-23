use madness::service::MdnsService;
use madness::packet::MdnsPacket;
use madness::dns;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut service = MdnsService::new(true)?;
    service.register("_myservice._tcp.local");
    service.discover("_services._dns-sd._udp.local", Duration::from_secs(1));
    loop {
        let (mut svc, packets) = service.next().await;
        for packet in packets {
            match packet {
                MdnsPacket::Query(query) => {
                    match query.service_name.as_str() {
                        "_myservice._tcp.local" => {
                            let mut packet = dns::PacketBuilder::new();
                            packet.add_answer(dns::Answer::PTR { name: "_myservice._tcp.local", ptr: "6000._myservice._tcp.local", ttl: Duration::from_secs(2) });
                            let packet = packet.build();
                            svc.enqueue_response(packet);
                        }
                        _ => ()
                    }
                }
                MdnsPacket::ServiceDiscovery(_disc) => {
                    let mut packet = dns::PacketBuilder::new();
                    packet.add_answer(dns::Answer::PTR { name: "_services._dns-sd._udp.local", ptr: "_myservice._tcp.local", ttl: Duration::from_secs(2) });
                    let packet = packet.build();
                    svc.enqueue_response(packet);
                }
                MdnsPacket::Response(_resp) => {
                    println!("got a response: {:#?}", _resp);
                }
            }
        }
        service = svc;
    }
}
