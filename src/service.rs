use std::collections::HashSet;
use std::io;
use std::net::SocketAddr;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::time::Duration;

use crate::dns;
use crate::error::Error;
use crate::META_QUERY_SERVICE;

use once_cell::sync::Lazy;
use tokio::sync::{mpsc, oneshot};
use tokio::time;
use super::dns::{QueryType, QueryClass};

static IPV4_MDNS_MULTICAST_ADDRESS: Lazy<SocketAddr> =
    Lazy::new(|| SocketAddr::from((Ipv4Addr::new(224, 0, 0, 251), 5353)));
static IPV6_MDNS_MULTICAST_ADDRESS: Lazy<SocketAddr> =
    Lazy::new(|| SocketAddr::from((Ipv6Addr::from_str("FF02::FB").unwrap(), 5353)));

#[derive(Debug)]
pub struct Query {
    pub name: String,
    pub prefer_unicast: bool,
    pub qtype: QueryType,
    pub qclass: QueryClass,
    pub from: SocketAddr,
    pub id: u16,
}

impl Query {
    pub fn is_meta_service_query(&self) -> bool {
        self.name == META_QUERY_SERVICE
    }
}

#[derive(Debug)]
pub enum Packet {
    Query(Vec<Query>),
    Response(mdns::Response),
}

pub struct MdnsService {
    socket_v4: tokio::net::UdpSocket,
    socket_v6: tokio::net::UdpSocket,
    query_socket: tokio::net::UdpSocket,
    recv_buffer_v4: [u8; 2048],
    recv_buffer_v6: [u8; 2048],
    /// Buffers pending to send on the main socket.
    send_buffers: Vec<Vec<u8>>,
    /// Buffers pending to send on the query socket.
    query_send_buffers: Vec<Vec<u8>>,
    advertized_sevices: HashSet<String>,
    discovery_scheduler_snd: mpsc::Sender<String>,
    discovery_scheduler_rcv: mpsc::Receiver<String>,
}

pub struct ServiceDiscovery(oneshot::Sender<()>, String);

impl ServiceDiscovery {
    pub fn name(&self) -> &str {
        &self.1
    }
}

macro_rules! send_packets {
    ($self:ident, $socket:ident, $addr:expr, $to_send:ident) => {
        match $self
            .$socket
            .send_to(&$to_send, $addr)
            .await
            {
                Ok(bytes_written) => {
                    debug_assert_eq!(bytes_written, $to_send.len());
                }
                Err(_) => {
                    // Errors are non-fatal because they can happen for example if we lose
                    // connection to the network.
                    $self.send_buffers.clear();
                    break;
                }
            }
    };
}

impl MdnsService {
    /// creates a new mdns Service to advertize and discover mdns services. If `loopback` is
    /// enabled, you will receive the multicast packets.
    pub fn new(loopback: bool) -> Result<Self, Error> {
        #[cfg(unix)]
        fn platform_specific(s: &net2::UdpBuilder) -> io::Result<()> {
            net2::unix::UnixUdpBuilderExt::reuse_port(s, true)?;
            Ok(())
        }
        #[cfg(not(unix))]
        fn platform_specific(_: &net2::UdpBuilder) -> io::Result<()> {
            Ok(())
        }
        
        // setup ipv4 socket
        let std_socket_v4 = {
            let builder = net2::UdpBuilder::new_v4()?;
            builder.reuse_address(true)?;
            platform_specific(&builder)?;
            builder.bind(("0.0.0.0", 5353))?
        };

        let socket_v4 = tokio::net::UdpSocket::from_std(std_socket_v4)?;
        socket_v4.set_multicast_loop_v4(loopback)?;
        socket_v4.set_multicast_ttl_v4(255)?;
        socket_v4.join_multicast_v4(From::from([224, 0, 0, 251]), Ipv4Addr::UNSPECIFIED)?;

        // setup ipv6 socket
        let std_socket_v6 = {
            let builder = net2::UdpBuilder::new_v6()?;
            builder.reuse_address(true)?;
            platform_specific(&builder)?;
            builder.bind(("::", 5353))?
        };

        let socket_v6 = tokio::net::UdpSocket::from_std(std_socket_v6)?;
        socket_v6.set_multicast_loop_v6(loopback)?;
        socket_v6.join_multicast_v6(&FromStr::from_str("FF02::FB").unwrap(), 0)?;

        let query_socket = tokio::net::UdpSocket::from_std(std::net::UdpSocket::bind(&[
                SocketAddr::from((Ipv4Addr::from([0u8, 0, 0, 0]), 0u16)),
                SocketAddr::from((Ipv6Addr::from_str("::").unwrap(), 0u16))
        ][..])?)?;

        let (tx, rx) = mpsc::channel(100);

        Ok(MdnsService {
            socket_v4,
            socket_v6,
            query_socket,
            recv_buffer_v4: [0; 2048],
            recv_buffer_v6: [0; 2048],
            send_buffers: Vec::new(),
            query_send_buffers: Vec::new(),
            advertized_sevices: HashSet::new(),
            discovery_scheduler_snd: tx,
            discovery_scheduler_rcv: rx,
        })
    }

    /// register a service to advertize
    pub fn register(&mut self, svc: &str) {
        self.advertized_sevices.insert(svc.to_string());
    }

    /// unregister an advertized service. If the service doesn't exists, this is no-op.
    pub fn unregister(&mut self, svc: &str) {
        self.advertized_sevices.remove(svc);
    }

    /// Adds a service to discover by the mdns server instance. When `ServiceDiscovery` is dropped, the service
    /// is not discovered anymore
    pub fn discover(
        &mut self,
        service_name: impl AsRef<str>,
        interval: Duration,
    ) -> ServiceDiscovery {
        let (otx, mut orx) = oneshot::channel();
        let mut interval = time::interval(interval);
        let sender = self.discovery_scheduler_snd.clone();
        let service = service_name.as_ref().to_string();
        tokio::spawn(async move {
            loop {
                let _ = interval.tick().await;
                // stop service dicovery when the sender is dropped
                match orx.try_recv() {
                    Err(oneshot::error::TryRecvError::Closed) => break,
                    _ => {
                        let _ = sender.send(service.clone()).await;
                    }
                }
            }
        });
        ServiceDiscovery(otx, service_name.as_ref().to_string())
    }

    pub fn enqueue_response(&mut self, rsp: Vec<u8>) {
        self.send_buffers.push(rsp);
    }

    async fn send_buffers(&mut self) {
        // Flush the query send buffer.
        while !self.send_buffers.is_empty() {
            let to_send = self.send_buffers.remove(0);
            send_packets!(self, socket_v4, *IPV4_MDNS_MULTICAST_ADDRESS, to_send);
            send_packets!(self, socket_v6, *IPV6_MDNS_MULTICAST_ADDRESS, to_send);
        }

        while !self.query_send_buffers.is_empty() {
            let to_send = self.query_send_buffers.remove(0);
            send_packets!(self, query_socket, &[*IPV4_MDNS_MULTICAST_ADDRESS, *IPV6_MDNS_MULTICAST_ADDRESS][..], to_send);
        }
    }

    pub async fn next(&mut self) -> Packet {
        loop{
            self.send_buffers().await;

            tokio::select! {
                Ok((len, from)) = self.socket_v4.recv_from(&mut self.recv_buffer_v4) => {
                    if let Ok(packet) = self.parse_mdns_packets(&self.recv_buffer_v4[..len], from) {
                        return packet;
                    }
                },
                Ok((len, from)) = self.socket_v6.recv_from(&mut self.recv_buffer_v6) => {
                    if let Ok(packet) = self.parse_mdns_packets(&self.recv_buffer_v6[..len], from) {
                        return packet;
                    }
                },
                Some(service_name) = self.discovery_scheduler_rcv.recv() => {
                    let mut query = dns::PacketBuilder::new();
                    query.add_question(
                        true,
                        &service_name,
                        dns::QueryClass::IN,
                        dns::QueryType::PTR,
                    );
                    let query = query.build();
                    self.query_send_buffers.push(query);
                }
            }
        }
    }

    fn parse_mdns_packets(&self, buf: &[u8], from: SocketAddr) -> Result<Packet, Error> {
        let packet = dns_parser::Packet::parse(buf)?;
        if packet.header.query {
            let queries = packet
                .questions
                .iter()
                .filter_map(|q| {
                    let name = q.qname.to_string();
                    if self.advertized_sevices.contains(&name) || name == META_QUERY_SERVICE {
                        Some(Query {
                            name,
                            from,
                            id: packet.header.id,
                            qclass: q.qclass,
                            qtype: q.qtype,
                            prefer_unicast: q.prefer_unicast,
                        })
                    } else {
                        None
                    }
                })
            .collect::<Vec<_>>();
            Ok(Packet::Query(queries))
        } else {
            Ok(Packet::Response(mdns::Response::from_packet(&packet)))
        }
    }
}
