use std::collections::HashSet;
use std::io;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::time::Duration;

use crate::dns;
use crate::error::Error;
use crate::META_QUERY_SERVICE;

use futures::future::Either;
use once_cell::sync::Lazy;
use tokio::sync::{mpsc, oneshot};
use tokio::time;
use super::dns::{QueryType, QueryClass};

static IPV4_MDNS_MULTICAST_ADDRESS: Lazy<SocketAddr> =
    Lazy::new(|| SocketAddr::from((Ipv4Addr::new(224, 0, 0, 251), 5353)));

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
    socket: tokio::net::UdpSocket,
    query_socket: tokio::net::UdpSocket,
    recv_buffer: [u8; 2048],
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

impl MdnsService {
    /// creates a new mdns Service to advertize and discover mmdns services. If `loopback` is
    /// enabled, you will receive the multicast packets.
    pub fn new(loopback: bool) -> Result<Self, Error> {
        let std_socket = {
            #[cfg(unix)]
            fn platform_specific(s: &net2::UdpBuilder) -> io::Result<()> {
                net2::unix::UnixUdpBuilderExt::reuse_port(s, true)?;
                Ok(())
            }
            #[cfg(not(unix))]
            fn platform_specific(_: &net2::UdpBuilder) -> io::Result<()> {
                Ok(())
            }
            let builder = net2::UdpBuilder::new_v4()?;
            builder.reuse_address(true)?;
            platform_specific(&builder)?;
            builder.bind(("0.0.0.0", 5353))?
        };

        let socket = tokio::net::UdpSocket::from_std(std_socket)?;
        // Given that we pass an IP address to bind, which does not need to be resolved, we can
        // use std::net::UdpSocket::bind, instead of its async counterpart from async-std.
        let query_socket = tokio::net::UdpSocket::from_std(std::net::UdpSocket::bind((
            Ipv4Addr::from([0u8, 0, 0, 0]),
            0u16,
        ))?)?;

        socket.set_multicast_loop_v4(loopback)?;
        socket.set_multicast_ttl_v4(255)?;
        // TODO: correct interfaces?
        socket.join_multicast_v4(From::from([224, 0, 0, 251]), Ipv4Addr::UNSPECIFIED)?;

        let (tx, rx) = mpsc::channel(100);

        Ok(MdnsService {
            socket,
            query_socket,
            recv_buffer: [0; 2048],
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
        let mut sender = self.discovery_scheduler_snd.clone();
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

    pub async fn next(&mut self) -> Packet {
        // Flush the query send buffer.
        loop {
            while !self.send_buffers.is_empty() {
                let to_send = self.send_buffers.remove(0);

                match self
                    .socket
                    .send_to(&to_send, *IPV4_MDNS_MULTICAST_ADDRESS)
                    .await
                {
                    Ok(bytes_written) => {
                        debug_assert_eq!(bytes_written, to_send.len());
                    }
                    Err(_) => {
                        // Errors are non-fatal because they can happen for example if we lose
                        // connection to the network.
                        self.send_buffers.clear();
                        break;
                    }
                }
            }

            while !self.query_send_buffers.is_empty() {
                let to_send = self.query_send_buffers.remove(0);

                match self
                    .query_socket
                    .send_to(&to_send, *IPV4_MDNS_MULTICAST_ADDRESS)
                    .await
                {
                    Ok(bytes_written) => {
                        debug_assert_eq!(bytes_written, to_send.len());
                    }
                    Err(_) => {
                        // Errors are non-fatal because they can happen for example if we lose
                        // connection to the network.
                        self.query_send_buffers.clear();
                        break;
                    }
                }
            }

            let selected_output = match futures::future::select(
                Box::pin(self.socket.recv_from(&mut self.recv_buffer)),
                Box::pin(self.discovery_scheduler_rcv.recv()),
            )
            .await
            {
                Either::Left((packets, _)) => Either::Left(packets),
                Either::Right((service, _)) => Either::Right(service),
            };

            match selected_output {
                Either::Left(left) => match left {
                    Ok((len, from)) => {
                        if let Ok(packet) = self.parse_mdns_packets(&self.recv_buffer[..len], from) {
                            return packet;
                        }
                    }
                    Err(_) => (), // non-fatal error
                },
                Either::Right(service_name) => {
                    if let Some(service_name) = service_name {
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
