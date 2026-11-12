//! Port 53: UDP and TCP on one address, with `hickory-server` doing the wire format.
//!
//! A domain controller has to answer a validator's questions about the protocol itself - compression,
//! truncation, EDNS, the shape of a response - and hand-writing RFC 1035 would be a second place to
//! be wrong about all of it. So the protocol comes from `hickory-proto` and the server loop from
//! `hickory-server`; what stays ours is the zone: `ZoneHandler` is implemented over whatever holds the
//! records, and [`InMemory`] is that implementation for a zone held in memory.
//!
//! The interface this file has to fit is the one the crate actually publishes, and it was read from
//! the source rather than from prose: `Catalog::upsert(LowerName, Vec<Arc<dyn ZoneHandler>>)`,
//! `Server::new(handler)`, `register_socket(UdpSocket)`, `register_listener(TcpListener, timeout,
//! buffer)`. The zone handler answers `lookup` (one name and type), `search` (whatever the query
//! asks), `nsec_records`/`nsec3_records` (proof of absence) and `update` (RFC 2136, not yet).
//!
//! Deliberately not here: the zone read out of the directory (RRL-2.25.2), the records a domain
//! needs (2.25.6), and dynamic updates with their signatures (2.25.7/2.25.8). This file is the
//! listener and the seam those land on.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hickory_server::proto::op::ResponseCode;
use hickory_server::proto::rr::{LowerName, Record, RecordSet, RecordType, TSigResponseContext};
use hickory_server::server::{Request, RequestInfo, Server};
use hickory_server::zone_handler::{
    AuthLookup, AxfrPolicy, Catalog, LookupControlFlow, LookupError, LookupOptions, LookupRecords,
    ZoneHandler, ZoneType,
};

/// How long a TCP connection may sit between requests before it is closed.
///
/// Five seconds is what `hickory`'s own examples use, and it is a defence against a connection that
/// is opened and never spoken to: TCP DNS is rare enough that a slow client is not a workload here.
const TCP_TIMEOUT: Duration = Duration::from_secs(5);

/// The buffer a TCP response is assembled in. 1232 is the EDNS0 payload every modern resolver
/// assumes, and a response larger than it is cut with TC instead of being written into a bigger one.
const TCP_BUFFER: usize = 1232;

/// A zone held in memory, which is what a zone looks like to this module.
///
/// The records carry their own owner names, so the lookup is a filter over them: a domain's zone is
/// tens of records and not millions, and a map keyed by `(name, type)` would be a second structure to
/// keep in step with this one for no measured gain.
#[derive(Debug, Default)]
pub struct InMemory {
    origin: Option<LowerName>,
    records: Vec<Record>,
}

impl InMemory {
    /// A zone at `origin`, holding `records`.
    ///
    /// Returns `None` when `origin` is not a name: a zone without an origin is one the catalog cannot
    /// place, and guessing would put its records under somebody else's domain.
    pub fn new(origin: &str, records: Vec<Record>) -> Option<Self> {
        let origin = LowerName::from(hickory_server::proto::rr::Name::from_ascii(origin).ok()?);
        Some(Self {
            origin: Some(origin),
            records,
        })
    }

    /// The records for `name` and `rtype`, with `ANY` meaning every type.
    fn matching(&self, name: &LowerName, rtype: RecordType) -> Vec<Record> {
        self.records
            .iter()
            .filter(|record| {
                LowerName::from(record.name.clone()) == *name
                    && (rtype == RecordType::ANY || record.record_type() == rtype)
            })
            .cloned()
            .collect()
    }

    /// Whether any record carries this name, whatever its type.
    ///
    /// The difference between "no such name" (NXDOMAIN) and "the name exists, not with that type"
    /// (NOERROR with an empty answer) is the one a client acts on: the first makes it stop asking.
    fn knows(&self, name: &LowerName) -> bool {
        self.records
            .iter()
            .any(|record| LowerName::from(record.name.clone()) == *name)
    }

    /// The answer to a lookup, in the shape the trait wants.
    ///
    /// The records are grouped into one `RecordSet` per type, because that is the unit `hickory`
    /// answers with: a set carries the TTL and the class of its records, and a list of loose records
    /// would make the server infer what the set already knows.
    fn answer(
        &self,
        name: &LowerName,
        rtype: RecordType,
        options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        let found = self.matching(name, rtype);
        if found.is_empty() {
            // A name this zone knows with other types is not NXDOMAIN: telling a client the name does
            // not exist would stop it asking for the type that does.
            return if self.knows(name) {
                LookupControlFlow::Continue(Err(LookupError::NameExists))
            } else {
                LookupControlFlow::Continue(Err(LookupError::ResponseCode(ResponseCode::NXDomain)))
            };
        }

        let mut sets: Vec<Arc<RecordSet>> = Vec::new();
        for record in found {
            match sets
                .iter_mut()
                .find(|set| set.record_type() == record.record_type())
            {
                Some(set) => {
                    Arc::make_mut(set).insert(record, 0);
                }
                None => {
                    let mut set = RecordSet::new(record.name.clone(), record.record_type(), 0);
                    set.set_dns_class(record.dns_class);
                    set.set_ttl(record.ttl);
                    set.insert(record, 0);
                    sets.push(Arc::new(set));
                }
            }
        }
        LookupControlFlow::Continue(Ok(AuthLookup::Records {
            answers: LookupRecords::many(options, sets),
            additionals: None,
        }))
    }
}

#[async_trait::async_trait]
impl ZoneHandler for InMemory {
    fn zone_type(&self) -> ZoneType {
        ZoneType::Primary
    }

    fn axfr_policy(&self) -> AxfrPolicy {
        // No zone transfer: the records live in a directory that replicates them by its own means,
        // and an AXFR would be a second, unreplicated copy of the same data.
        AxfrPolicy::Deny
    }

    fn origin(&self) -> &LowerName {
        // `new` refuses to build one without an origin, so this cannot be reached on a value that
        // came through it; the panic names the invariant instead of answering with `example.com`.
        self.origin
            .as_ref()
            .expect("a zone without an origin is not built")
    }

    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        _request_info: Option<&RequestInfo<'_>>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        self.answer(name, rtype, lookup_options)
    }

    async fn search(
        &self,
        request: &Request,
        lookup_options: LookupOptions,
    ) -> (LookupControlFlow<AuthLookup>, Option<TSigResponseContext>) {
        // `Request` derefs to its `MessageRequest`, which carries the queries it was parsed from.
        // A request with no query at all is a form the caller has already rejected; answering
        // `Skip` here hands it to the next zone instead of inventing a name.
        let Some(question) = request.queries.queries().first() else {
            return (LookupControlFlow::Skip, None);
        };
        let name = question.name().clone();
        let rtype = question.query_type();
        (self.answer(&name, rtype, lookup_options), None)
    }

    async fn nsec_records(
        &self,
        _name: &LowerName,
        _lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        // Unsigned zone: there is no proof of absence to hand out, and claiming one would be worse
        // than saying nothing.
        LookupControlFlow::Skip
    }
}

/// What a started listener is: where it took the port and the task serving it.
pub struct Running {
    pub bind: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl Running {
    /// Stops the listener and waits for the task to finish.
    pub async fn stop(self) {
        self.task.abort();
        let _ = self.task.await;
    }
}

/// Serves `catalog` on `bind`, over UDP and TCP at the same address.
///
/// One port for both is what the protocol requires and what a client expects: a resolver asks over
/// UDP and retries over TCP when the answer does not fit, and it does not ask on a different port.
/// So the UDP socket is bound to the TCP listener's address rather than to an address of its own.
///
/// A failure to bind either transport is an error here, not a listener that silently answers half the
/// questions: a zone reachable over UDP and not TCP is one whose large answers are truncated forever.
pub async fn listen(bind: SocketAddr, catalog: Catalog) -> Result<Running, String> {
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(|err| format!("dns {bind} tcp: {err}"))?;
    let addr = listener
        .local_addr()
        .map_err(|err| format!("dns {bind} tcp: {err}"))?;
    let socket = tokio::net::UdpSocket::bind(addr)
        .await
        .map_err(|err| format!("dns {addr} udp: {err}"))?;

    let mut server = Server::new(catalog);
    server.register_socket(socket);
    server.register_listener(listener, TCP_TIMEOUT, TCP_BUFFER);

    let task = tokio::spawn(async move {
        if let Err(err) = server.block_until_done().await {
            eprintln!("dns: {err}");
        }
    });
    Ok(Running { bind: addr, task })
}

/// A catalog holding one zone, which is what a domain is: one name, one set of records.
pub fn catalog_with(zone: Arc<InMemory>) -> Catalog {
    let mut catalog = Catalog::new();
    catalog.upsert(zone.origin().clone(), vec![zone]);
    catalog
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_server::proto::op::{Message, MessageType, OpCode, Query};
    use hickory_server::proto::rr::rdata::SRV;
    use hickory_server::proto::rr::{Name, RData};
    use std::net::Ipv4Addr;

    fn name(text: &str) -> Name {
        Name::from_ascii(text).expect("a name")
    }

    /// The zone a domain needs, as far as this test is concerned: an address and a service locator.
    fn zone() -> Arc<InMemory> {
        let origin = name("ad.example.com.");
        // `from_rdata` writes the IN class and the TTL asked for, which is every record a domain
        // serves: the class is a constant of the protocol here and not a per-record choice.
        let a = Record::from_rdata(
            name("samba.ad.example.com."),
            600,
            RData::A(Ipv4Addr::new(10, 0, 2, 2).into()),
        );
        let srv = Record::from_rdata(
            name("_ldap._tcp.ad.example.com."),
            600,
            RData::SRV(SRV::new(0, 100, 389, name("samba.ad.example.com."))),
        );
        Arc::new(InMemory::new(origin.to_string().as_str(), vec![a, srv]).expect("a zone"))
    }

    fn query(name: &str, rtype: RecordType, id: u16) -> Vec<u8> {
        let mut message = Message::new(id, MessageType::Query, OpCode::Query);
        message.add_query(Query::query(Name::from_ascii(name).expect("a name"), rtype));
        message.to_vec().expect("encoded")
    }

    async fn ask_udp(addr: SocketAddr, packet: &[u8]) -> Message {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("socket");
        socket.send_to(packet, addr).await.expect("sent");
        let mut buffer = vec![0u8; 4096];
        let read = tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut buffer))
            .await
            .expect("an answer in time")
            .expect("read");
        Message::from_vec(&buffer[..read]).expect("decoded")
    }

    async fn ask_tcp(addr: SocketAddr, packet: &[u8]) -> Message {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let length = u16::try_from(packet.len()).expect("a short query");
        stream
            .write_all(&length.to_be_bytes())
            .await
            .expect("length");
        stream.write_all(packet).await.expect("written");
        let mut length = [0u8; 2];
        stream.read_exact(&mut length).await.expect("length back");
        let mut body = vec![0u8; usize::from(u16::from_be_bytes(length))];
        stream.read_exact(&mut body).await.expect("body");
        Message::from_vec(&body).expect("decoded")
    }

    /// The acceptance of this task: one zone, one port, the same answer over both transports.
    ///
    /// A zone that answers on UDP and not TCP is one whose large answers are truncated forever, and
    /// the difference would only show up on a real validator; here it shows up in four assertions.
    #[tokio::test]
    async fn a_zone_answers_the_same_way_over_udp_and_tcp() {
        let running = listen(
            "127.0.0.1:0".parse().expect("an address"),
            catalog_with(zone()),
        )
        .await
        .expect("started");
        let addr = running.bind;

        for (question, rtype, expected) in [
            ("samba.ad.example.com.", RecordType::A, RecordType::A),
            (
                "_ldap._tcp.ad.example.com.",
                RecordType::SRV,
                RecordType::SRV,
            ),
        ] {
            let packet = query(question, rtype, 7);
            let over_udp = ask_udp(addr, &packet).await;
            let over_tcp = ask_tcp(addr, &packet).await;

            for (transport, answer) in [("udp", &over_udp), ("tcp", &over_tcp)] {
                assert_eq!(
                    answer.response_code,
                    ResponseCode::NoError,
                    "{question} over {transport}"
                );
                let answers = &answer.answers;
                assert_eq!(answers.len(), 1, "{question} over {transport}");
                assert_eq!(answers[0].record_type(), expected);
                assert_eq!(answers[0].name.to_string(), question);
            }
            assert_eq!(
                over_udp.answers[0].data, over_tcp.answers[0].data,
                "the same record over both transports"
            );
        }
        running.stop().await;
    }

    /// A name the zone does not hold is NXDOMAIN, and a type it does not hold is an empty answer:
    /// the two tell a client different things, and confusing them makes it stop asking.
    #[tokio::test]
    async fn an_absent_name_and_an_absent_type_answer_differently() {
        let running = listen(
            "127.0.0.1:0".parse().expect("an address"),
            catalog_with(zone()),
        )
        .await
        .expect("started");

        let absent = ask_udp(
            running.bind,
            &query("nobody.ad.example.com.", RecordType::A, 1),
        )
        .await;
        assert_eq!(absent.response_code, ResponseCode::NXDomain);

        let wrong_type = ask_udp(
            running.bind,
            &query("samba.ad.example.com.", RecordType::TXT, 2),
        )
        .await;
        assert_eq!(
            wrong_type.response_code,
            ResponseCode::NoError,
            "the name exists, so this is not NXDOMAIN"
        );
        assert!(wrong_type.answers.is_empty());
        running.stop().await;
    }
}
