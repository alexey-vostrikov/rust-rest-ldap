//! Port 88, both transports.
//!
//! The KDC engine answers octets: one request in, one reply out, no socket anywhere in the crate.
//! That is what makes it usable in a test without a network and here without a second process - and
//! it also means the framing is ours.
//!
//! # UDP is not optional
//!
//! A client sends its AS-REQ over UDP first. MIT's `kinit` does, Windows does, and Samba's own client
//! does; the TCP path exists for a reply too large for a datagram and for clients told to prefer it.
//! Serving only TCP produces the specific failure this whole exercise is meant to remove: a client
//! that reports "cannot contact any KDC" while `ss` shows the port listening.
//!
//! # Framing
//!
//! RFC 4120 §7.2.2: four octets of length, big endian, then the message. The length is the message,
//! not the frame, so a 4 is an empty request - which is refused by the decoder rather than by a
//! subtraction that could underflow.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use rust_kdc::kdc::Kdc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::watch;

/// The largest datagram a client could have sent us.
///
/// 65535 is the UDP limit, and the buffer is that size rather than a guess: a datagram truncated by
/// a short buffer is a decoder error the operator would read as a broken KDC.
const DATAGRAM: usize = 65_535;

/// The seconds since the epoch, which is the clock the engine takes.
///
/// Passed in rather than read inside the engine so that a test can place a request in time. A clock
/// before 1970 is not something to fail a request over: zero is a valid Kerberos time, and the
/// tickets it produces are simply already expired.
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

/// Answers datagrams until `shutdown` flips or the socket fails.
pub async fn serve_udp(socket: UdpSocket, kdc: Arc<Kdc>, mut shutdown: watch::Receiver<bool>) {
    let mut buffer = vec![0u8; DATAGRAM];
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                // A closed channel means every sender is gone: that is a shutdown that was never
                // announced, and looping on it would spin a core for ever.
                if changed.is_err() || *shutdown.borrow() {
                    return;
                }
            }
            received = socket.recv_from(&mut buffer) => {
                let (length, peer) = match received {
                    Ok(received) => received,
                    // One bad datagram is not a reason to stop answering: a client that sent
                    // garbage gets silence, as it would from any KDC on the network.
                    Err(err) => {
                        eprintln!("kerberos: recvfrom: {err}");
                        continue;
                    }
                };
                let reply = kdc.handle_from(&buffer[..length], now(), Some(peer.ip()));
                if let Err(err) = socket.send_to(&reply, peer).await {
                    eprintln!("kerberos: sendto {peer}: {err}");
                }
            }
        }
    }
}

/// Accepts connections until `shutdown` flips or the listener fails.
pub async fn serve_tcp(listener: TcpListener, kdc: Arc<Kdc>, mut shutdown: watch::Receiver<bool>) {
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                // A closed channel means every sender is gone: that is a shutdown that was never
                // announced, and looping on it would spin a core for ever.
                if changed.is_err() || *shutdown.borrow() {
                    return;
                }
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, peer)) => {
                        let kdc = Arc::clone(&kdc);
                        // A connection per task: one client holding a socket open all day must not
                        // stop the next one from being answered.
                        tokio::spawn(async move {
                            if let Err(err) = answer_connection(stream, &kdc).await {
                                eprintln!("kerberos: {peer}: {err}");
                            }
                        });
                    }
                    Err(err) => eprintln!("kerberos: accept: {err}"),
                }
            }
        }
    }
}

/// Answers every request on one connection, in order.
///
/// In order because a client may pipeline, and a reply out of order is a reply to the wrong request.
/// A connection stays open for as long as the client keeps it: MIT sends several requests down one.
async fn answer_connection(mut stream: TcpStream, kdc: &Kdc) -> std::io::Result<()> {
    loop {
        let mut length = [0u8; 4];
        match stream.read_exact(&mut length).await {
            Ok(_) => {}
            // The client closed its side. That is how a connection ends, not a fault.
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(err) => return Err(err),
        }
        let length = u32::from_be_bytes(length) as usize;
        if length == 0 || length > DATAGRAM {
            // Beyond a datagram's size nothing legitimate arrives, and allocating what the header
            // asks for is how a four-byte header becomes a memory exhaustion.
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("frame of {length} octets cannot be a Kerberos message"),
            ));
        }

        let mut request = vec![0u8; length];
        stream.read_exact(&mut request).await?;

        let reply = kdc.handle(&request, now());
        let mut framed = Vec::with_capacity(4 + reply.len());
        framed.extend_from_slice(&(reply.len() as u32).to_be_bytes());
        framed.extend_from_slice(&reply);
        stream.write_all(&framed).await?;
        stream.flush().await?;
    }
}

/// Everything a started KDC is: what it answers, where, and the tasks serving it.
#[derive(Debug)]
pub struct Running {
    /// The realm, upper-cased.
    pub realm: String,
    /// The address both transports took.
    pub bind: std::net::SocketAddr,
    /// UDP, TCP, and the task that keeps the realm's view of the directory current.
    pub tasks: Vec<tokio::task::JoinHandle<()>>,
}

/// Starts the KDC: provisions `krbtgt` if the realm has none, binds both transports, and serves.
///
/// One entry point rather than three, because the three are not independent: a realm without a
/// `krbtgt` answers every AS-REQ with an error, and a server that refused to start would say so
/// once instead of on every logon attempt.
pub async fn start(
    settings: &super::Settings,
    source: Arc<crate::reload::Source>,
    base_dn: String,
    master_key_file: Option<&std::path::Path>,
    keytab: Option<&std::path::Path>,
    shutdown: watch::Receiver<bool>,
) -> Result<Running, String> {
    use rust_kdc::crypto::OwnCipher;
    use rust_kdc::hdb::ldap::LdapHdb;
    use rust_kdc::kdc::KdcConfig;

    super::bootstrap::ensure_krbtgt(&source, &settings.realm, &base_dn, master_key_file).await?;

    // The realm learns its services before it answers anybody: a client that asks for a `cifs/`
    // ticket must find the principal the acceptors are already configured with. Said out loud
    // because a realm that quietly gained entries is a realm an operator will not recognise.
    if let Some(keytab) = keytab {
        for dn in
            super::bootstrap::ensure_keytab_principals(&source, &settings.realm, &base_dn, keytab)
                .await?
        {
            eprintln!("kerberos: provisioned {dn}");
        }
    }

    let view = Arc::new(super::realm::RealmView::new(
        settings.realm.clone(),
        base_dn.clone(),
        source.directory().await,
    ));
    let config = KdcConfig::new(&settings.realm)
        .map_err(|err| format!("realm '{}': {err}", settings.realm))?;
    let kdc = Arc::new(Kdc::new(
        config,
        Arc::new(LdapHdb::new(
            Arc::clone(&view) as Arc<dyn rust_kdc::hdb::ldap::Directory>
        )),
        Arc::new(OwnCipher),
    ));

    // Both transports on one port, and a failure to take either is a failure to start: a realm that
    // answers TCP and not UDP is a realm half the clients cannot reach, and they report it as a
    // network problem rather than as this.
    // TCP first, then UDP on the address it actually took: with a port of 0 the two binds would
    // otherwise land on different ports, and a realm whose transports disagree is a realm that
    // answers a client on one protocol and not the other.
    let tcp = TcpListener::bind(settings.bind)
        .await
        .map_err(|err| format!("kerberos tcp '{}': {err}", settings.bind))?;
    let bind = tcp
        .local_addr()
        .map_err(|err| format!("kerberos tcp '{}': {err}", settings.bind))?;
    let udp = UdpSocket::bind(bind)
        .await
        .map_err(|err| format!("kerberos udp '{bind}': {err}"))?;

    let mut tasks = vec![
        tokio::spawn(serve_udp(udp, Arc::clone(&kdc), shutdown.clone())),
        tokio::spawn(serve_tcp(tcp, Arc::clone(&kdc), shutdown.clone())),
        tokio::spawn(follow_directory(source, Arc::clone(&view), shutdown)),
    ];
    tasks.retain(|task| !task.is_finished());

    Ok(Running {
        realm: settings.realm.clone(),
        bind,
        tasks,
    })
}

/// Keeps the realm's view of the directory at the directory's current snapshot.
///
/// Driven by the write notices rather than by a timer, so that a password changed through LDAP is
/// the key the KDC checks on the very next request: a realm that lagged would keep accepting a key
/// its owner had just replaced, which is the one thing a password change is meant to stop. The tick
/// is the backstop for a change that arrived another way - a peer's replication, an import.
async fn follow_directory(
    source: Arc<crate::reload::Source>,
    view: Arc<super::realm::RealmView>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut notices = source.subscribe();
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                // A closed channel means every sender is gone: that is a shutdown that was never
                // announced, and looping on it would spin a core for ever.
                if changed.is_err() || *shutdown.borrow() {
                    return;
                }
            }
            _ = tick.tick() => view.refresh(source.directory().await),
            received = notices.recv() => {
                match received {
                    // A write, whoever made it. The snapshot behind `directory()` is the one the
                    // LDAP side serves from, so taking it is taking exactly what a client reads.
                    Ok(_) => view.refresh(source.directory().await),
                    // Lagged means the receiver fell behind and missed notices; the snapshot is
                    // still correct, so the next tick catches up. Closed means the source is gone.
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        view.refresh(source.directory().await)
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_clock_is_seconds_since_the_epoch() {
        // Pinned because the engine's time checks are in seconds: a millisecond value here would put
        // every request a thousand times too far in the future, and the skew check would refuse it.
        let value = now();
        assert!(value > 1_700_000_000, "{value} is not a plausible date");
        assert!(value < 4_000_000_000, "{value} is not seconds");
    }
}
