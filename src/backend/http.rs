//! The HTTP client the REST backend talks to its service through.
//!
//! Written on `hyper` and `tokio-rustls` rather than pulled from a framework client: both are
//! already in the build (axum serves on hyper, the LDAP client speaks TLS on rustls), and a
//! client of our own keeps the "no C dependencies" rule visible instead of hiding it behind a
//! feature list. What it does not do is worth naming: no redirects, no compression, no cookies,
//! no HTTP/2. The REST backend talks to one service the operator configured, and following a
//! redirect to an unexpected host with an `Authorization` header attached is a way to hand a
//! token to whoever answers.

use std::sync::Arc;

use http_body_util::BodyExt;
use hyper::body::Bytes;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::client::Trust;

/// How much of a response body is kept.
///
/// A directory service that answers a list of users can legitimately send megabytes; a service
/// that answers an endless stream must not be able to fill this process's memory before the
/// timeout. Eight megabytes is far above a realistic directory and far below a problem.
pub const MAX_BODY: usize = 8 * 1024 * 1024;

/// A parsed `http://` or `https://` address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    /// True for `https://`.
    pub secure: bool,
    pub host: String,
    pub port: u16,
    /// The path the service lives under, without a trailing slash: `""` or `/api`.
    pub prefix: String,
}

impl Endpoint {
    /// Parses a base URL.
    ///
    /// Only what a configuration file plausibly contains: a scheme, a host, an optional port,
    /// and a path prefix. Credentials in the URL are refused rather than ignored - a token in
    /// the address would end up in the log line that prints where the backend points.
    pub fn parse(url: &str) -> Result<Self, Error> {
        let (secure, rest) = match url.split_once("://") {
            Some(("http", rest)) => (false, rest),
            Some(("https", rest)) => (true, rest),
            Some((scheme, _)) => {
                return Err(Error::Url {
                    url: url.to_string(),
                    reason: format!("unknown scheme '{scheme}': expected http or https"),
                });
            }
            None => {
                return Err(Error::Url {
                    url: url.to_string(),
                    reason: "no scheme: write it as http://host:port or https://host".to_string(),
                });
            }
        };

        if rest.contains('@') {
            return Err(Error::Url {
                url: url.to_string(),
                reason: "the address carries credentials; use auth_token instead".to_string(),
            });
        }

        let (authority, path) = match rest.split_once('/') {
            Some((authority, path)) => (authority, format!("/{path}")),
            None => (rest, String::new()),
        };

        if authority.is_empty() {
            return Err(Error::Url {
                url: url.to_string(),
                reason: "no host".to_string(),
            });
        }

        // An IPv6 literal wears brackets in the authority and not in the host: keeping them
        // here would put them back twice when the request is written, `[[::1]]:8000`.
        let bare = authority
            .strip_prefix('[')
            .and_then(|rest| rest.split_once(']'))
            .map(|(host, tail)| (host.to_string(), tail.strip_prefix(':')));

        let (host, port) = match bare {
            Some((host, Some(port))) => {
                let port = port.parse::<u16>().map_err(|_| Error::Url {
                    url: url.to_string(),
                    reason: format!("'{port}' is not a port number"),
                })?;
                (host, port)
            }
            Some((host, None)) => (host, if secure { 443 } else { 80 }),
            None => match authority.rsplit_once(':') {
                Some((host, port)) => {
                    let port = port.parse::<u16>().map_err(|_| Error::Url {
                        url: url.to_string(),
                        reason: format!("'{port}' is not a port number"),
                    })?;
                    (host.to_string(), port)
                }
                None => (authority.to_string(), if secure { 443 } else { 80 }),
            },
        };

        if host.is_empty() {
            return Err(Error::Url {
                url: url.to_string(),
                reason: "no host".to_string(),
            });
        }

        Ok(Self {
            secure,
            host,
            port,
            // The prefix keeps its slashes inside and loses the one at the end, so joining a
            // path never produces `//` and the service never sees a doubled separator.
            prefix: path.trim_end_matches('/').to_string(),
        })
    }

    /// The host and port a socket is opened to.
    pub fn authority(&self) -> String {
        if self.host.contains(':') {
            // An IPv6 literal: the brackets belong to the authority, not to the name.
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// The request target for a path below the prefix.
    ///
    /// An empty path addresses the prefix itself, which is what a service that puts its
    /// collection at `/api/users` expects for `/users` under the prefix `/api`.
    pub fn target(&self, path: &str) -> String {
        // An empty path addresses the prefix itself, and an empty prefix is the root - not
        // `/api/` and not the empty string a request line cannot carry.
        if path.is_empty() {
            return if self.prefix.is_empty() {
                "/".to_string()
            } else {
                self.prefix.clone()
            };
        }

        let path = if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{path}")
        };

        format!("{}{}", self.prefix, path)
    }
}

/// What went wrong talking to the service.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("'{url}' is not a usable address: {reason}")]
    Url { url: String, reason: String },
    #[error("cannot connect to {authority}: {source}")]
    Connect {
        authority: String,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot negotiate TLS with {authority}: {detail}")]
    Tls { authority: String, detail: String },
    #[error("request to {target} failed: {detail}")]
    Request { target: String, detail: String },
    #[error("request to {target} took longer than {limit:?}")]
    Timeout {
        target: String,
        limit: std::time::Duration,
    },
    #[error("{target} answered {status}: {body}")]
    Status {
        target: String,
        status: u16,
        body: String,
    },
    #[error("the answer of {target} is larger than {limit} bytes")]
    TooLarge { target: String, limit: usize },
}

/// One request to the configured service.
#[derive(Debug, Clone)]
pub struct Client {
    endpoint: Endpoint,
    token: Option<String>,
    timeout: std::time::Duration,
    trust: Trust,
}

impl Client {
    pub fn new(
        endpoint: Endpoint,
        token: Option<String>,
        timeout: std::time::Duration,
        trust: Trust,
    ) -> Self {
        Self {
            endpoint,
            token,
            timeout,
            trust,
        }
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// `GET path`, returning the body of a 200 answer.
    pub async fn get(&self, path: &str) -> Result<Bytes, Error> {
        self.send(hyper::Method::GET, path, None).await
    }

    /// `PUT path` with a JSON body, returning the body of a 200 answer.
    ///
    /// PUT and not POST: the caller names the object in the path and sends the fields that
    /// changed, so sending the same request twice leaves the same state.
    pub async fn put(&self, path: &str, body: Vec<u8>) -> Result<Bytes, Error> {
        self.send(hyper::Method::PUT, path, Some(body)).await
    }

    async fn send(
        &self,
        method: hyper::Method,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> Result<Bytes, Error> {
        let target = self.endpoint.target(path);

        match tokio::time::timeout(self.timeout, self.exchange(&method, &target, body)).await {
            Ok(result) => result,
            Err(_) => Err(Error::Timeout {
                target,
                limit: self.timeout,
            }),
        }
    }

    async fn exchange(
        &self,
        method: &hyper::Method,
        target: &str,
        body: Option<Vec<u8>>,
    ) -> Result<Bytes, Error> {
        let tcp = tokio::net::TcpStream::connect(self.endpoint.authority())
            .await
            .map_err(|source| Error::Connect {
                authority: self.endpoint.authority(),
                source,
            })?;

        let request = self.request(method, target, body.clone());

        if self.endpoint.secure {
            let config = self.trust.config().map_err(|err| Error::Tls {
                authority: self.endpoint.authority(),
                detail: err.to_string(),
            })?;

            let server_name = rustls::pki_types::ServerName::try_from(self.endpoint.host.clone())
                .map_err(|err| Error::Tls {
                authority: self.endpoint.authority(),
                detail: format!("'{}' is not a server name: {err}", self.endpoint.host),
            })?;

            let stream = tokio_rustls::TlsConnector::from(config)
                .connect(server_name, tcp)
                .await
                .map_err(|err| Error::Tls {
                    authority: self.endpoint.authority(),
                    detail: err.to_string(),
                })?;

            self.round_trip(stream, request, target).await
        } else {
            self.round_trip(tcp, request, target).await
        }
    }

    fn request(
        &self,
        method: &hyper::Method,
        target: &str,
        body: Option<Vec<u8>>,
    ) -> hyper::Request<http_body_util::Full<Bytes>> {
        let mut builder = hyper::Request::builder()
            .method(method.clone())
            .uri(target)
            .header(hyper::header::HOST, self.endpoint.authority())
            // The service is asked for JSON and told what it gets; an intermediary that
            // rewrites the body would break the diff this backend sends.
            .header(hyper::header::ACCEPT, "application/json");

        if let Some(token) = &self.token {
            builder = builder.header(hyper::header::AUTHORIZATION, format!("Token {token}"));
        }

        let body = match body {
            Some(bytes) => {
                builder = builder.header(hyper::header::CONTENT_TYPE, "application/json");
                bytes
            }
            None => Vec::new(),
        };

        builder
            .body(http_body_util::Full::new(Bytes::from(body)))
            .expect("a request with a valid method, URI and headers cannot fail to build")
    }

    async fn round_trip<S>(
        &self,
        stream: S,
        request: hyper::Request<http_body_util::Full<Bytes>>,
        target: &str,
    ) -> Result<Bytes, Error>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
                .await
                .map_err(|err| Error::Request {
                    target: target.to_string(),
                    detail: err.to_string(),
                })?;

        // The connection task owns the stream; it ends when the sender is dropped, which happens
        // when this request is done - one request per connection, no pooling.
        let driving = tokio::spawn(async move {
            let _ = connection.await;
        });

        let response = sender
            .send_request(request)
            .await
            .map_err(|err| Error::Request {
                target: target.to_string(),
                detail: err.to_string(),
            })?;

        let status = response.status();
        let body = read_limited(response, target).await?;

        drop(sender);
        driving.abort();

        if status != hyper::StatusCode::OK {
            return Err(Error::Status {
                target: target.to_string(),
                status: status.as_u16(),
                // The body of a refusal is the service's explanation, and losing it turns a
                // fixable mistake ("unknown user") into a bare status code.
                body: String::from_utf8_lossy(&body).trim().to_string(),
            });
        }

        Ok(body)
    }
}

/// Reads a body, refusing one that grows past [`MAX_BODY`].
async fn read_limited(
    response: hyper::Response<hyper::body::Incoming>,
    target: &str,
) -> Result<Bytes, Error> {
    let mut response = response;
    let mut collected = Vec::new();

    while let Some(frame) = response.frame().await {
        let frame = frame.map_err(|err| Error::Request {
            target: target.to_string(),
            detail: err.to_string(),
        })?;

        if let Some(chunk) = frame.data_ref() {
            if collected.len() + chunk.len() > MAX_BODY {
                return Err(Error::TooLarge {
                    target: target.to_string(),
                    limit: MAX_BODY,
                });
            }
            collected.extend_from_slice(chunk);
        }
    }

    Ok(Bytes::from(collected))
}

/// Posts are not offered on purpose: this backend names the object it changes in the path.
#[allow(dead_code)]
const _: Option<Arc<()>> = None;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plain_address_gets_the_default_port_and_no_prefix() {
        let endpoint = Endpoint::parse("http://localhost:8000").expect("parse");

        assert!(!endpoint.secure);
        assert_eq!(endpoint.host, "localhost");
        assert_eq!(endpoint.port, 8000);
        assert_eq!(endpoint.prefix, "");
        assert_eq!(endpoint.target("/users"), "/users");
    }

    #[test]
    fn https_without_a_port_means_four_four_three() {
        let endpoint = Endpoint::parse("https://directory.example.com").expect("parse");

        assert!(endpoint.secure);
        assert_eq!(endpoint.port, 443);
        assert_eq!(endpoint.authority(), "directory.example.com:443");
    }

    #[test]
    fn a_path_prefix_is_kept_and_joined_without_a_doubled_slash() {
        let endpoint = Endpoint::parse("http://localhost:8000/api/").expect("parse");

        assert_eq!(endpoint.prefix, "/api");
        assert_eq!(endpoint.target("/ldap/user"), "/api/ldap/user");
        assert_eq!(endpoint.target("ldap/user"), "/api/ldap/user");
    }

    #[test]
    fn an_address_without_a_scheme_is_refused_rather_than_guessed() {
        let err = Endpoint::parse("localhost:8000/api").expect_err("refuse");
        assert!(err.to_string().contains("no scheme"), "{err}");
    }

    #[test]
    fn an_unknown_scheme_is_refused_by_name() {
        let err = Endpoint::parse("ftp://localhost/").expect_err("refuse");
        assert!(err.to_string().contains("unknown scheme 'ftp'"), "{err}");
    }

    #[test]
    fn credentials_in_the_address_are_refused_rather_than_sent() {
        // A token in the URL ends up in the startup line that prints where the backend points,
        // and in every log of it.
        let err = Endpoint::parse("http://user:secret@localhost:8000").expect_err("refuse");
        assert!(err.to_string().contains("auth_token"), "{err}");
    }

    #[test]
    fn a_port_that_is_not_a_number_is_refused_with_the_text() {
        let err = Endpoint::parse("http://localhost:http").expect_err("refuse");
        assert!(err.to_string().contains("'http' is not a port"), "{err}");
    }

    #[test]
    fn an_ipv6_literal_keeps_its_brackets_in_the_authority() {
        let endpoint = Endpoint::parse("http://[::1]:8000/api").expect("parse");

        assert_eq!(endpoint.host, "::1");
        assert_eq!(endpoint.authority(), "[::1]:8000");
    }

    #[test]
    fn an_empty_path_addresses_the_prefix_itself() {
        let endpoint = Endpoint::parse("http://localhost:8000/api").expect("parse");
        assert_eq!(endpoint.target(""), "/api");

        let bare = Endpoint::parse("http://localhost:8000").expect("parse");
        assert_eq!(bare.target(""), "/");
    }
}
