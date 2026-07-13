//! Strict source attribution for the small set of public, IP-rate-limited endpoints.
//!
//! A reserved header is useful only behind the one explicitly pinned reverse proxy. Direct
//! development requests use the socket peer and must not be able to opt into header trust.

use std::net::{IpAddr, SocketAddr};

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::{request::Parts, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

pub(crate) const CLIENT_IP_HEADER: &str = "x-nil-client-ip";

/// How a service resolves the transient address used for an in-memory abuse-control bucket.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ClientIpPolicy {
    trusted_proxy: Option<IpAddr>,
}

impl ClientIpPolicy {
    #[cfg(test)]
    pub(crate) const fn direct() -> Self {
        Self {
            trusted_proxy: None,
        }
    }

    #[cfg(test)]
    pub(crate) const fn trusted_proxy(ip: IpAddr) -> Self {
        Self {
            trusted_proxy: Some(ip),
        }
    }

    /// Load the single allowed proxy address. Release builds refuse direct-peer mode because the
    /// production listener is designed to sit behind Caddy and would otherwise collapse every
    /// caller into Caddy's rate-limit bucket.
    pub(crate) fn from_env(release_build: bool) -> anyhow::Result<Self> {
        match std::env::var("NW_TRUSTED_PROXY_IP") {
            Ok(raw) => Self::from_config(Some(&raw), release_build),
            Err(std::env::VarError::NotPresent) => Self::from_config(None, release_build),
            Err(std::env::VarError::NotUnicode(_)) => {
                anyhow::bail!("NW_TRUSTED_PROXY_IP must be a canonical IP address")
            }
        }
    }

    fn from_config(raw: Option<&str>, release_build: bool) -> anyhow::Result<Self> {
        let trusted_proxy = match raw {
            Some(raw) => Some(parse_canonical_ip(raw).ok_or_else(|| {
                anyhow::anyhow!(
                    "NW_TRUSTED_PROXY_IP must contain exactly one canonical IPv4 or IPv6 address"
                )
            })?),
            None if release_build => {
                anyhow::bail!(
                    "release nil-portal requires NW_TRUSTED_PROXY_IP to pin the exact reverse-proxy socket peer"
                )
            }
            None => None,
        };
        Ok(Self { trusted_proxy })
    }

    fn resolve(self, peer: IpAddr, headers: &HeaderMap) -> Result<IpAddr, ClientIpRejection> {
        let Some(trusted_proxy) = self.trusted_proxy else {
            // The reserved field has no meaning on a direct development connection. Reject it so
            // a deployment cannot accidentally start trusting caller-controlled attribution.
            if headers.contains_key(CLIENT_IP_HEADER) {
                return Err(ClientIpRejection::UnexpectedHeader);
            }
            return Ok(peer);
        };

        // Authenticate the socket peer before examining any caller-controlled bytes.
        if peer != trusted_proxy {
            return Err(ClientIpRejection::UntrustedPeer);
        }

        let mut values = headers.get_all(CLIENT_IP_HEADER).iter();
        let value = values.next().ok_or(ClientIpRejection::InvalidHeader)?;
        if values.next().is_some() {
            return Err(ClientIpRejection::InvalidHeader);
        }
        let raw = value
            .to_str()
            .map_err(|_| ClientIpRejection::InvalidHeader)?;
        parse_canonical_ip(raw).ok_or(ClientIpRejection::InvalidHeader)
    }
}

fn parse_canonical_ip(raw: &str) -> Option<IpAddr> {
    let parsed = raw.parse::<IpAddr>().ok()?;
    (parsed.to_string() == raw).then_some(parsed)
}

/// Extracted, verified address. It is used only as an ephemeral rate-limit key and is never
/// logged, returned, or persisted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ClientIp(pub(crate) IpAddr);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ClientIpRejection {
    MissingConnectInfo,
    MissingPolicy,
    UntrustedPeer,
    InvalidHeader,
    UnexpectedHeader,
}

impl IntoResponse for ClientIpRejection {
    fn into_response(self) -> Response {
        // Deliberately return only a PII-free status. Do not echo the socket peer or header.
        match self {
            Self::MissingConnectInfo | Self::MissingPolicy => StatusCode::INTERNAL_SERVER_ERROR,
            Self::UntrustedPeer => StatusCode::FORBIDDEN,
            Self::InvalidHeader | Self::UnexpectedHeader => StatusCode::BAD_REQUEST,
        }
        .into_response()
    }
}

#[axum::async_trait]
impl<S> FromRequestParts<S> for ClientIp
where
    S: Send + Sync,
{
    type Rejection = ClientIpRejection;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|connect| connect.0.ip())
            .ok_or(ClientIpRejection::MissingConnectInfo)?;
        let policy = parts
            .extensions
            .get::<ClientIpPolicy>()
            .copied()
            .ok_or(ClientIpRejection::MissingPolicy)?;
        policy.resolve(peer, &parts.headers).map(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderName, HeaderValue};
    use std::time::Duration;

    fn ip(raw: &str) -> IpAddr {
        raw.parse().unwrap()
    }

    fn headers(values: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append(
                HeaderName::from_static(CLIENT_IP_HEADER),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        headers
    }

    #[test]
    fn trusted_proxy_requires_one_canonical_reserved_value() {
        let policy = ClientIpPolicy::trusted_proxy(ip("172.30.10.2"));
        assert_eq!(
            policy.resolve(ip("172.30.10.2"), &headers(&["198.51.100.7"])),
            Ok(ip("198.51.100.7"))
        );
        for hostile in [
            vec![],
            vec!["198.51.100.7", "203.0.113.8"],
            vec!["198.51.100.7,203.0.113.8"],
            vec!["2001:0db8::1"],
            vec!["198.51.100.7:443"],
        ] {
            assert_eq!(
                policy.resolve(ip("172.30.10.2"), &headers(&hostile)),
                Err(ClientIpRejection::InvalidHeader)
            );
        }
    }

    #[test]
    fn untrusted_peer_is_rejected_before_its_header_is_considered() {
        let policy = ClientIpPolicy::trusted_proxy(ip("172.30.10.2"));
        assert_eq!(
            policy.resolve(ip("172.30.10.99"), &headers(&["not-an-ip"])),
            Err(ClientIpRejection::UntrustedPeer)
        );
    }

    #[test]
    fn direct_mode_uses_the_peer_and_rejects_the_reserved_header() {
        let peer = ip("198.51.100.9");
        assert_eq!(
            ClientIpPolicy::direct().resolve(peer, &HeaderMap::new()),
            Ok(peer)
        );
        assert_eq!(
            ClientIpPolicy::direct().resolve(peer, &headers(&["203.0.113.4"])),
            Err(ClientIpRejection::UnexpectedHeader)
        );
    }

    #[test]
    fn unrelated_forwarding_headers_never_select_the_bucket() {
        let policy = ClientIpPolicy::trusted_proxy(ip("172.30.10.2"));
        let mut headers = headers(&["198.51.100.7"]);
        headers.insert("forwarded", HeaderValue::from_static("for=203.0.113.99"));
        headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.99"));
        headers.insert("cf-connecting-ip", HeaderValue::from_static("203.0.113.99"));
        assert_eq!(
            policy.resolve(ip("172.30.10.2"), &headers),
            Ok(ip("198.51.100.7"))
        );
    }

    #[test]
    fn authenticated_sources_receive_independent_rate_limit_budgets() {
        let policy = ClientIpPolicy::trusted_proxy(ip("172.30.10.2"));
        let first = policy
            .resolve(ip("172.30.10.2"), &headers(&["198.51.100.7"]))
            .unwrap();
        let second = policy
            .resolve(ip("172.30.10.2"), &headers(&["203.0.113.8"]))
            .unwrap();
        let limiter = crate::ratelimit::RateLimiter::new(1, Duration::from_secs(60));

        assert!(limiter.check(&first.to_string()));
        assert!(limiter.check(&second.to_string()));
        assert!(!limiter.check(&first.to_string()));
    }

    #[test]
    fn release_configuration_requires_one_canonical_proxy_ip() {
        assert!(ClientIpPolicy::from_config(None, true).is_err());
        assert!(ClientIpPolicy::from_config(Some(" 172.30.10.2"), true).is_err());
        assert!(ClientIpPolicy::from_config(Some("172.30.10.2,172.30.10.3"), true).is_err());
        assert!(ClientIpPolicy::from_config(Some("2001:0db8::1"), true).is_err());
        assert_eq!(
            ClientIpPolicy::from_config(Some("2001:db8::1"), true).unwrap(),
            ClientIpPolicy::trusted_proxy(ip("2001:db8::1"))
        );
        assert_eq!(
            ClientIpPolicy::from_config(None, false).unwrap(),
            ClientIpPolicy::direct()
        );
    }
}
