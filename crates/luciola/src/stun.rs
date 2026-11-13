//! RFC 5389 Session Traversal Utilities for NAT (STUN) client.
//!
//! Provides asynchronous discovery of public reflexive endpoints (`srflx`)
//! across both IPv4 and IPv6 without external heavy dependencies.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::Duration;
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::time::{sleep, Instant};

/// Standard RFC 5389 STUN magic cookie (0x2112A442).
pub const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;
/// STUN Binding Request message type.
pub const BINDING_REQUEST: u16 = 0x0001;
/// STUN Binding Success Response message type.
pub const BINDING_RESPONSE: u16 = 0x0101;
/// STUN Binding Error Response message type (RFC 5389 class = error).
pub const BINDING_ERROR_RESPONSE: u16 = 0x0111;
/// Attribute type: XOR-MAPPED-ADDRESS (RFC 5389).
pub const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
/// Attribute type: MAPPED-ADDRESS (RFC 3489 compatibility).
pub const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
/// Attribute type: CHANGE-REQUEST (RFC 5780 / RFC 3489).
pub const ATTR_CHANGE_REQUEST: u16 = 0x0003;
/// Attribute type: RESPONSE-ORIGIN (RFC 5780).
pub const ATTR_RESPONSE_ORIGIN: u16 = 0x802b;
/// Attribute type: OTHER-ADDRESS (RFC 5780).
pub const ATTR_OTHER_ADDRESS: u16 = 0x802c;

/// RFC 5780 NAT Mapping Behavior classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum NatMappingBehavior {
    /// No NAT translation: local address equals reflexive address.
    DirectOpen,
    /// Endpoint-Independent Mapping: reflexive endpoint is constant across all destinations.
    EndpointIndependent,
    /// Address-Dependent Mapping: reflexive endpoint depends on target IP.
    AddressDependent,
    /// Address and Port-Dependent Mapping: reflexive endpoint changes for each target (Symmetric NAT).
    AddressAndPortDependent,
    /// Behavior could not be determined conclusively.
    Unknown,
}

impl NatMappingBehavior {
    /// Human-readable label for diagnostics.
    pub fn as_str(&self) -> &'static str {
        match self {
            NatMappingBehavior::DirectOpen => "Direct (No NAT)",
            NatMappingBehavior::EndpointIndependent => "Endpoint-Independent (Cone)",
            NatMappingBehavior::AddressDependent => "Address-Dependent",
            NatMappingBehavior::AddressAndPortDependent => "Address-and-Port-Dependent (Symmetric)",
            NatMappingBehavior::Unknown => "Unknown",
        }
    }
}

/// RFC 5780 NAT Filtering Behavior classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum NatFilteringBehavior {
    /// No filtering applied (Direct / Open Internet).
    DirectOpen,
    /// Endpoint-Independent Filtering (Full Cone: any external host can send inbound).
    EndpointIndependent,
    /// Address-Dependent Filtering (Restricted Cone: external host must have received an outbound packet).
    AddressDependent,
    /// Address and Port-Dependent Filtering (Port-Restricted Cone).
    AddressAndPortDependent,
    /// Filtering behavior could not be determined conclusively.
    Unknown,
}

impl NatFilteringBehavior {
    /// Human-readable label for diagnostics.
    pub fn as_str(&self) -> &'static str {
        match self {
            NatFilteringBehavior::DirectOpen => "Direct (No Filtering)",
            NatFilteringBehavior::EndpointIndependent => "Endpoint-Independent (Full Cone)",
            NatFilteringBehavior::AddressDependent => "Address-Dependent (Restricted Cone)",
            NatFilteringBehavior::AddressAndPortDependent => {
                "Address-and-Port-Dependent (Port Restricted)"
            }
            NatFilteringBehavior::Unknown => "Unknown",
        }
    }
}

/// High-level NAT topology classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum NatClassification {
    /// Direct public internet or native IPv6.
    OpenInternet = 1,
    /// Full cone NAT: inbound packets from any remote IP/port accepted.
    FullCone = 2,
    /// Address-restricted cone NAT: inbound accepted only from visited IP.
    RestrictedCone = 3,
    /// Port-restricted cone NAT: inbound accepted only from visited IP:Port.
    PortRestrictedCone = 4,
    /// Symmetric NAT: separate mapping per destination; P2P punch probability ~0%.
    Symmetric = 5,
    /// Unknown or unresolved.
    Unknown = 0,
}

impl NatClassification {
    /// Convert numeric code to enum.
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => NatClassification::OpenInternet,
            2 => NatClassification::FullCone,
            3 => NatClassification::RestrictedCone,
            4 => NatClassification::PortRestrictedCone,
            5 => NatClassification::Symmetric,
            _ => NatClassification::Unknown,
        }
    }

    /// Human-readable diagnosis.
    pub fn as_str(&self) -> &'static str {
        match self {
            NatClassification::OpenInternet => "Open Internet",
            NatClassification::FullCone => "Full Cone",
            NatClassification::RestrictedCone => "Restricted Cone",
            NatClassification::PortRestrictedCone => "Port-Restricted Cone",
            NatClassification::Symmetric => "Symmetric NAT",
            NatClassification::Unknown => "Unknown",
        }
    }
}

/// Diagnostic report detailing local NAT characteristics.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NatReport {
    /// Local socket binding address.
    pub local_addr: SocketAddr,
    /// Server-reflexive public endpoint (if discovered).
    pub reflexive_addr: Option<SocketAddr>,
    /// NAT mapping behavior.
    pub mapping: NatMappingBehavior,
    /// NAT filtering behavior.
    pub filtering: NatFilteringBehavior,
}

impl NatReport {
    /// Derive overall classification from mapping and filtering behavior.
    pub fn classification(&self) -> NatClassification {
        if self.mapping == NatMappingBehavior::DirectOpen {
            return NatClassification::OpenInternet;
        }
        if self.mapping == NatMappingBehavior::AddressAndPortDependent {
            return NatClassification::Symmetric;
        }
        // A classification is only worth printing when both dimensions were
        // actually measured. Guessing "cone" from one half is how a symmetric
        // NAT ends up being advertised as punchable.
        match (self.mapping, self.filtering) {
            (_, NatFilteringBehavior::Unknown) | (NatMappingBehavior::Unknown, _) => {
                NatClassification::Unknown
            }
            (_, NatFilteringBehavior::DirectOpen) => NatClassification::OpenInternet,
            (_, NatFilteringBehavior::EndpointIndependent) => NatClassification::FullCone,
            (_, NatFilteringBehavior::AddressDependent) => NatClassification::RestrictedCone,
            (_, NatFilteringBehavior::AddressAndPortDependent) => {
                NatClassification::PortRestrictedCone
            }
        }
    }
}

/// Parsed attributes from a STUN Binding response.
#[derive(Debug, Clone)]
pub struct StunResponseDetails {
    /// Reflexive public endpoint.
    pub mapped_address: SocketAddr,
    /// Address from which the response was sent (RESPONSE-ORIGIN).
    pub response_origin: Option<SocketAddr>,
    /// Alternative address and port available on the STUN server (OTHER-ADDRESS).
    pub other_address: Option<SocketAddr>,
}

/// Default verified public STUN server endpoints.
pub const DEFAULT_STUN_SERVERS: &[&str] = &[
    "stun.cloudflare.com:3478",
    "stun.miwifi.com:3478",
    "stun.1und1.de:3478",
];

/// Errors produced during STUN server communication or response decoding.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum StunError {
    /// An underlying socket I/O error occurred.
    #[error("stun io error: {0}")]
    Io(#[from] std::io::Error),
    /// The STUN request timed out after retries.
    #[error("stun query timed out")]
    Timeout,
    /// The response header or magic cookie was invalid.
    #[error("invalid stun header or transaction id mismatch")]
    InvalidHeader,
    /// Neither XOR-MAPPED-ADDRESS nor MAPPED-ADDRESS attribute was found.
    #[error("no mapped address attribute found in stun response")]
    AddressNotFound,
    /// Failed to resolve the STUN server hostname.
    #[error("failed to resolve stun server: {0}")]
    ResolveFailed(String),
    /// The server answered with a Binding Error Response.
    #[error("stun server returned a binding error response")]
    ErrorResponse,
}

/// Builds an RFC 5389 20-byte Binding Request message.
pub fn build_binding_request(transaction_id: [u8; 12]) -> [u8; 20] {
    let mut req = [0u8; 20];
    req[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    req[2..4].copy_from_slice(&0u16.to_be_bytes()); // Message Length: 0
    req[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    req[8..20].copy_from_slice(&transaction_id);
    req
}

/// Builds an RFC 5780 Binding Request message with CHANGE-REQUEST attribute.
pub fn build_binding_request_with_change(
    transaction_id: [u8; 12],
    change_ip: bool,
    change_port: bool,
) -> Vec<u8> {
    let mut req = Vec::with_capacity(28);
    req.extend_from_slice(&BINDING_REQUEST.to_be_bytes());
    req.extend_from_slice(&8u16.to_be_bytes()); // Attribute total length: 4 (header) + 4 (val) = 8
    req.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    req.extend_from_slice(&transaction_id);

    req.extend_from_slice(&ATTR_CHANGE_REQUEST.to_be_bytes());
    req.extend_from_slice(&4u16.to_be_bytes());
    let mut flags = 0u32;
    if change_ip {
        flags |= 0x04;
    }
    if change_port {
        flags |= 0x02;
    }
    req.extend_from_slice(&flags.to_be_bytes());
    req
}

fn parse_sockaddr_raw(attr_val: &[u8]) -> Option<SocketAddr> {
    if attr_val.len() < 8 {
        return None;
    }
    let family = attr_val[1];
    let port = u16::from_be_bytes([attr_val[2], attr_val[3]]);
    if family == 0x01 && attr_val.len() >= 8 {
        let ip = Ipv4Addr::new(attr_val[4], attr_val[5], attr_val[6], attr_val[7]);
        Some(SocketAddr::V4(SocketAddrV4::new(ip, port)))
    } else if family == 0x02 && attr_val.len() >= 20 {
        let mut ip_bytes = [0u8; 16];
        ip_bytes.copy_from_slice(&attr_val[4..20]);
        let ip = Ipv6Addr::from(ip_bytes);
        Some(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)))
    } else {
        None
    }
}

/// Parses a STUN Binding Success Response buffer and extracts detailed attributes (RFC 5780).
pub fn parse_detailed_binding_response(
    buf: &[u8],
    expected_transaction_id: &[u8; 12],
) -> Result<StunResponseDetails, StunError> {
    if buf.len() < 20 {
        return Err(StunError::InvalidHeader);
    }

    let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
    let msg_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let magic = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let resp_tid = &buf[8..20];

    if msg_type == BINDING_ERROR_RESPONSE && magic == STUN_MAGIC_COOKIE {
        return Err(StunError::ErrorResponse);
    }
    if msg_type != BINDING_RESPONSE
        || magic != STUN_MAGIC_COOKIE
        || resp_tid != expected_transaction_id
    {
        return Err(StunError::InvalidHeader);
    }
    if !msg_len.is_multiple_of(4) || 20usize.saturating_add(msg_len) > buf.len() {
        return Err(StunError::InvalidHeader);
    }

    let attr_end = 20 + msg_len;
    let mut offset = 20;

    let mut xor_mapped_addr = None;
    let mut fallback_mapped_addr = None;
    let mut response_origin = None;
    let mut other_address = None;

    while offset + 4 <= attr_end {
        let attr_type = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let attr_len = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]) as usize;
        offset += 4;

        if offset + attr_len > attr_end {
            break;
        }

        let attr_val = &buf[offset..offset + attr_len];

        if attr_type == ATTR_XOR_MAPPED_ADDRESS && attr_len >= 8 {
            let family = attr_val[1];
            let xor_port = u16::from_be_bytes([attr_val[2], attr_val[3]]);
            let port = xor_port ^ (STUN_MAGIC_COOKIE >> 16) as u16;

            if family == 0x01 && attr_len >= 8 {
                let xor_ip =
                    u32::from_be_bytes([attr_val[4], attr_val[5], attr_val[6], attr_val[7]]);
                let ip = Ipv4Addr::from(xor_ip ^ STUN_MAGIC_COOKIE);
                xor_mapped_addr = Some(SocketAddr::V4(SocketAddrV4::new(ip, port)));
            } else if family == 0x02 && attr_len >= 20 {
                let mut xor_key = [0u8; 16];
                xor_key[0..4].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
                xor_key[4..16].copy_from_slice(expected_transaction_id);

                let mut ip_bytes = [0u8; 16];
                for i in 0..16 {
                    ip_bytes[i] = attr_val[4 + i] ^ xor_key[i];
                }
                let ip = Ipv6Addr::from(ip_bytes);
                xor_mapped_addr = Some(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)));
            }
        } else if attr_type == ATTR_MAPPED_ADDRESS && attr_len >= 8 {
            fallback_mapped_addr = parse_sockaddr_raw(attr_val);
        } else if attr_type == ATTR_RESPONSE_ORIGIN && attr_len >= 8 {
            response_origin = parse_sockaddr_raw(attr_val);
        } else if attr_type == ATTR_OTHER_ADDRESS && attr_len >= 8 {
            other_address = parse_sockaddr_raw(attr_val);
        }

        // Align attribute to 4-byte boundary
        offset += (attr_len + 3) & !3;
    }

    let mapped_address = xor_mapped_addr
        .or(fallback_mapped_addr)
        .ok_or(StunError::AddressNotFound)?;

    Ok(StunResponseDetails {
        mapped_address,
        response_origin,
        other_address,
    })
}

/// Parses a STUN Binding Success Response buffer and extracts the public mapped address.
pub fn parse_binding_response(
    buf: &[u8],
    expected_transaction_id: &[u8; 12],
) -> Result<SocketAddr, StunError> {
    parse_detailed_binding_response(buf, expected_transaction_id).map(|d| d.mapped_address)
}

/// Discovers the public reflexive socket address by querying the given STUN servers.
///
/// **Crucial**: The `socket` passed in MUST be the same socket used for subsequent hole
/// punching probes and data transfer, ensuring the NAT mapping remains valid and identical.
pub async fn query_public_address(
    socket: &UdpSocket,
    servers: &[&str],
) -> Result<SocketAddr, StunError> {
    let is_v4 = socket.local_addr()?.is_ipv4();
    if servers.is_empty() {
        return Err(StunError::ResolveFailed(
            "no STUN servers configured".into(),
        ));
    }

    // Hard upper bound so an unreachable server list can never wedge a CLI
    // command or a WAN connection attempt indefinitely.
    let overall_deadline = Instant::now() + Duration::from_secs(5);
    let mut resolved_any = false;
    let mut last_error = StunError::Timeout;

    for &server in servers {
        if Instant::now() >= overall_deadline {
            break;
        }
        let addrs = match tokio::net::lookup_host(server).await {
            Ok(addrs) => addrs,
            Err(e) => {
                last_error = StunError::ResolveFailed(format!("{server}: {e}"));
                continue;
            }
        };

        // Filter address family to match socket family
        let target_addr = match addrs.into_iter().find(|a| a.is_ipv4() == is_v4) {
            Some(a) => a,
            None => {
                last_error = StunError::ResolveFailed(format!(
                    "{server}: no address matching the socket family"
                ));
                continue;
            }
        };
        resolved_any = true;

        let mut transaction_id = [0u8; 12];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut transaction_id);
        let req_bytes = build_binding_request(transaction_id);

        let mut rto = Duration::from_millis(400);
        const MAX_ATTEMPTS: u32 = 3;

        for _ in 0..MAX_ATTEMPTS {
            if Instant::now() >= overall_deadline {
                return Err(StunError::Timeout);
            }
            if socket.send_to(&req_bytes, target_addr).await.is_err() {
                break;
            }

            let attempt_deadline = (Instant::now() + rto).min(overall_deadline);
            let mut buf = [0u8; 512];

            while Instant::now() < attempt_deadline {
                let remaining = attempt_deadline.saturating_duration_since(Instant::now());
                match tokio::time::timeout(remaining, socket.recv_from(&mut buf)).await {
                    Ok(Ok((len, from))) => {
                        // Verify response source address strictly matches target
                        // to prevent spoofing.
                        if from == target_addr {
                            match parse_binding_response(&buf[..len], &transaction_id) {
                                Ok(mapped) => return Ok(mapped),
                                Err(StunError::ErrorResponse) => {
                                    last_error = StunError::ErrorResponse;
                                    break; // try the next server
                                }
                                Err(_) => {} // malformed / unrelated datagram
                            }
                        }
                    }
                    Ok(Err(e)) => return Err(StunError::Io(e)),
                    Err(_) => break, // Timeout for this attempt
                }
            }

            rto *= 2;
            sleep(Duration::from_millis(50)).await;
        }
    }

    if !resolved_any {
        Err(last_error)
    } else {
        Err(StunError::Timeout)
    }
}

/// Sends one probe and returns the parsed response **plus the address it came
/// from**.
///
/// The source address is not decoration: RFC 5780's filtering tests are only
/// meaningful if the reply really came from the alternate endpoint. A server
/// that ignores CHANGE-REQUEST answers from its primary address, and treating
/// that as success reports a Full Cone NAT that does not exist.
async fn query_stun_target(
    socket: &UdpSocket,
    target_addr: SocketAddr,
    req_bytes: &[u8],
    expected_tid: &[u8; 12],
    timeout_duration: Duration,
) -> Result<(StunResponseDetails, SocketAddr), StunError> {
    socket.send_to(req_bytes, target_addr).await?;
    let deadline = Instant::now() + timeout_duration;
    let mut buf = [0u8; 512];
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, socket.recv_from(&mut buf)).await {
            Ok(Ok((len, from))) => {
                if let Ok(details) = parse_detailed_binding_response(&buf[..len], expected_tid) {
                    return Ok((details, from));
                }
            }
            Ok(Err(e)) => return Err(StunError::Io(e)),
            Err(_) => break,
        }
    }
    Err(StunError::Timeout)
}

/// Discovers RFC 5780 NAT mapping and filtering behavior using multi-server or multi-attribute probes.
pub async fn probe_nat_behavior(
    socket: &UdpSocket,
    servers: &[&str],
) -> Result<NatReport, StunError> {
    let local_addr = socket.local_addr()?;
    let is_v4 = local_addr.is_ipv4();

    let mut resolved_servers: Vec<SocketAddr> = Vec::new();
    for &server in servers {
        if let Ok(addrs) = tokio::net::lookup_host(server).await {
            if let Some(target) = addrs.into_iter().find(|a| a.is_ipv4() == is_v4) {
                if !resolved_servers.contains(&target) {
                    resolved_servers.push(target);
                }
            }
        }
    }
    if resolved_servers.is_empty() {
        return Err(StunError::ResolveFailed(
            "could not resolve STUN servers".into(),
        ));
    }

    let primary_server = resolved_servers[0];

    // --- TEST I: Query primary server ---
    let mut tid_1 = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut tid_1);
    let req_1 = build_binding_request(tid_1);
    // First query also pinpoints the address the server answers from, which is
    // the baseline every filtering test is compared against.
    let (resp_1, _server_source) = query_stun_target(
        socket,
        primary_server,
        &req_1,
        &tid_1,
        Duration::from_millis(1500),
    )
    .await?;

    let reflexive_addr = resp_1.mapped_address;

    // Check if open internet (local IP matches reflexive IP)
    let is_open_internet = if local_addr.ip() == reflexive_addr.ip() {
        true
    } else {
        let local_ips: Vec<_> = luciola_net::NetworkDetector::local_candidate_addresses();
        local_ips
            .iter()
            .any(|ip| ip == &reflexive_addr.ip().to_string())
    };

    if is_open_internet {
        return Ok(NatReport {
            local_addr,
            reflexive_addr: Some(reflexive_addr),
            mapping: NatMappingBehavior::DirectOpen,
            filtering: NatFilteringBehavior::DirectOpen,
        });
    }

    // --- MAPPING BEHAVIOR TEST ---
    // A server that advertises OTHER-ADDRESS is RFC 5780 aware, which makes a
    // failed alternate probe meaningful rather than a guess.
    let server_supports_rfc5780 = resp_1.other_address.is_some();

    let mapping = if let Some(other_addr) = resp_1.other_address {
        // Probe the alternate endpoint exactly as advertised: OTHER-ADDRESS
        // carries its own port and that is the only port listening there.
        let mut tid_alt = [0u8; 12];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut tid_alt);
        let req_alt = build_binding_request(tid_alt);
        match query_stun_target(
            socket,
            other_addr,
            &req_alt,
            &tid_alt,
            Duration::from_millis(1200),
        )
        .await
        {
            Ok((resp_alt, _)) if resp_alt.mapped_address == reflexive_addr => {
                NatMappingBehavior::EndpointIndependent
            }
            Ok((resp_alt, _)) => {
                // Same alternate IP, primary port: an unchanged mapping here
                // means the mapping depends on the destination IP only.
                let same_ip_primary_port = SocketAddr::new(other_addr.ip(), primary_server.port());
                if same_ip_primary_port == other_addr {
                    NatMappingBehavior::AddressAndPortDependent
                } else {
                    let mut tid_third = [0u8; 12];
                    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut tid_third);
                    let req_third = build_binding_request(tid_third);
                    match query_stun_target(
                        socket,
                        same_ip_primary_port,
                        &req_third,
                        &tid_third,
                        Duration::from_millis(800),
                    )
                    .await
                    {
                        Ok((resp_third, _))
                            if resp_third.mapped_address.port()
                                == resp_alt.mapped_address.port() =>
                        {
                            NatMappingBehavior::AddressDependent
                        }
                        Ok(_) => NatMappingBehavior::AddressAndPortDependent,
                        Err(_) => NatMappingBehavior::Unknown,
                    }
                }
            }
            // A timeout proves nothing about the mapping. Defaulting it to
            // "cone" is how a symmetric NAT gets advertised as punchable.
            Err(_) => NatMappingBehavior::Unknown,
        }
    } else if resolved_servers.len() > 1 {
        let secondary_server = resolved_servers[1];
        let mut tid_2 = [0u8; 12];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut tid_2);
        let req_2 = build_binding_request(tid_2);
        match query_stun_target(
            socket,
            secondary_server,
            &req_2,
            &tid_2,
            Duration::from_millis(1500),
        )
        .await
        {
            Ok((resp_2, _)) if resp_2.mapped_address == reflexive_addr => {
                NatMappingBehavior::EndpointIndependent
            }
            Ok(_) => NatMappingBehavior::AddressAndPortDependent,
            Err(_) => NatMappingBehavior::Unknown,
        }
    } else {
        // One server and no OTHER-ADDRESS: the mapping cannot be measured.
        NatMappingBehavior::Unknown
    };

    // --- FILTERING BEHAVIOR TEST ---
    // Test II asks the server to answer from a different IP *and* port. Only a
    // reply that demonstrably came from somewhere else counts: a server that
    // ignores CHANGE-REQUEST answers from its own address, which is evidence of
    // nothing at all.
    let mut tid_f2 = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut tid_f2);
    let req_f2 = build_binding_request_with_change(tid_f2, true, true);
    // The discriminator that actually matters: did the reply come from the
    // endpoint we sent to, or from somewhere else? A server that ignores
    // CHANGE-REQUEST answers from its own address and proves nothing; one that
    // honours it necessarily answers from another endpoint.
    let request_honoured = matches!(
        query_stun_target(
            socket,
            primary_server,
            &req_f2,
            &tid_f2,
            Duration::from_millis(700),
        )
        .await,
        Ok((_, from)) if from != primary_server
    );

    let filtering = if request_honoured {
        NatFilteringBehavior::EndpointIndependent
    } else {
        let mut tid_f3 = [0u8; 12];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut tid_f3);
        let req_f3 = build_binding_request_with_change(tid_f3, false, true);
        match query_stun_target(
            socket,
            primary_server,
            &req_f3,
            &tid_f3,
            Duration::from_millis(700),
        )
        .await
        {
            Ok((_, from)) if from.port() != primary_server.port() => {
                NatFilteringBehavior::AddressDependent
            }
            // Answered from the primary endpoint: CHANGE-REQUEST was ignored.
            Ok(_) => NatFilteringBehavior::Unknown,
            // Silence from an RFC 5780 server is the documented signature of
            // port-restricted filtering; silence from anything else says
            // nothing.
            Err(_) if server_supports_rfc5780 => NatFilteringBehavior::AddressAndPortDependent,
            Err(_) => NatFilteringBehavior::Unknown,
        }
    };

    Ok(NatReport {
        local_addr,
        reflexive_addr: Some(reflexive_addr),
        mapping,
        filtering,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ipv4_xor_mapped_address() {
        let tid: [u8; 12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let mut resp = Vec::new();
        // Header: 0x0101, len: 12, magic: 0x2112A442, tid
        resp.extend_from_slice(&0x0101u16.to_be_bytes());
        resp.extend_from_slice(&12u16.to_be_bytes());
        resp.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        resp.extend_from_slice(&tid);

        // Attribute: 0x0020 (XOR-MAPPED-ADDRESS), len: 8
        resp.extend_from_slice(&0x0020u16.to_be_bytes());
        resp.extend_from_slice(&8u16.to_be_bytes());

        // Value: 0x00, family: 0x01 (IPv4)
        resp.push(0x00);
        resp.push(0x01);

        // Target: 1.2.3.4:54321
        let target_port: u16 = 54321;
        let xport = target_port ^ (STUN_MAGIC_COOKIE >> 16) as u16;
        resp.extend_from_slice(&xport.to_be_bytes());

        let target_ip: u32 = 0x01020304; // 1.2.3.4
        let xip = target_ip ^ STUN_MAGIC_COOKIE;
        resp.extend_from_slice(&xip.to_be_bytes());

        let parsed = parse_binding_response(&resp, &tid).expect("Should parse valid response");
        assert_eq!(parsed, "1.2.3.4:54321".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn parse_ipv6_xor_mapped_address() {
        let tid: [u8; 12] = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
        ];
        let mut resp = Vec::new();
        resp.extend_from_slice(&0x0101u16.to_be_bytes());
        resp.extend_from_slice(&24u16.to_be_bytes());
        resp.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        resp.extend_from_slice(&tid);

        // Attribute: 0x0020, len: 20
        resp.extend_from_slice(&0x0020u16.to_be_bytes());
        resp.extend_from_slice(&20u16.to_be_bytes());
        resp.push(0x00);
        resp.push(0x02); // IPv6

        let target_port: u16 = 8080;
        let xport = target_port ^ (STUN_MAGIC_COOKIE >> 16) as u16;
        resp.extend_from_slice(&xport.to_be_bytes());

        let target_ipv6 = [
            0x24, 0x08, 0x82, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];
        let mut xor_key = [0u8; 16];
        xor_key[0..4].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        xor_key[4..16].copy_from_slice(&tid);

        for i in 0..16 {
            resp.push(target_ipv6[i] ^ xor_key[i]);
        }

        let parsed = parse_binding_response(&resp, &tid).expect("Should parse IPv6 response");
        assert_eq!(parsed.port(), 8080);
        assert_eq!(
            parsed.ip(),
            "2408:8248::1".parse::<std::net::IpAddr>().unwrap()
        );
    }

    /// Build a Binding Success Response containing XOR-MAPPED-ADDRESS for
    /// 1.2.3.4:54321, optionally preceded by an odd-length attribute so the
    /// 4-byte padding rule is exercised.
    fn success_response(tid: &[u8; 12], pad: bool) -> Vec<u8> {
        let mut body = Vec::new();
        if pad {
            body.extend_from_slice(&0x9999u16.to_be_bytes()); // unknown attribute
            body.extend_from_slice(&3u16.to_be_bytes());
            body.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0x00]); // 3 bytes + padding
        }
        body.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        body.extend_from_slice(&8u16.to_be_bytes());
        body.push(0x00);
        body.push(0x01);
        let xport = 54321u16 ^ (STUN_MAGIC_COOKIE >> 16) as u16;
        body.extend_from_slice(&xport.to_be_bytes());
        let xip = 0x0102_0304u32 ^ STUN_MAGIC_COOKIE;
        body.extend_from_slice(&xip.to_be_bytes());

        let mut resp = Vec::new();
        resp.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
        resp.extend_from_slice(&(body.len() as u16).to_be_bytes());
        resp.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        resp.extend_from_slice(tid);
        resp.extend_from_slice(&body);
        resp
    }

    #[test]
    fn padded_attribute_keeps_the_mapped_address_aligned() {
        let tid = [7u8; 12];
        let parsed = parse_binding_response(&success_response(&tid, true), &tid).unwrap();
        assert_eq!(parsed, "1.2.3.4:54321".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn truncated_and_misaligned_bodies_are_rejected() {
        let tid = [7u8; 12];
        let resp = success_response(&tid, false);
        assert!(matches!(
            parse_binding_response(&resp[..10], &tid),
            Err(StunError::InvalidHeader)
        ));
        // Claim more bytes than were actually received.
        let mut short = resp.clone();
        short.truncate(resp.len() - 4);
        assert!(matches!(
            parse_binding_response(&short, &tid),
            Err(StunError::InvalidHeader)
        ));
        // Message length is not a multiple of 4.
        let mut odd = resp.clone();
        odd[3] = 0x0d;
        assert!(matches!(
            parse_binding_response(&odd, &tid),
            Err(StunError::InvalidHeader)
        ));
    }

    #[test]
    fn binding_error_response_is_distinguished_from_a_timeout() {
        let tid = [7u8; 12];
        let mut resp = Vec::new();
        resp.extend_from_slice(&BINDING_ERROR_RESPONSE.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        resp.extend_from_slice(&tid);
        assert!(matches!(
            parse_binding_response(&resp, &tid),
            Err(StunError::ErrorResponse)
        ));
    }

    #[test]
    fn invalid_tid_rejected() {
        let tid_a: [u8; 12] = [1; 12];
        let tid_b: [u8; 12] = [2; 12];
        let mut resp = Vec::new();
        resp.extend_from_slice(&0x0101u16.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        resp.extend_from_slice(&tid_a);

        assert!(matches!(
            parse_binding_response(&resp, &tid_b),
            Err(StunError::InvalidHeader)
        ));
    }

    #[tokio::test]
    async fn loopback_mock_stun_server() {
        // Run mock STUN responder on port 0
        let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_socket.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            if let Ok((len, from)) = server_socket.recv_from(&mut buf).await {
                if len >= 20 {
                    let tid: [u8; 12] = buf[8..20].try_into().unwrap();
                    let mut resp = Vec::new();
                    resp.extend_from_slice(&0x0101u16.to_be_bytes());
                    resp.extend_from_slice(&12u16.to_be_bytes());
                    resp.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
                    resp.extend_from_slice(&tid);
                    // XOR-MAPPED-ADDRESS for IPv4
                    resp.extend_from_slice(&0x0020u16.to_be_bytes());
                    resp.extend_from_slice(&8u16.to_be_bytes());
                    resp.push(0x00);
                    resp.push(0x01);
                    let xport = from.port() ^ (STUN_MAGIC_COOKIE >> 16) as u16;
                    resp.extend_from_slice(&xport.to_be_bytes());
                    let ip_bytes = match from.ip() {
                        std::net::IpAddr::V4(v4) => v4.octets(),
                        _ => [127, 0, 0, 1],
                    };
                    let ip_num = u32::from_be_bytes(ip_bytes);
                    resp.extend_from_slice(&(ip_num ^ STUN_MAGIC_COOKIE).to_be_bytes());

                    let _ = server_socket.send_to(&resp, from).await;
                }
            }
        });

        let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_port = client_socket.local_addr().unwrap().port();
        let server_str = server_addr.to_string();

        let resolved = query_public_address(&client_socket, &[&server_str])
            .await
            .expect("Mock STUN should succeed");

        assert_eq!(
            resolved.ip(),
            "127.0.0.1".parse::<std::net::IpAddr>().unwrap()
        );
        assert_eq!(resolved.port(), client_port);
    }

    // ------------------------------------------------------------ NAT 行为探测
    //
    // 公网 NAT 的行为无法在 CI 里复现，但"服务器到底有没有换地址回包"是可以在本机
    // 精确构造的。这些用例全部对着本地 mock STUN 跑，断言的是**分类逻辑**，不是
    // 真实网络。

    /// Public endpoint the mock reports, deliberately not a loopback address so
    /// the open-internet short circuit does not swallow the probes.
    const PROBE_PUBLIC: &str = "203.0.113.9:40000";

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum MockReply {
        /// Answers every request from the primary socket, ignoring CHANGE-REQUEST.
        IgnoreChange,
        /// Answers CHANGE-REQUEST from a *second* socket on another port.
        HonorChange,
        /// Answers the first request only, then stays silent.
        SilentAfterFirst,
        /// Advertises an OTHER-ADDRESS it will actually answer on.
        AdvertiseOther,
    }

    fn attr_xor_mapped(addr: SocketAddr, tid: &[u8; 12]) -> Vec<u8> {
        let mut v = Vec::with_capacity(20);
        v.push(0);
        match addr {
            SocketAddr::V4(a) => {
                v.push(0x01);
                v.extend_from_slice(&(a.port() ^ (STUN_MAGIC_COOKIE >> 16) as u16).to_be_bytes());
                let ip = u32::from_be_bytes(a.ip().octets()) ^ STUN_MAGIC_COOKIE;
                v.extend_from_slice(&ip.to_be_bytes());
            }
            SocketAddr::V6(a) => {
                v.push(0x02);
                v.extend_from_slice(&(a.port() ^ (STUN_MAGIC_COOKIE >> 16) as u16).to_be_bytes());
                let mut key = [0u8; 16];
                key[..4].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
                key[4..].copy_from_slice(tid);
                for (i, byte) in a.ip().octets().iter().enumerate() {
                    v.push(byte ^ key[i]);
                }
            }
        }
        v
    }

    fn attr_sockaddr(addr: SocketAddr) -> Vec<u8> {
        let mut v = Vec::with_capacity(20);
        v.push(0);
        match addr {
            SocketAddr::V4(a) => {
                v.push(0x01);
                v.extend_from_slice(&a.port().to_be_bytes());
                v.extend_from_slice(&a.ip().octets());
            }
            SocketAddr::V6(a) => {
                v.push(0x02);
                v.extend_from_slice(&a.port().to_be_bytes());
                v.extend_from_slice(&a.ip().octets());
            }
        }
        v
    }

    fn push_attr(out: &mut Vec<u8>, kind: u16, value: &[u8]) {
        out.extend_from_slice(&kind.to_be_bytes());
        out.extend_from_slice(&(value.len() as u16).to_be_bytes());
        out.extend_from_slice(value);
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
    }

    fn build_mock_response(
        request: &[u8],
        mapped: SocketAddr,
        origin: Option<SocketAddr>,
        other: Option<SocketAddr>,
    ) -> Option<Vec<u8>> {
        if request.len() < 20 {
            return None;
        }
        let tid: [u8; 12] = request[8..20].try_into().ok()?;
        let mut body = Vec::new();
        push_attr(
            &mut body,
            ATTR_XOR_MAPPED_ADDRESS,
            &attr_xor_mapped(mapped, &tid),
        );
        if let Some(origin) = origin {
            push_attr(&mut body, ATTR_RESPONSE_ORIGIN, &attr_sockaddr(origin));
        }
        if let Some(other) = other {
            push_attr(&mut body, ATTR_OTHER_ADDRESS, &attr_sockaddr(other));
        }
        let mut resp = Vec::with_capacity(20 + body.len());
        resp.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
        resp.extend_from_slice(&(body.len() as u16).to_be_bytes());
        resp.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        resp.extend_from_slice(&tid);
        resp.extend_from_slice(&body);
        Some(resp)
    }

    fn has_change_request(buf: &[u8]) -> bool {
        if buf.len() < 20 {
            return false;
        }
        let end = (20 + u16::from_be_bytes([buf[2], buf[3]]) as usize).min(buf.len());
        let mut off = 20;
        while off + 4 <= end {
            let kind = u16::from_be_bytes([buf[off], buf[off + 1]]);
            let len = u16::from_be_bytes([buf[off + 2], buf[off + 3]]) as usize;
            if kind == ATTR_CHANGE_REQUEST {
                return true;
            }
            off += 4 + ((len + 3) & !3);
        }
        false
    }

    struct MockStun {
        primary: SocketAddr,
        /// Hits on the alternate endpoint. Used to prove OTHER-ADDRESS is
        /// probed as advertised instead of being rewritten.
        alt_hits: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    async fn spawn_mock(reply: MockReply) -> MockStun {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let primary = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let alt = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let primary_addr = primary.local_addr().unwrap();
        let alt_addr = alt.local_addr().unwrap();
        let alt_hits = Arc::new(AtomicUsize::new(0));
        let seen = Arc::new(AtomicUsize::new(0));

        // Primary responder.
        let alt_for_primary = alt.clone();
        let hits_for_primary = alt_hits.clone();
        let seen_primary = seen.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let Ok((n, from)) = primary.recv_from(&mut buf).await else {
                    break;
                };
                let request = &buf[..n];
                let count = seen_primary.fetch_add(1, Ordering::SeqCst);
                if reply == MockReply::SilentAfterFirst && count > 0 {
                    continue;
                }
                let mapped: SocketAddr = PROBE_PUBLIC.parse().unwrap();
                if reply == MockReply::HonorChange && has_change_request(request) {
                    if let Some(resp) = build_mock_response(request, mapped, Some(alt_addr), None) {
                        let _ = alt_for_primary.send_to(&resp, from).await;
                        hits_for_primary.fetch_add(1, Ordering::SeqCst);
                    }
                    continue;
                }
                let other = matches!(reply, MockReply::AdvertiseOther | MockReply::HonorChange)
                    .then_some(alt_addr);
                if let Some(resp) = build_mock_response(request, mapped, Some(primary_addr), other)
                {
                    let _ = primary.send_to(&resp, from).await;
                }
            }
        });

        // The advertised alternate endpoint answers plain binding requests, so a
        // correct implementation gets a real mapping answer from it.
        let alt_reader = alt.clone();
        let alt_hits_reader = alt_hits.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let Ok((n, from)) = alt_reader.recv_from(&mut buf).await else {
                    break;
                };
                let mapped: SocketAddr = PROBE_PUBLIC.parse().unwrap();
                let count = alt_hits_reader.fetch_add(1, Ordering::SeqCst);
                let _ = count;
                if let Some(resp) = build_mock_response(&buf[..n], mapped, Some(alt_addr), None) {
                    let _ = alt_reader.send_to(&resp, from).await;
                }
            }
        });

        MockStun {
            primary: primary_addr,
            alt_hits,
        }
    }

    async fn probe_against(reply: MockReply) -> (NatReport, MockStun) {
        let mock = spawn_mock(reply).await;
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = mock.primary.to_string();
        let report = probe_nat_behavior(&socket, &[server.as_str()])
            .await
            .expect("probe must complete against the mock");
        (report, mock)
    }

    /// A server that ignores CHANGE-REQUEST answers from its own address. That
    /// is **not** evidence of endpoint-independent filtering.
    #[tokio::test]
    async fn ignored_change_request_is_not_reported_as_full_cone() {
        let (report, _mock) = probe_against(MockReply::IgnoreChange).await;
        assert_ne!(
            report.filtering,
            NatFilteringBehavior::EndpointIndependent,
            "a reply from the server's primary address must not be read as Full Cone"
        );
        assert_ne!(report.classification(), NatClassification::FullCone);
    }

    /// Positive control: when the change really is honoured (reply from another
    /// port), the classification must still be Full Cone. Without this the test
    /// above would also pass if the classifier simply returned Unknown forever.
    #[tokio::test]
    async fn honoured_change_request_is_reported_as_full_cone() {
        let (report, mock) = probe_against(MockReply::HonorChange).await;
        assert_eq!(report.filtering, NatFilteringBehavior::EndpointIndependent);
        assert_eq!(report.classification(), NatClassification::FullCone);
        assert!(
            mock.alt_hits.load(std::sync::atomic::Ordering::SeqCst) > 0,
            "the alternate endpoint must have answered"
        );
    }

    /// A timeout is the *expected* signature of a restrictive NAT. Reporting it
    /// as endpoint-independent inverts the meaning of the measurement.
    #[tokio::test]
    async fn mapping_timeout_is_unknown_not_endpoint_independent() {
        let (report, _mock) = probe_against(MockReply::SilentAfterFirst).await;
        assert_eq!(
            report.mapping,
            NatMappingBehavior::Unknown,
            "a timed-out mapping probe proves nothing; it must not default to cone"
        );
    }

    /// OTHER-ADDRESS carries an IP *and* a port. Rewriting the port back to the
    /// primary one probes an endpoint that usually is not listening.
    #[tokio::test]
    async fn other_address_port_is_probed_as_advertised() {
        let (report, mock) = probe_against(MockReply::AdvertiseOther).await;
        assert!(
            mock.alt_hits.load(std::sync::atomic::Ordering::SeqCst) > 0,
            "the advertised OTHER-ADDRESS port must be probed verbatim"
        );
        assert_eq!(report.mapping, NatMappingBehavior::EndpointIndependent);
    }
}
