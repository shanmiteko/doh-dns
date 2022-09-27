use crate::client::DnsClient;
use crate::error::{DnsError, QueryError};
use crate::status::RCode;
use crate::{Dns, DnsAnswer, DnsHttpsServer, DnsResponse};
use hyper::Uri;

use log::error;
use tokio::time::timeout;

impl<C: DnsClient, S: DnsHttpsServer> Dns<C, S> {
    /// Creates an instance with the given servers along with their respective timeouts
    /// (in seconds). These servers are tried in the given order. If a request fails on
    /// the first one, each subsequent server is tried. Only on certain failures a new
    /// request is retried such as a connection failure or certain server return codes.
    pub fn with_servers(servers: &[S]) -> Result<Self, DnsError> {
        if servers.is_empty() {
            return Err(DnsError::NoServers);
        }
        Ok(Dns {
            client: C::default(),
            servers: servers.to_vec(),
        })
    }

    /// Returns MX records in order of priority for the given name. It removes the priorities
    /// from the data.
    pub async fn resolve_mx_and_sort(&self, domain: &str) -> Result<Vec<DnsAnswer>, DnsError> {
        match self.client_request(domain, &RTYPE_mx).await {
            Err(e) => Err(DnsError::Query(e)),
            Ok(res) => match num::FromPrimitive::from_u32(res.Status) {
                Some(RCode::NoError) => {
                    let mut mxs = res
                        .Answer
                        .unwrap_or_default()
                        .iter()
                        .filter_map(|a| {
                            // Get only MX records.
                            if a.r#type == RTYPE_mx.0 {
                                // Get only the records that have a priority.
                                let mut parts = a.data.split_ascii_whitespace();
                                if let Some(part_1) = parts.next() {
                                    // Convert priority to an integer.
                                    if let Ok(priority) = part_1.parse::<u32>() {
                                        if let Some(mx) = parts.next() {
                                            // Change data from "priority name" -> "name".
                                            let mut m = a.clone();
                                            m.data = mx.to_string();
                                            return Some((m, priority));
                                        }
                                    }
                                }
                            }
                            None
                        })
                        .collect::<Vec<_>>();
                    // Order MX records by priority.
                    mxs.sort_unstable_by_key(|x| x.1);
                    Ok(mxs.into_iter().map(|x| x.0).collect())
                }
                Some(code) => Err(DnsError::Status(code)),
                None => Err(DnsError::Status(RCode::Unknown)),
            },
        }
    }

    // Generates the DNS over HTTPS request on the given name for rtype. It filters out
    // results that are not of the given rtype with the exception of `ANY`.
    async fn request_and_process(
        &self,
        name: &str,
        rtype: &Rtype,
    ) -> Result<Vec<DnsAnswer>, DnsError> {
        match self.client_request(name, rtype).await {
            Err(e) => Err(DnsError::Query(e)),
            Ok(res) => match num::FromPrimitive::from_u32(res.Status) {
                Some(RCode::NoError) => Ok(res
                    .Answer
                    .unwrap_or_default()
                    .into_iter()
                    // Get only the record types requested. There is only exception and that is
                    // the ANY record which has a value of 0.
                    .filter(|a| a.r#type == rtype.0 || rtype.0 == 0)
                    .collect::<Vec<_>>()),
                Some(code) => Err(DnsError::Status(code)),
                None => Err(DnsError::Status(RCode::Unknown)),
            },
        }
    }

    // Creates the HTTPS request to the server. In certain occasions, it retries to a new server
    // if one is available.
    async fn client_request(&self, name: &str, rtype: &Rtype) -> Result<DnsResponse, QueryError> {
        // Name has to be puny encoded.
        let name = match idna::domain_to_ascii(name) {
            Ok(name) => name,
            Err(e) => return Err(QueryError::InvalidName(format!("{:?}", e))),
        };
        let mut error = QueryError::Unknown;
        for server in self.servers.iter() {
            let url = format!("{}?name={}&type={}", server.uri(), name, rtype.1);
            let endpoint = match url.parse::<Uri>() {
                Err(e) => return Err(QueryError::InvalidEndpoint(e.to_string())),
                Ok(endpoint) => endpoint,
            };

            error = match timeout(server.timeout(), self.client.get(endpoint)).await {
                Ok(Err(e)) => QueryError::Connection(e.to_string()),
                Ok(Ok(res)) => {
                    match res.status().as_u16() {
                        200 => match hyper::body::to_bytes(res).await {
                            Err(e) => QueryError::ReadResponse(e.to_string()),
                            Ok(body) => match serde_json::from_slice::<DnsResponse>(&body) {
                                Err(e) => QueryError::ParseResponse(e.to_string()),
                                Ok(res) => {
                                    return Ok(res);
                                }
                            },
                        },
                        400 => return Err(QueryError::BadRequest400),
                        413 => return Err(QueryError::PayloadTooLarge413),
                        414 => return Err(QueryError::UriTooLong414),
                        415 => return Err(QueryError::UnsupportedMediaType415),
                        501 => return Err(QueryError::NotImplemented501),
                        // If the following errors occur, the request will be retried on
                        // the next server if one is available.
                        429 => QueryError::TooManyRequests429,
                        500 => QueryError::InternalServerError500,
                        502 => QueryError::BadGateway502,
                        504 => QueryError::ResolverTimeout504,
                        _ => QueryError::Unknown,
                    }
                }
                Err(_) => QueryError::Connection(format!(
                    "connection timeout after {:?}",
                    server.timeout()
                )),
            };
            error!("request error on URL {}: {}", url, error);
        }
        Err(error)
    }
}

struct Rtype(pub u32, pub &'static str);

macro_rules! rtypes {
    (
        $(
            $(#[$docs:meta])*
            ($konst:ident, $num:expr);
        )+
    ) => {
        paste::item! {
            impl<C: DnsClient, S: DnsHttpsServer> Dns<C, S> {
                $(
                    $(#[$docs])*
                    pub async fn [<resolve_ $konst>](&self, name: &str) -> Result<Vec<DnsAnswer>, DnsError> {
                        self.request_and_process(name, &[<RTYPE_ $konst>]).await
                    }
                )+

                pub async fn resolve_str_type(&self, name: &str, rtype: &str) -> Result<Vec<DnsAnswer>, DnsError> {
                    match rtype.to_ascii_lowercase().as_ref() {
                        $(
                        stringify!($konst) => self.[<resolve_ $konst>](name).await,
                        )+
                        _ => Err(DnsError::InvalidRecordType),
                    }
                }

                /// Converts the given record type to a string representation.
                pub fn rtype_to_name(&self, rtype: u32) -> String {
                    let name = match rtype {
                        $(
                        $num => stringify!($konst),
                        )+
                        _ => "unknown",
                    };
                    name.to_ascii_uppercase()
                }
            }
        $(
            #[allow(non_upper_case_globals)]
            const [<RTYPE_ $konst>]: Rtype = Rtype($num, stringify!($konst));
        )+
        }
    }
}

// The following types were obtained from the following address:
// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
rtypes! {
    /// Queries a host address for the given name.
    (a, 1);
    /// Queries an IP6 Address for the given name.
    (aaaa, 28);
    /// Queries all record types for a given name.
    (any, 0);
    /// Queries a certification authority restriction record for the given name.
    (caa, 257);
    /// Queries a child DS record for the given name.
    (cds, 59);
    /// Queries a CERT record for the given name.
    (cert, 37);
    /// Queries the canonical name for an alias for the given name.
    (cname, 5);
    /// Queries a DNAME record for the given name.
    (dname, 39);
    /// Queries a DNSKEY record for the given name.
    (dnskey, 48);
    /// Queries a delegation signer record for the given name.
    (ds, 43);
    /// Queries a host information record for the given name.
    (hinfo, 13);
    /// Queries a IPSECKEY record for the given name.
    (ipseckey, 45);
    /// Queries a mail exchange record for the given name.
    (mx, 15);
    /// Queries a naming authority pointer record for the given name.
    (naptr, 35);
    /// Queries an authoritative name server record for the given name.
    (ns, 2);
    /// Queries a NSEC record for the given name.
    (nsec, 47);
    /// Queries a NSEC3 record for the given name.
    (nsec3, 50);
    /// Queries a NSEC3PARAM record for the given name.
    (nsec3param, 51);
    /// Queries a domain name pointer record for the given name.
    (ptr, 12);
    /// Queries a responsible person record for the given name.
    (rp, 17);
    /// Queries a RRSIG record for the given name.
    (rrsig, 46);
    /// Queries the start of a zone of authority record for the given name.
    (soa, 6);
    /// Queries an SPF record for the given name. See RFC7208.
    (spf, 99);
    /// Queries a server selection record for the given name.
    (srv, 33);
    /// Queries an SSH key fingerprint record for the given name.
    (sshfp, 44);
    /// Queries a TLSA record for the given name.
    (tlsa, 52);
    /// Queries a text strings record for the given name.
    (txt, 16);
    /// Queries a well known service description record for the given name.
    (wks, 11);
}
