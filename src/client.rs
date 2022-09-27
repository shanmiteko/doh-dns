//! HTTPS client to query DoH servers.
use async_trait::async_trait;

use hyper::{
    client::{connect::dns::GaiResolver, HttpConnector},
    Body, Client, Request, Response, Result as HyperResult, Uri,
};
use hyper_tls::HttpsConnector;

/// Creates a `GET` request over the given `URI` and returns its response. It is used to
/// request data from DoH servers.
#[async_trait]
pub trait DnsClient: Default {
    async fn get(&self, uri: Uri) -> HyperResult<Response<Body>>;
}

/// Hyper-based DNS client over SSL and with a static resolver to resolve DNS server names
/// such as `dns.google` since Google does not accept request over `8.8.8.8` like Cloudflare
/// does over `1.1.1.1`.
pub struct HyperDnsClient {
    client: Client<HttpsConnector<HttpConnector<GaiResolver>>>,
}

impl Default for HyperDnsClient {
    fn default() -> HyperDnsClient {
        let mut http_connector = HttpConnector::new();
        http_connector.enforce_http(false);
        let mut connector = HttpsConnector::from((
            http_connector,
            native_tls::TlsConnector::new().unwrap().into(),
        ));
        connector.https_only(true);
        HyperDnsClient {
            client: Client::builder().build(connector),
        }
    }
}

#[async_trait]
impl DnsClient for HyperDnsClient {
    async fn get(&self, uri: Uri) -> HyperResult<Response<Body>> {
        // The reason to build a request manually is to set the Accept header required by
        // DNS servers.
        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .header("Accept", "application/dns-json")
            .body(Body::default())
            .expect("request builder");
        self.client.request(req).await
    }
}
