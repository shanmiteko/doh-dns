//! Library to make DNS over HTTPS requests.
//!
//! This DNS over HTTPS (DoH) library queries public DoH servers provided by Google and
//! Clouflare. It is based on `async/await` with the help of `hyper` and `tokio`.
//!
//! The library supports timeouts and retries which can be fully customized. A utility
//! is provided in this crate to use this library in the command line.
//!
//! # Quick Start
//!
//! To quickly get started, a default client can be created with `Dns:default` and
//! `A` records can be queried using [Dns::resolve_a]. The default resolvers use Google
//! first with a timeout of 3 seconds and Clouflare second with a timeout of 10 seconds.
//! *Note: Cloudlare does not support queries for `ANY` records. You can use the Google
//! resolver for that.
//!
//! # Example
//! ```
//! use doh_dns::{client::HyperDnsClient, Dns, DnsHttpsServer};
//! use std::time::Duration;
//! use tokio;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // The following sets up the main DoH server to be Google with a default timeout
//!     // of 2 seconds. If a retry is needed, the Cloudflare's 1.1.1.1 server is used.
//!     // Alternatively, the default server setup can be used with:
//!     // let dns = Dns::default();
//!     let dns: Dns<HyperDnsClient> = Dns::with_servers(&[
//!         DnsHttpsServer::Google(Duration::from_secs(2)),
//!         DnsHttpsServer::Cloudflare1_1_1_1(Duration::from_secs(10)),
//!     ])
//!     .unwrap();
//!     match dns.resolve_a("memo.com").await {
//!         Ok(responses) => {
//!             if responses.is_empty() {
//!                 println!("No entries found.");
//!             } else {
//!                 for res in responses {
//!                     println!(
//!                         "name: {}, type: {}, TTL: {}, data: {}",
//!                         res.name,
//!                         dns.rtype_to_name(res.r#type),
//!                         res.TTL,
//!                         res.data
//!                     );
//!                 }
//!             }
//!         }
//!         Err(err) => println!("Error: {}", err),
//!     }
//!     Ok(())
//! }
//! ```
//!
//! # Logging
//! This library uses the `log` crate to log errors during retries. Please see that create
//! on methods on display such errors. If no logger is setup, nothing will be logged.
#![feature(proc_macro_hygiene)]
#![feature(stmt_expr_attributes)]
pub mod client;
mod dns;
pub mod error;
pub mod status;
#[macro_use]
extern crate serde_derive;
extern crate num;
#[macro_use]
extern crate num_derive;
use std::time::Duration;

/// The data associated for requests returned by the DNS over HTTPS servers.
#[allow(non_snake_case)]
#[derive(Deserialize, Debug, Serialize, Clone)]
pub struct DnsAnswer {
    /// The name of the record.
    pub name: String,
    /// The type associated with each record. To convert to a string representation use
    /// [Dns::rtype_to_name].
    pub r#type: u32,
    /// The time to live in seconds for this record.
    pub TTL: u32,
    /// The data associated with the record.
    pub data: String,
}

#[allow(non_snake_case)]
#[derive(Deserialize, Debug, Serialize)]
struct DnsResponse {
    Status: u32,
    Answer: Option<Vec<DnsAnswer>>,
    Comment: Option<String>,
}

pub trait DnsHttpsServer: Clone {
    fn uri(&self) -> &str;
    fn timeout(&self) -> Duration;
}

/// The main interface to this library. It provides all functions to query records.
pub struct Dns<C: client::DnsClient, S: DnsHttpsServer> {
    client: C,
    servers: Vec<S>,
}
