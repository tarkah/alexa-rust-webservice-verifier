//! Verify that incoming requests are from Alexa for custom, webservice skills.  
//!
//! - Confirmed working with the Alexa [certification functional test](https://developer.amazon.com/docs/devconsole/test-and-submit-your-skill.html).
//!
//! - Built using the [Developer Documentation](https://developer.amazon.com/docs/custom-skills/host-a-custom-skill-as-a-web-service.html#manually-verify-request-sent-by-alexa)
//! and [Python Alexa SDK](https://github.com/alexa/alexa-skills-kit-sdk-for-python/tree/master/ask-sdk-webservice-support)
//! as reference.
//!
//! # Features
//! Both sync and async clients are provided by default. These are behind feature
//! flags `sync` or `async`, respectively.
//!
//! - `sync` provides `RequestVerifier` client
//! - `async` provides `RequestVerifierAsync` client
//!
//! # Using
//! Example using [Rouille](https://github.com/tomaka/rouille) server
//! and [alexa_sdk](https://github.com/tarkah/alexa_rust) for request deserialization
//!
//! ```rust
//! use crate::skill::process_request; // Entry point to custom skill
//! use alexa_verifier::RequestVerifier; // Struct provided by this crate
//! use log::{debug, error, info};
//! use rouille::{router, Request, Response};
//! use std::{
//!     io::Read,
//!     sync::{Mutex, MutexGuard},
//! };
//!
//! fn note_routes(request: &Request, verifier: &mut MutexGuard<RequestVerifier>) -> Response {
//!     router!(request,
//!         (POST) (/) => {
//!             info!("Request received...");
//!
//!             // Get request body data
//!             let mut body = request.data().unwrap();
//!             let mut body_bytes: Vec<u8> = vec![];
//!             body.read_to_end(&mut body_bytes).unwrap();
//!
//!             // Get needed headers, default to blank (will cause verification to fail)
//!             let signature_cert_chain_url = request.header("SignatureCertChainUrl").unwrap_or("");
//!             let signature = request.header("Signature").unwrap_or("");
//!
//!             // Deserialize using alexa_sdk::Request
//!             let _request = serde_json::from_slice::<alexa_sdk::Request>(&body_bytes);
//!             if let Err(e) = _request {
//!                 error!("Could not deserialize request");
//!                 error!("{:?}", e);
//!                 let response = Response::empty_400();
//!                 info!("Sending back response...");
//!                 debug!("{:?}", response);
//!                 return response;
//!             }
//!             let request = _request.unwrap();
//!             debug!("{:?}", request);
//!
//!             // alexa-verifier used here, return 400 if verification fails
//!             if verifier
//!                 .verify(
//!                     signature_cert_chain_url,
//!                     signature,
//!                     &body_bytes,
//!                     request.body.timestamp.as_str(),
//!                     None
//!                 ).is_err() {
//!                     error!("Could not validate request came from Alexa");
//!                     let response = Response::empty_400();
//!                     info!("Sending back response...");
//!                     debug!("{:?}", response);
//!                     return response;
//!                 };
//!             debug!("Request is validated...");
//!
//!             // Entry point custom to skill, returning alexa_sdk::Response
//!             let response = Response::json(&process_request(request));
//!             info!("Sending back response...");
//!             debug!("{:?}", response);
//!             response
//!     },
//!         _ => Response::empty_404()
//!     )
//! }
//!
//! pub fn run() -> std::io::Result<()> {
//!     info!("Starting server on 0.0.0.0:8086");
//!     let verifier = Mutex::from(RequestVerifier::new());
//!
//!     rouille::start_server("0.0.0.0:8086", move |request| {
//!         let mut verifier = verifier.lock().unwrap();
//!         note_routes(&request, &mut verifier)
//!     });
//! }
//! ```
//!

mod constants;
mod error;
mod normalize;

#[cfg(feature = "sync")]
mod sync;
pub use sync::RequestVerifier;

#[cfg(feature = "async")]
mod r#async;
pub use r#async::RequestVerifierAsync;
