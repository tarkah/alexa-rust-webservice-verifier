# Alexa Rust Webservice Verifier

Verify that incoming requests are from Alexa for custom, webservice skills.

- [Documentation](https://docs.rs/alexa-verifier)
- [Developer Documentation](https://developer.amazon.com/docs/custom-skills/host-a-custom-skill-as-a-web-service.html#manually-verify-request-sent-by-alexa)

## About
- `RequestVerifier` caches certs on the first request
- Initialize with `RequestVerifier::new()`
- Method `verify() -> Result<(), Error>` returns `Ok` if verified successfully and `Error` if failed

```rust
    pub struct RequestVerifier {
        cert_cache: HashMap<String, Vec<u8>>,
    }

    impl Default for RequestVerifier {
        fn default() -> Self {
            RequestVerifier {
                cert_cache: HashMap::new(),
            }
        }
    }

    impl RequestVerifier {
        pub fn new() -> Self {
            RequestVerifier::default()
        }

        pub fn verify(
            &mut self,
            signature_cert_chain_url: &str,
            signature: &str,
            body: &[u8],
            timestamp: &str,
            timestamp_tolerance_millis: Option<u64>,
        ) -> Result<(), Error> { 
            ...
        }
    }
```

## Example using Rouille server and alexa_sdk

```rust
use crate::skill::process_request; // Entry point to custom skill
use alexa_verifier::RequestVerifier; // Struct provided by this crate
use log::{debug, error, info};
use rouille::{router, Request, Response};
use std::{
    io::Read,
    sync::{Mutex, MutexGuard},
};

fn note_routes(request: &Request, verifier: &mut MutexGuard<RequestVerifier>) -> Response {
    router!(request,
        (POST) (/) => {
            info!("Request received...");

            // Get request body data
            let mut body = request.data().unwrap();
            let mut body_bytes: Vec<u8> = vec![];
            body.read_to_end(&mut body_bytes).unwrap();

            // Get needed headers, default to blank (will cause verification to fail)
            let signature_cert_chain_url = request.header("SignatureCertChainUrl").unwrap_or("");
            let signature = request.header("Signature").unwrap_or("");

            // Deserialize using alexa_sdk::Request
            let _request = serde_json::from_slice::<alexa_sdk::Request>(&body_bytes); 
            if let Err(e) = _request {
                error!("Could not deserialize request");
                error!("{:?}", e);
                let response = Response::empty_400();
                info!("Sending back response...");
                debug!("{:?}", response);
                return response;
            }
            let request = _request.unwrap();
            debug!("{:?}", request);

            // alexa-verifier used here, return 400 if verification fails
            if verifier
                .verify(
                    signature_cert_chain_url,
                    signature,
                    &body_bytes,
                    request.body.timestamp.as_str(),
                    None
                ).is_err() {
                    error!("Could not validate request came from Alexa");
                    let response = Response::empty_400();
                    info!("Sending back response...");
                    debug!("{:?}", response);
                    return response;
                };
            debug!("Request is validated...");

            // Entry point to custom skill, returning alexa_sdk::Response
            let response = Response::json(&process_request(request));
            info!("Sending back response...");
            debug!("{:?}", response);
            response
    },
        _ => Response::empty_404()
    )
}

pub fn run() -> std::io::Result<()> {
    info!("Starting server on 0.0.0.0:8086");
    let verifier = Mutex::from(RequestVerifier::new());

    rouille::start_server("0.0.0.0:8086", move |request| {
        let mut verifier = verifier.lock().unwrap();
        note_routes(&request, &mut verifier)
    });
}
```
