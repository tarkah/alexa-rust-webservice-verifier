use crate::{
    constants::*,
    error::{log_error, VerificationError},
    normalize,
};
use failure::{bail, Error, ResultExt};
use std::{collections::HashMap, path::Path, sync::Mutex};
use time::Duration;
use url::{Host, Url};
use x509_parser::objects::Nid;

/// Exposes verify method and caches new certificates synchronously on the first request
pub struct RequestVerifier {
    cert_cache: Mutex<HashMap<String, Vec<u8>>>,
}

/// ```rust
/// impl Default for RequestVerifier {
///     fn default() -> Self {
///         RequestVerifier {
///             cert_cache: Mutex::new(HashMap::new()),
///         }
///     }
/// }
/// ```
impl Default for RequestVerifier {
    fn default() -> Self {
        RequestVerifier {
            cert_cache: Mutex::new(HashMap::new()),
        }
    }
}

impl RequestVerifier {
    /// Create default instance with an empty cache
    pub fn new() -> Self {
        RequestVerifier::default()
    }

    /// Verify that the request came from Alexa.  
    ///
    /// - `SignatureCertChainUrl` and `Signature` are headers of the request
    ///
    /// - Pass the entire body of the request for signature verification
    ///
    /// - Timestamp comes from the body, `{ "request" : { "timestamp": "" } }`. If deserialized using [alexa_sdk](https://github.com/tarkah/alexa_rust) then timestamp can be taken from `alexa_sdk::Request.body.timestamp`
    ///
    /// - A tolerance value in milliseconds can be passed to verify the request was received within that tolerance (default is `150_000`)
    pub fn verify(
        &self,
        signature_cert_chain_url: &str,
        signature: &str,
        body: &[u8],
        timestamp: &str,
        timestamp_tolerance_millis: Option<u64>,
    ) -> Result<(), Error> {
        if let Err(e) = self.retrieve_and_validate_cert(signature_cert_chain_url, signature, body) {
            log_error(e)?;
        };

        if let Err(e) = self.validate_timestamp(timestamp, timestamp_tolerance_millis) {
            log_error(e)?;
        };

        Ok(())
    }

    fn retrieve_and_validate_cert(
        &self,
        signature_cert_chain_url: &str,
        signature: &str,
        body: &[u8],
    ) -> Result<(), Error> {
        // First, validate cert url
        self.validate_cert_url(&signature_cert_chain_url)?;

        // Look for certificate in cache, if not, download using validated url
        let mut not_exists = false;
        if !self
            .cert_cache
            .lock()
            .unwrap()
            .contains_key(&signature_cert_chain_url.to_string())
        {
            not_exists = true;
            self.retrieve_cert(&signature_cert_chain_url)
                .context(VerificationError::RetrieveCert)?;
        }

        // Get certificate from cache (shouldn't fail), convert from pem to der,
        // then parse as x509
        let cert_cache = self.cert_cache.lock().unwrap();
        let pem_bytes = cert_cache
            .get(&signature_cert_chain_url.to_string())
            .ok_or(VerificationError::MissingCertCache)?;
        let (_, pem) =
            x509_parser::pem::pem_to_der(pem_bytes).map_err(|_| VerificationError::PemParse)?;
        drop(cert_cache);
        let certificate = pem.parse_x509().map_err(|_| VerificationError::CertParse)?;

        // Make sure cert is not expired
        let not_before = certificate.tbs_certificate.validity.not_before;
        let not_after = certificate.tbs_certificate.validity.not_after;
        let now_utc = time::now_utc();
        if now_utc < not_before || now_utc > not_after {
            bail!(VerificationError::ExpiredCert)
        }

        // Make sure domain is in SAN extension
        // Only need to validate first time cert is downloaded
        if not_exists {
            let mut sans: Vec<&str> = Vec::new();
            for ext in &certificate.tbs_certificate.extensions {
                if ext.oid == x509_parser::objects::nid2obj(&Nid::SubjectAltName).unwrap() {
                    let (_, ber) = der_parser::parse_der(&ext.value)
                        .map_err(|_| VerificationError::CertExtParse)?;
                    for b in ber.into_iter() {
                        if let der_parser::ber::BerObjectContent::Unknown(_, i) = b.content {
                            sans.push(
                                std::str::from_utf8(i).context(VerificationError::SanExtension)?,
                            )
                        } else {
                            bail!(VerificationError::SanExtension)
                        }
                    }
                }
            }
            if !sans.contains(&CERT_CHAIN_DOMAIN) {
                bail!(VerificationError::DomainNotInSan)
            }
        }

        // Get primary key for signature verification
        let pkey = certificate
            .tbs_certificate
            .subject_pki
            .subject_public_key
            .data;

        // Parses the public key and verifies signature is a valid signature of message using it.
        self.validate_request_body(signature, body, pkey)?;

        Ok(())
    }

    fn retrieve_cert(&self, signature_cert_chain_url: &str) -> Result<(), Error> {
        // Get cert using validated SignatureCertChainUrl
        let mut resp = reqwest::blocking::get(signature_cert_chain_url)?;
        let mut buf: Vec<u8> = vec![];
        resp.copy_to(&mut buf)?;

        // Add to cert cache
        let _ = self
            .cert_cache
            .lock()
            .unwrap()
            .insert(signature_cert_chain_url.to_string(), buf);

        Ok(())
    }

    fn validate_cert_url(&self, signature_cert_chain_url: &str) -> Result<(), Error> {
        let parsed_url = Url::parse(signature_cert_chain_url)?;

        let scheme = parsed_url.scheme();
        if scheme != CERT_CHAIN_URL_SCHEME {
            bail!(VerificationError::UrlScheme {
                scheme: scheme.to_string()
            })
        }

        if let Some(hostname) = parsed_url.host() {
            match hostname {
                Host::Domain(hostname) => {
                    if hostname.to_lowercase() != CERT_CHAIN_URL_HOSTNAME {
                        bail!(VerificationError::UrlHostname {
                            hostname: hostname.to_string()
                        });
                    }
                }
                Host::Ipv4(ip) => bail!(VerificationError::UrlHostname {
                    hostname: format!("{}", ip)
                }),
                Host::Ipv6(ip) => bail!(VerificationError::UrlHostname {
                    hostname: format!("{}", ip)
                }),
            }
        } else {
            bail!(VerificationError::UrlHostname {
                hostname: "".to_string()
            })
        }

        let path = Path::new(parsed_url.path());
        let normalized_path = normalize::normalize_path(&path);
        if !normalized_path.starts_with(CERT_CHAIN_URL_STARTPATH) {
            bail!(VerificationError::UrlPath {
                path: format!("{}", normalized_path.display())
            })
        }

        if let Some(port) = parsed_url.port() {
            if port != CERT_CHAIN_URL_PORT {
                bail!(VerificationError::UrlPort { port })
            }
        }

        Ok(())
    }

    fn validate_request_body(
        &self,
        signature: &str,
        body: &[u8],
        pkey_bytes: &[u8],
    ) -> Result<(), Error> {
        let decoded_signature = base64::decode(&signature)?;

        let pkey = ring::signature::UnparsedPublicKey::new(
            &ring::signature::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
            pkey_bytes,
        );

        pkey.verify(body, &decoded_signature)?;

        Ok(())
    }

    fn validate_timestamp(
        &self,
        timestamp: &str,
        timestamp_tolerance_millis: Option<u64>,
    ) -> Result<(), Error> {
        // If no tolerance is provided, use DEFAULT
        let tolerance_millis = {
            if let Some(t) = timestamp_tolerance_millis {
                Duration::milliseconds(t as i64)
            } else {
                Duration::milliseconds(DEFAULT_TIMESTAMP_TOLERANCE_IN_MILLIS)
            }
        };

        // Make sure tolerance is not higher than max allowed by Alexa
        if tolerance_millis > Duration::milliseconds(MAX_TIMESTAMP_TOLERANCE_IN_MILLIS) {
            bail!(VerificationError::TimestampMax {
                millis: tolerance_millis.num_milliseconds()
            });
        }

        // Timestamp is in ISO 8601 format
        let timestamp =
            time::strptime(timestamp, "%FT%TZ").context(VerificationError::TimestampParse {
                timestamp: timestamp.to_owned(),
            })?;
        let utc_now = time::now_utc();

        // Ensure request received within tolerance milliseconds
        let duration_between = utc_now - timestamp;
        if duration_between > tolerance_millis {
            bail!(VerificationError::Timestamp);
        };

        Ok(())
    }
}
