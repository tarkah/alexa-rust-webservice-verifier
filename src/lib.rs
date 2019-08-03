use failure::{bail, Error, Fail, ResultExt};
use std::collections::HashMap;
use std::io::Cursor;
use std::path::Path;
use url::{Host, Url};
use x509_parser::objects::Nid;
use x509_parser::pem::Pem;

mod normalize;

const CERT_CHAIN_URL_SCHEME: &str = "https";
const CERT_CHAIN_URL_HOSTNAME: &str = "s3.amazonaws.com";
const CERT_CHAIN_URL_STARTPATH: &str = "/echo.api/";
const CERT_CHAIN_URL_PORT: u16 = 443;
const CERT_CHAIN_DOMAIN: &str = "echo-api.amazon.com";
const DEFAULT_TIMESTAMP_TOLERANCE_IN_MILLIS: u64 = 150_000;
const MAX_TIMESTAMP_TOLERANCE_IN_MILLIS: u64 = 3_600_000;

#[derive(Debug, Fail)]
pub enum VerificationError {
    #[fail(display = "Failed to validate URL")]
    ValidateUrl,
    #[fail(display = "Failed to retreive cert")]
    RetrieveCert,
    #[fail(display = "Failed to decode PEM")]
    PemParse,
    #[fail(display = "Failed to parse certificate to x509")]
    CertParse,
    #[fail(display = "Failed to parse certificate to x509")]
    DerParse,
    #[fail(display = "No valid data in SAN extension")]
    SanExtension,
    #[fail(display = "Cert missing from cache")]
    MissingCertCache,
    #[fail(display = "Signing Certificate expired")]
    ExpiredCert,
    #[fail(display = "'echo-api.amazon.com' not in SAN extension")]
    DomainNotInSan,
    #[fail(display = "Expecting 'https', got '{}'", scheme)]
    UrlScheme { scheme: String },
    #[fail(display = "Expecting 's3.amazonaws.com', got '{}'", hostname)]
    UrlHostname { hostname: String },
    #[fail(display = "Expecting '/echo.api/', got '{}'", path)]
    UrlPath { path: String },
    #[fail(display = "Expecting '443', got '{}'", port)]
    UrlPort { port: u16 },
}

pub struct RequestVerifier {
    cert_cache: HashMap<String, Pem>,
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
        signature_cert_chain_url: String,
        signature: String,
    ) -> Result<(), Error> {
        self.retrieve_and_validate_cert(signature_cert_chain_url)?;

        Ok(())
    }

    fn retrieve_and_validate_cert(
        &mut self,
        signature_cert_chain_url: String,
    ) -> Result<(), Error> {
        validate_cert_url(&signature_cert_chain_url)?;

        if !self.cert_cache.contains_key(&signature_cert_chain_url) {
            self.retrieve_cert(&signature_cert_chain_url)
                .context(VerificationError::RetrieveCert)?;
        }

        let pem = self
            .cert_cache
            .get(&signature_cert_chain_url)
            .ok_or(VerificationError::MissingCertCache)?;
        let certificate = pem.parse_x509().map_err(|_| VerificationError::CertParse)?;

        let not_before = certificate.tbs_certificate.validity.not_before;
        let not_after = certificate.tbs_certificate.validity.not_after;
        let now_utc = time::now_utc();
        if now_utc < not_before || now_utc > not_after {
            bail!(VerificationError::ExpiredCert)
        }

        let mut sans: Vec<&str> = Vec::new();
        for ext in &certificate.tbs_certificate.extensions {
            if ext.oid == x509_parser::objects::nid2obj(&Nid::SubjectAltName).unwrap() {
                let (_, ber) =
                    der_parser::parse_der(&ext.value).map_err(|_| VerificationError::DerParse)?;
                for b in ber.into_iter() {
                    if let der_parser::ber::BerObjectContent::Unknown(_, i) = b.content {
                        sans.push(std::str::from_utf8(i).context(VerificationError::SanExtension)?)
                    } else {
                        bail!(VerificationError::SanExtension)
                    }
                }
            }
        }
        if !sans.contains(&CERT_CHAIN_DOMAIN) {
            bail!(VerificationError::DomainNotInSan)
        }

        let pkey = certificate
            .tbs_certificate
            .subject_pki
            .subject_public_key
            .data;

        validate_request_body(signature_cert_chain_url, String::from(""), pkey)?;

        Ok(())
    }

    fn retrieve_cert(&mut self, signature_cert_chain_url: &str) -> Result<(), Error> {
        let mut resp = reqwest::get(signature_cert_chain_url)?;
        let mut buf: Vec<u8> = vec![];
        resp.copy_to(&mut buf)?;

        let (pem, _) = Pem::read(Cursor::new(buf)).map_err(|_| VerificationError::PemParse)?;
        let _ = self
            .cert_cache
            .insert(signature_cert_chain_url.to_string(), pem);

        Ok(())
    }
}

fn validate_cert_url(signature_cert_chain_url: &str) -> Result<(), Error> {
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

fn validate_request_body(signature: String, body: String, pkey: &[u8]) -> Result<(), Error> {
    unimplemented!();
    let decoded_signature = base64::decode(&signature)?;


    Ok(())
}
