use failure::{Error, Fail};
use log::error;

/// Error detailing why verification failed
#[derive(Debug, Fail)]
pub enum VerificationError {
    #[fail(display = "Failed to retreive cert")]
    RetrieveCert,
    #[fail(display = "Failed to decode PEM")]
    PemParse,
    #[fail(display = "Failed to parse certificate to x509")]
    CertParse,
    #[fail(display = "Failed to parse x509 extension")]
    CertExtParse,
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
    #[fail(display = "Could not parse timestamp into DateTime: '{}'", timestamp)]
    TimestampParse { timestamp: String },
    #[fail(
        display = "Provided tolerance of '{}' exceeds max of 3_600_000",
        millis
    )]
    TimestampMax { millis: i64 },
    #[fail(display = "Timestamp verification failed")]
    Timestamp,
}

pub fn log_error(e: Error) -> Result<(), Error> {
    error!("{}", e);
    for cause in e.iter_causes() {
        error!("Caused by: {}", cause);
    }
    Err(e)
}
