use anyhow::anyhow;
use std::str::FromStr;

pub(crate) enum DIDMIMEType {
    JSON,
    CBOR,
}

impl FromStr for DIDMIMEType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, anyhow::Error> {
        match s {
            "application/json+did" => Ok(Self::JSON),
            // we don't directly support JSON-LD, but we should be able to consume it
            "application/jsonld+did" => Ok(Self::JSON),
            "application/cbor+did" => Ok(Self::CBOR),
            _ => Err(anyhow!("Invalid MIME type")),
        }
    }
}

impl ToString for DIDMIMEType {
    fn to_string(&self) -> String {
        match self {
            Self::JSON => "application/json+did",
            Self::CBOR => "application/cbor+did",
        }
        .to_string()
    }
}

pub(crate) enum ModifiedData {
    Modified(Vec<u8>),
    NotModified,
}
