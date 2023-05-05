#![allow(dead_code)]
use anyhow::anyhow;
use base64::engine::{general_purpose::URL_SAFE_NO_PAD, Engine};
use did_toolkit::prelude::*;
use josekit::{
    jwk::{alg::ec::EcCurve, Jwk},
    jws::{alg::ecdsa::EcdsaJwsAlgorithm, serialize_compact, JwsHeader},
};
use serde::Serialize;
use std::{path::PathBuf, str::FromStr, time::SystemTime};

const ROOT_DID: &str = "fan.did";

pub enum DIDMIMEType {
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

#[inline]
fn jwk_alg_to_signing_alg(alg: EcCurve) -> EcdsaJwsAlgorithm {
    match alg {
        EcCurve::P256 => EcdsaJwsAlgorithm::Es256,
        EcCurve::P384 => EcdsaJwsAlgorithm::Es384,
        EcCurve::P521 => EcdsaJwsAlgorithm::Es512,
        EcCurve::Secp256k1 => EcdsaJwsAlgorithm::Es256k,
    }
}

// TODO: convince josekit to provide this method
#[inline]
fn jwk_alg_from_str(s: &str) -> Result<EcCurve, anyhow::Error> {
    match s {
        "P-256" => Ok(EcCurve::P256),
        "P-384" => Ok(EcCurve::P384),
        "P-521" => Ok(EcCurve::P521),
        "secp256k1" => Ok(EcCurve::Secp256k1),
        _ => Err(anyhow!("Invalid algorithm specified")),
    }
}

#[derive(Serialize)]
pub struct SignedPayload<'a> {
    payload: &'a [u8],
    content_type: &'a str,
}

pub enum ModifiedData {
    Modified(Vec<u8>),
    NotModified,
}

pub trait StorageDriver {
    fn load(&self, name: &str) -> Result<(Document, SystemTime), anyhow::Error>;
    fn load_root(&self) -> Result<(Document, SystemTime), anyhow::Error>;
}

pub struct Storage<SD: StorageDriver> {
    driver: SD,
    signing_key: Jwk,
}

impl<SD: StorageDriver> Storage<SD> {
    pub fn fetch_root(
        &self,
        if_modified_since: SystemTime,
        mime: &str,
    ) -> Result<ModifiedData, anyhow::Error> {
        match self.driver.load_root() {
            Ok((doc, time)) => match if_modified_since.duration_since(time) {
                Ok(_) => {
                    let mut writer = std::io::Cursor::new(Vec::new());

                    match DIDMIMEType::from_str(mime)? {
                        DIDMIMEType::CBOR => {
                            ciborium::ser::into_writer(&doc, &mut writer)?;
                        }
                        DIDMIMEType::JSON => {
                            serde_json::to_writer(&mut writer, &doc)?;
                        }
                    }

                    let res = writer.into_inner();

                    Ok(ModifiedData::Modified(res))
                }
                Err(_) => Ok(ModifiedData::NotModified),
            },
            Err(e) => Err(e.into()),
        }
    }

    pub fn fetch(
        &self,
        name: &str,
        if_modified_since: SystemTime,
        mime: &str,
    ) -> Result<ModifiedData, anyhow::Error> {
        match self.driver.load(name) {
            Ok((doc, time)) => match if_modified_since.duration_since(time) {
                Ok(_) => {
                    let alg = jwk_alg_to_signing_alg(jwk_alg_from_str(
                        self.signing_key.algorithm().map_or_else(
                            || Err(anyhow!("Invalid algorithm specified")),
                            |s| Ok(s),
                        )?,
                    )?);

                    let mut header = JwsHeader::new();
                    header.set_algorithm(alg.to_string());

                    let mut writer = std::io::Cursor::new(Vec::new());

                    match DIDMIMEType::from_str(mime)? {
                        DIDMIMEType::JSON => {
                            serde_json::to_writer(
                                &mut writer,
                                &SignedPayload {
                                    payload: URL_SAFE_NO_PAD
                                        .encode(serde_json::json!(doc).to_string())
                                        .as_bytes(),
                                    content_type: &DIDMIMEType::JSON.to_string(),
                                },
                            )?;
                        }
                        DIDMIMEType::CBOR => {
                            let mut inner = std::io::Cursor::new(Vec::new());
                            ciborium::ser::into_writer(&doc, &mut inner)?;
                            let buf = inner.into_inner();
                            let buf = URL_SAFE_NO_PAD.encode(&buf);

                            let payload = SignedPayload {
                                payload: buf.as_bytes(),
                                content_type: &DIDMIMEType::CBOR.to_string(),
                            };

                            ciborium::ser::into_writer(&payload, &mut writer)?;
                        }
                    }

                    Ok(ModifiedData::Modified(
                        serialize_compact(
                            &writer.into_inner(),
                            &header,
                            &alg.signer_from_jwk(&self.signing_key)?,
                        )?
                        .as_bytes()
                        .to_vec(),
                    ))
                }
                Err(_) => Ok(ModifiedData::NotModified),
            },
            Err(e) => Err(e.into()),
        }
    }
}

pub struct FileSystemStorage<'a> {
    root: &'a str,
    cbor: bool,
}

impl FileSystemStorage<'_> {
    fn load_doc(&self, path: PathBuf) -> Result<(Document, SystemTime), anyhow::Error> {
        let f = std::fs::OpenOptions::new();
        let io = f.open(path)?;
        let meta = io.metadata()?;

        let doc: Document = if self.cbor {
            ciborium::de::from_reader(io)?
        } else {
            serde_json::from_reader(io)?
        };

        let modified = meta.modified()?;

        Ok((doc, modified))
    }
}

impl StorageDriver for FileSystemStorage<'_> {
    fn load_root(&self) -> Result<(Document, SystemTime), anyhow::Error> {
        let path = PathBuf::from(self.root).join("/".to_string() + ROOT_DID);
        self.load_doc(path)
    }

    fn load(&self, name: &str) -> Result<(Document, SystemTime), anyhow::Error> {
        if name.contains(std::path::MAIN_SEPARATOR) {
            return Err(anyhow!("name contains invalid characters"));
        }

        let path = PathBuf::from(self.root).join(&format!(
            "{}user{}{}.did",
            std::path::MAIN_SEPARATOR,
            std::path::MAIN_SEPARATOR,
            name
        ));

        self.load_doc(path)
    }
}
