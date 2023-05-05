#![allow(dead_code)]
use crate::mime::{DIDMIMEType, ModifiedData};
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
pub(crate) struct SignedPayload<'a> {
    payload: &'a [u8],
    content_type: &'a str,
}

pub(crate) trait StorageDriver {
    fn load_user(&self, name: &str) -> Result<(Document, SystemTime), anyhow::Error>;
    fn load_root(&self) -> Result<(Document, SystemTime), anyhow::Error>;
}

#[derive(Clone)]
pub(crate) struct Storage<SD: StorageDriver + Clone + Send + ?Sized> {
    pub driver: Box<SD>,
    pub signing_key: Jwk,
}

impl<SD: StorageDriver + Clone + Send + ?Sized> Storage<SD> {
    fn encode_root(&self, doc: Document, mime: &str) -> Result<ModifiedData, anyhow::Error> {
        let mut writer = std::io::Cursor::new(Vec::new());

        match DIDMIMEType::from_str(mime)? {
            DIDMIMEType::CBOR => {
                ciborium::ser::into_writer(&doc, &mut writer)?;
            }
            DIDMIMEType::JSON => {
                serde_json::to_writer(&mut writer, &doc)?;
            }
        }

        Ok(ModifiedData::Modified(writer.into_inner()))
    }

    fn encode_user(&self, doc: Document, mime: &str) -> Result<ModifiedData, anyhow::Error> {
        let alg = jwk_alg_to_signing_alg(jwk_alg_from_str(
            self.signing_key
                .algorithm()
                .map_or_else(|| Err(anyhow!("Invalid algorithm specified")), |s| Ok(s))?,
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
                let buf = URL_SAFE_NO_PAD.encode(&inner.into_inner());

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

    pub(crate) fn fetch_root(
        &self,
        if_modified_since: Option<SystemTime>,
        mime: &str,
    ) -> Result<ModifiedData, anyhow::Error> {
        match self.driver.load_root() {
            Ok((doc, time)) => {
                if let Some(if_modified_since) = if_modified_since {
                    match if_modified_since.duration_since(time) {
                        Ok(_) => self.encode_root(doc, mime),
                        Err(_) => Ok(ModifiedData::NotModified),
                    }
                } else {
                    self.encode_root(doc, mime)
                }
            }
            Err(e) => Err(e.into()),
        }
    }

    pub(crate) fn fetch_user(
        &self,
        name: &str,
        if_modified_since: Option<SystemTime>,
        mime: &str,
    ) -> Result<ModifiedData, anyhow::Error> {
        match self.driver.load_user(name) {
            Ok((doc, time)) => {
                if let Some(if_modified_since) = if_modified_since {
                    match if_modified_since.duration_since(time) {
                        Ok(_) => self.encode_user(doc, mime),
                        Err(_) => Ok(ModifiedData::NotModified),
                    }
                } else {
                    self.encode_user(doc, mime)
                }
            }
            Err(e) => Err(e.into()),
        }
    }
}

#[derive(Clone)]
pub(crate) struct FileSystemStorage {
    pub root: PathBuf,
    pub cbor: bool,
}

impl FileSystemStorage {
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

impl StorageDriver for FileSystemStorage {
    fn load_root(&self) -> Result<(Document, SystemTime), anyhow::Error> {
        let path = self
            .root
            .join(std::path::MAIN_SEPARATOR.to_string() + ROOT_DID);
        self.load_doc(path)
    }

    fn load_user(&self, name: &str) -> Result<(Document, SystemTime), anyhow::Error> {
        if name.contains(std::path::MAIN_SEPARATOR) {
            return Err(anyhow!("name contains invalid characters"));
        }

        let path = self.root.join(&format!(
            "{}user{}{}.did",
            std::path::MAIN_SEPARATOR,
            std::path::MAIN_SEPARATOR,
            name
        ));

        self.load_doc(path)
    }
}
