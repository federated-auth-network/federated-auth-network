#![allow(dead_code)]
use anyhow::anyhow;
use base64::engine::{general_purpose::URL_SAFE_NO_PAD, Engine};
use did_toolkit::prelude::*;
use josekit::{
    jwk::{alg::ec::EcCurve, Jwk},
    jws::{alg::ecdsa::EcdsaJwsAlgorithm, serialize_compact, JwsHeader},
};
use serde::Serialize;
use std::time::SystemTime;

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
    Modified(String),
    NotModified,
}

pub trait StorageDriver {
    fn load(&self, name: &str) -> Result<(Document, SystemTime), anyhow::Error>;
    fn load_did(&self) -> Result<(Document, SystemTime), anyhow::Error>;
}

pub struct Storage<SD: StorageDriver> {
    driver: SD,
    signing_key: Jwk,
}

impl<SD: StorageDriver> Storage<SD> {
    pub fn fetch_did(&self, if_modified_since: SystemTime) -> Result<ModifiedData, anyhow::Error> {
        match self.driver.load_did() {
            Ok((doc, time)) => match if_modified_since.duration_since(time) {
                Ok(_) => Ok(ModifiedData::Modified(serde_json::json!(doc).to_string())),
                Err(_) => Ok(ModifiedData::NotModified),
            },
            Err(e) => Err(e.into()),
        }
    }

    pub fn fetch(
        &self,
        name: &str,
        if_modified_since: SystemTime,
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

                    let payload = serde_json::json!(SignedPayload {
                        payload: URL_SAFE_NO_PAD
                            .encode(serde_json::json!(doc).to_string())
                            .as_bytes(),
                        content_type: "application/json+did",
                    });

                    match serialize_compact(
                        payload.to_string().as_bytes(),
                        &header,
                        &alg.signer_from_jwk(&self.signing_key)?,
                    ) {
                        Ok(res) => Ok(ModifiedData::Modified(res)),
                        Err(e) => Err(e.into()),
                    }
                }
                Err(_) => Ok(ModifiedData::NotModified),
            },
            Err(e) => Err(e.into()),
        }
    }
}
