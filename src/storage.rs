#![allow(dead_code)]
use anyhow::anyhow;
use base64::engine::{general_purpose::URL_SAFE_NO_PAD, Engine};
use did_toolkit::prelude::*;
use josekit::{
    jwk::{alg::ec::EcCurve, Jwk},
    jws::{alg::ecdsa::EcdsaJwsAlgorithm, serialize_compact, JwsHeader},
};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

fn jwk_alg_to_signing_alg(alg: EcCurve) -> EcdsaJwsAlgorithm {
    match alg {
        EcCurve::P256 => EcdsaJwsAlgorithm::Es256,
        EcCurve::P384 => EcdsaJwsAlgorithm::Es384,
        EcCurve::P521 => EcdsaJwsAlgorithm::Es512,
        EcCurve::Secp256k1 => EcdsaJwsAlgorithm::Es256k,
    }
}

// TODO: convince josekit to provide this method
fn jwk_alg_from_str(s: &str) -> Result<EcCurve, anyhow::Error> {
    match s {
        "P-256" => Ok(EcCurve::P256),
        "P-384" => Ok(EcCurve::P384),
        "P-521" => Ok(EcCurve::P521),
        "secp256k1" => Ok(EcCurve::Secp256k1),
        _ => Err(anyhow!("Invalid algorithm specified")),
    }
}

#[derive(Serialize, Deserialize)]
pub struct SignedPayload {
    payload: Vec<u8>,
    content_type: String,
}

pub enum ModifiedData {
    Modified(String),
    NotModified,
}

pub trait StorageDriver {
    fn load(&self, name: &str) -> Result<(Document, SystemTime), anyhow::Error>;
    fn store(&self, doc: Document) -> Result<(), anyhow::Error>;
}

pub struct Storage<SD: StorageDriver> {
    driver: SD,
    signing_key: Jwk,
}

impl<SD: StorageDriver> Storage<SD> {
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

                    let signer = alg.signer_from_jwk(&self.signing_key)?;

                    let mut header = JwsHeader::new();
                    header.set_algorithm(alg.to_string());

                    let json_doc = serde_json::json!(doc);

                    let payload = serde_json::json!(SignedPayload {
                        payload: URL_SAFE_NO_PAD
                            .encode(json_doc.to_string())
                            .as_bytes()
                            .to_vec(),
                        content_type: "application/json+did".to_string()
                    });

                    match serialize_compact(payload.to_string().as_bytes(), &header, &signer) {
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
