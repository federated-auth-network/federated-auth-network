#![allow(dead_code)]
use anyhow::anyhow;
use did_toolkit::prelude::*;
use std::time::SystemTime;

pub trait StorageDriver {
    fn load(name: &str) -> Result<(Document, SystemTime), anyhow::Error>;
    fn store(doc: Document) -> Result<(), anyhow::Error>;
}

pub struct Storage<SD: StorageDriver> {
    driver: SD,
    signing_key: jsonwebkey::JsonWebKey,
}

impl<SD: StorageDriver> Storage<SD> {
    pub fn fetch(_name: &str, _if_modified_since: SystemTime) -> Result<&[u8], anyhow::Error> {
        Err(anyhow!("not implemented"))
    }
}
