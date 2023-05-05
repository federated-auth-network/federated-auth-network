#![allow(dead_code)]
use crate::{
    mime::{DIDMIMEType, ModifiedData},
    storage::{FileSystemStorage, Storage},
};
use davisjr::prelude::*;
use josekit::jwk::Jwk;
use std::{path::PathBuf, time::SystemTime};

trait StorageFetcher {
    fn fetch_root(
        &self,
        if_modified_since: Option<SystemTime>,
        mime: &str,
    ) -> Result<ModifiedData, anyhow::Error>;

    fn fetch_user(
        &self,
        name: &str,
        if_modified_since: Option<SystemTime>,
        mime: &str,
    ) -> Result<ModifiedData, anyhow::Error>;
}

#[derive(Clone)]
struct FileSystemState {
    storage: Storage<FileSystemStorage>,
}

impl StorageFetcher for FileSystemState {
    fn fetch_root(
        &self,
        if_modified_since: Option<SystemTime>,
        mime: &str,
    ) -> Result<ModifiedData, anyhow::Error> {
        self.storage.fetch_root(if_modified_since, mime)
    }

    fn fetch_user(
        &self,
        name: &str,
        if_modified_since: Option<SystemTime>,
        mime: &str,
    ) -> Result<ModifiedData, anyhow::Error> {
        self.storage.fetch_user(name, if_modified_since, mime)
    }
}

#[inline]
fn accept(req: &Request<Body>) -> String {
    req.headers().get("Accept").map_or_else(
        || DIDMIMEType::JSON.to_string(),
        |s| String::from(s.to_str().unwrap()),
    )
}

#[inline]
fn modified<T>(md: ModifiedData, accept: &str, req: Request<Body>, state: T) -> HTTPResult<T> {
    match md {
        ModifiedData::Modified(res) => Ok((
            req,
            Some(
                Response::builder()
                    .status(200)
                    .header("Content-type", accept)
                    .body(Body::from(res))
                    .unwrap(),
            ),
            state,
        )),
        ModifiedData::NotModified => Ok((
            req,
            Some(Response::builder().status(304).body(Body::empty()).unwrap()),
            state,
        )),
    }
}

async fn get_root<
    S: StorageFetcher + Clone + Send + ?Sized + 'static,
    T: davisjr::TransientState,
>(
    req: Request<Body>,
    _resp: Option<Response<Body>>,
    _params: Params,
    app: App<S, T>,
    state: T,
) -> HTTPResult<T> {
    let accept = accept(&req);

    let storage = app.state().await.unwrap();
    let storage = storage.lock().await;

    modified(storage.fetch_root(None, &accept)?, &accept, req, state)
}

async fn get_user<
    S: StorageFetcher + Clone + Send + ?Sized + 'static,
    T: davisjr::TransientState,
>(
    req: Request<Body>,
    _resp: Option<Response<Body>>,
    params: Params,
    app: App<S, T>,
    state: T,
) -> HTTPResult<T> {
    let accept = accept(&req);

    let storage = app.state().await.unwrap();
    let storage = storage.lock().await;

    modified(
        storage.fetch_user(&params["name"], None, &accept)?,
        &accept,
        req,
        state,
    )
}

async fn configure_routes<
    S: StorageFetcher + Clone + Send + ?Sized + 'static,
    T: davisjr::TransientState,
>(
    mut app: App<S, T>,
) -> Result<(), davisjr::Error> {
    app.get("/fan.did", compose_handler!(get_root))?;
    app.get("/user/:name", compose_handler!(get_user))?;
    Ok(())
}

async fn boot_filesystem(
    addr: &str,
    root: PathBuf,
    cbor: bool,
    signing_key: Jwk,
) -> Result<(), ServerError> {
    let storage = Storage {
        driver: Box::new(FileSystemStorage { root, cbor }),
        signing_key,
    };

    let app: App<FileSystemState, NoState> = App::with_state(FileSystemState { storage });
    app.serve(addr).await?;

    Ok(())
}
