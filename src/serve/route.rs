use crate::track::{ConnectTrack, Http2TrackInfo};
use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{header::USER_AGENT, Request},
    Extension,
};
use axum_extra::response::ErasedJson;
use serde::Serialize;
use std::net::SocketAddr;

const DONATE_URL: &str = "TLS/HTTP2 tracking server written in Rust, Developed by penumbra-x. https://github.com/penumbra-x/pingly";

#[derive(Serialize)]
pub struct TrackInfo<'a> {
    donate: &'static str,
    addr: SocketAddr,
    http_version: String,
    method: &'a str,
    user_agent: &'a str,
    http2: Option<Http2TrackInfo>,
}

impl<'a> TrackInfo<'a> {
    pub fn new(addr: SocketAddr, track: ConnectTrack, req: &'a Request<Body>) -> TrackInfo<'a> {
        Self {
            donate: DONATE_URL,
            addr,
            http_version: format!("{:?}", req.version()),
            method: req.method().as_str(),
            user_agent: req.headers().get(USER_AGENT).unwrap().to_str().unwrap(),
            http2: Some(track.into_http2_frames()),
        }
    }
}

#[inline]
pub async fn manual_hello() -> &'static str {
    DONATE_URL
}

pub async fn http2_frames(
    Extension(ConnectInfo(addr)): Extension<ConnectInfo<SocketAddr>>,
    Extension(track): Extension<ConnectTrack>,
    req: Request<Body>,
) -> ErasedJson {
    let info = TrackInfo::new(addr, track, &req);
    ErasedJson::pretty(info)
}
