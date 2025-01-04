use crate::track::Http2TrackInfo;
use axum::{
    body::Body,
    http::{header::USER_AGENT, Request},
};
use serde::Serialize;
use std::net::SocketAddr;

const DONATE_URL: &str = "TLS/HTTP2 tracking server written in Rust, Developed by penumbra-x. https://github.com/penumbra-x/pingly";

#[derive(Serialize)]
pub struct TrackInfo<'a> {
    donate: &'static str,
    addr: SocketAddr,
    http_version: String,
    method: &'a str,
    user_agent: Option<&'a str>,
    headers_order: Vec<&'a str>,
    http2: Option<Http2TrackInfo>,
}

impl<'a> TrackInfo<'a> {
    #[inline]
    pub fn new_http2_track(
        addr: SocketAddr,
        http2: Http2TrackInfo,
        req: &'a Request<Body>,
    ) -> TrackInfo<'a> {
        let headers = req.headers();
        Self {
            donate: DONATE_URL,
            addr,
            http_version: format!("{:?}", req.version()),
            method: req.method().as_str(),
            user_agent: headers.get(USER_AGENT).and_then(|v| v.to_str().ok()),
            headers_order: headers.iter().map(|(k, _)| k.as_str()).collect(),
            http2: Some(http2),
        }
    }
}
