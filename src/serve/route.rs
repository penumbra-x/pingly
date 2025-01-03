use crate::{
    error::Error,
    track::{ConnectTrack, Http2TrackInfo},
    Result,
};
use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{header::USER_AGENT, Request, StatusCode},
    response::IntoResponse,
    Extension,
};
use axum_extra::response::ErasedJson;
use serde::Serialize;
use std::net::SocketAddr;

const DONATE_URL: &str = "TLS/HTTP2 tracking server written in Rust, Developed by penumbra-x. https://github.com/penumbra-x/pingly";

impl IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        tracing::warn!("server track error: {}", self);
        (StatusCode::INTERNAL_SERVER_ERROR).into_response()
    }
}

#[derive(Serialize)]
pub struct TrackInfo<'a> {
    donate: &'static str,
    addr: SocketAddr,
    http_version: String,
    method: &'a str,
    user_agent: Option<&'a str>,
    http2: Option<Http2TrackInfo>,
}

impl<'a> TrackInfo<'a> {
    #[inline]
    pub fn new_http2_track(
        addr: SocketAddr,
        http2: Http2TrackInfo,
        req: &'a Request<Body>,
    ) -> TrackInfo<'a> {
        Self {
            donate: DONATE_URL,
            addr,
            http_version: format!("{:?}", req.version()),
            method: req.method().as_str(),
            user_agent: req.headers().get(USER_AGENT).and_then(|v| v.to_str().ok()),
            http2: Some(http2),
        }
    }
}

#[inline]
pub async fn manual_hello() -> &'static str {
    DONATE_URL
}

#[inline]
pub async fn http2_frames(
    Extension(ConnectInfo(addr)): Extension<ConnectInfo<SocketAddr>>,
    Extension(track): Extension<ConnectTrack>,
    req: Request<Body>,
) -> Result<ErasedJson> {
    let http2 = tokio::task::spawn_blocking(move || track.into_http2_frames()).await?;
    let info = TrackInfo::new_http2_track(addr, http2, &req);
    Ok(ErasedJson::pretty(info))
}
