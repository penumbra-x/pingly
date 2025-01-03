mod accept;
mod info;
mod inspector;

pub use self::accept::TrackAcceptor;
pub use self::inspector::{Http2Frame, Http2Inspector, TlsInspector};
pub use info::Http2TrackInfo;
use std::sync::Arc;

/// ConnectTrack
/// Wrapper for tls and http2 settings
#[derive(Debug, Clone)]
pub struct ConnectTrack {
    http2_frames: Arc<boxcar::Vec<Http2Frame>>,
}

impl ConnectTrack {
    pub fn new(http2_frames: Arc<boxcar::Vec<Http2Frame>>) -> Self {
        Self { http2_frames }
    }

    pub fn into_http2_frames(self) -> Http2TrackInfo {
        Http2TrackInfo::new(self.http2_frames)
    }
}
