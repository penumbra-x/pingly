use super::Http2Frame;
use serde::{Serialize, Serializer};
use std::sync::Arc;

#[derive(Debug, Serialize)]
pub struct Http2TrackInfo {
    pub akamai_fingerprint: String,

    pub akamai_fingerprint_hash: String,

    #[serde(serialize_with = "serialize_sent_frames")]
    pub sent_frames: Arc<boxcar::Vec<Http2Frame>>,
}

impl Http2TrackInfo {
    pub fn new(sent_frames: Arc<boxcar::Vec<Http2Frame>>) -> Self {
        let akamai_fingerprint = compute_akamai_fingerprint(&sent_frames);
        let akamai_fingerprint_hash = compute_akamai_fingerprint_hash(&akamai_fingerprint);
        Self {
            akamai_fingerprint,
            akamai_fingerprint_hash,
            sent_frames,
        }
    }
}

/// Compute the Akamai fingerprint hash from the Akamai fingerprint
fn compute_akamai_fingerprint_hash(akamai_fingerprint: &str) -> String {
    let hash = md5::compute(akamai_fingerprint);
    hex::encode(hash.as_slice())
}

/// Compute the Akamai fingerprint from the sent frames
///
/// The Akamai fingerprint is a string of 16 bytes that is computed from the sent frames.
/// It is used to identify the client and the server.
///
/// Return example: 1:65536;4:131072;5:16384|12517377|3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1,13:0:0:241|m,p,a,s
fn compute_akamai_fingerprint(sent_frames: &Arc<boxcar::Vec<Http2Frame>>) -> String {
    let mut setting_group = Vec::new();
    let mut window_update_group = String::new();
    let mut priority_group = Vec::new();
    let mut headers_group = String::new();

    for (_, frame) in sent_frames.iter() {
        match frame {
            Http2Frame::Settings(frame) => {
                for setting in &frame.settings {
                    let (id, value) = setting.value();
                    setting_group.push(format!("{id}:{value}"));
                }
            }
            Http2Frame::WindowUpdate(frame) => {
                std::mem::swap(&mut window_update_group, &mut frame.increment.to_string());
            }
            Http2Frame::Priority(frame) => {
                priority_group.push(format!(
                    "{}:{}:{}:{}",
                    frame.stream_id,
                    frame.priority.exclusive,
                    frame.priority.depends_on,
                    frame.priority.weight
                ));
            }
            Http2Frame::Headers(frame) => {
                std::mem::swap(&mut headers_group, &mut frame.pseudo_headers.join(","));
            }
            Http2Frame::Unknown(v) => {
                tracing::trace!("Unknown http2 frame: {:?}", v);
            }
        }
    }

    vec![
        setting_group.join(";"),
        window_update_group,
        priority_group.join(","),
        headers_group,
    ]
    .join("|")
}

fn serialize_sent_frames<S>(
    sent_frames: &Arc<boxcar::Vec<Http2Frame>>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let vec = sent_frames
        .iter()
        .map(|(_, value)| value)
        .collect::<Vec<_>>();
    vec.serialize(serializer)
}
