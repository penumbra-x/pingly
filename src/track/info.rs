use super::{inspector::Frame, Http2Frame};
use serde::{Serialize, Serializer};
use std::sync::Arc;

#[derive(Serialize)]
pub struct Http2TrackInfo {
    track_time: String,
    akamai_fingerprint: String,
    akamai_fingerprint_hash: String,
    full_akamai_fingerprint: String,
    full_akamai_fingerprint_hash: String,

    #[serde(serialize_with = "serialize_sent_frames")]
    sent_frames: Arc<Http2Frame>,
}

impl Http2TrackInfo {
    pub fn new(sent_frames: Arc<Http2Frame>) -> Http2TrackInfo {
        let now = sent_frames.elapsed();

        let (akamai_fingerprint, full_akamai_fingerprint) =
            compute_akamai_fingerprint(&sent_frames);

        let akamai_fingerprint_hash = compute_akamai_fingerprint_hash(&akamai_fingerprint);
        let full_akamai_fingerprint_hash =
            compute_akamai_fingerprint_hash(&full_akamai_fingerprint);

        Self {
            track_time: format!("{now:?}"),
            akamai_fingerprint,
            akamai_fingerprint_hash,
            full_akamai_fingerprint,
            full_akamai_fingerprint_hash,
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
fn compute_akamai_fingerprint(sent_frames: &Arc<Http2Frame>) -> (String, String) {
    let mut setting_group = Vec::new();
    let mut window_update_group = None;
    let mut priority_group = None;
    let mut headers_group = String::new();
    let mut full_headers_group = Vec::with_capacity(4);

    for (_, frame) in sent_frames.iter() {
        match frame {
            Frame::Settings(frame) => {
                for setting in &frame.settings {
                    let (id, value) = setting.value();
                    setting_group.push(format!("{id}:{value}"));
                }
            }
            Frame::WindowUpdate(frame) => {
                window_update_group = Some(frame.increment);
            }
            Frame::Priority(frame) => {
                let priority_group = priority_group.get_or_insert_with(Vec::new);
                priority_group.push(format!(
                    "{}:{}:{}:{}",
                    frame.stream_id,
                    frame.priority.exclusive as u8,
                    frame.priority.depends_on,
                    frame.priority.weight as u16 + 1
                ));
            }
            Frame::Headers(frame) => {
                let pseudo_headers = frame.pseudo_headers.join(",");
                headers_group.push_str(&pseudo_headers);

                full_headers_group.push(format!("{}", frame.stream_id));
                full_headers_group.push(pseudo_headers);
                full_headers_group.push(format!("{}", *frame.flags));
                if let Some(ref priority) = frame.priority {
                    full_headers_group.push(format!(
                        "{}:{}:{}",
                        priority.exclusive as u8,
                        priority.depends_on,
                        priority.weight as u16 + 1
                    ));
                }
            }
            Frame::Unknown(v) => {
                tracing::trace!("Unknown http2 frame: {:?}", v);
            }
        }
    }

    let mut akamai_fingerprint = Vec::with_capacity(3);
    let mut full_akamai_fingerprint = Vec::with_capacity(3);

    akamai_fingerprint.push(setting_group.join(";"));
    full_akamai_fingerprint.push(setting_group.join(";"));

    if let Some(window_update_group) = window_update_group {
        akamai_fingerprint.push(window_update_group.to_string());
        full_akamai_fingerprint.push(window_update_group.to_string());
    }

    if let Some(priority_group) = priority_group {
        akamai_fingerprint.push(priority_group.join(","));
        full_akamai_fingerprint.push(priority_group.join(","));
    }

    akamai_fingerprint.push(headers_group);
    full_akamai_fingerprint.push(full_headers_group.join(";"));

    (
        akamai_fingerprint.join("|"),
        full_akamai_fingerprint.join("|"),
    )
}

fn serialize_sent_frames<S>(sent_frames: &Arc<Http2Frame>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let vec = sent_frames
        .iter()
        .map(|(_, value)| value)
        .collect::<Vec<_>>();
    vec.serialize(serializer)
}
