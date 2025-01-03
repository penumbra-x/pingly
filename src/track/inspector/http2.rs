#![allow(unused)]
use crate::track::TlsInspector;
use httlib_hpack::Decoder;
use serde::{Serialize, Serializer};
use std::pin::Pin;
use std::task;
use std::task::Poll;
use std::{io::IoSlice, sync::Arc};
use tokio::io::{self, AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::server::TlsStream;

pin_project_lite::pin_project! {
    pub struct Http2Inspector<I> {
        #[pin]
        inner: TlsStream<TlsInspector<I>>,

        buf: Vec<u8>,
        http2_frames: Arc<boxcar::Vec<Http2Frame>>,
    }
}

impl<I> Http2Inspector<I>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    pub fn new(inner: TlsStream<TlsInspector<I>>) -> Self {
        Self {
            inner,
            buf: Vec::new(),
            http2_frames: Arc::new(boxcar::Vec::new()),
        }
    }

    #[inline]
    #[must_use]
    pub fn frames(&self) -> Arc<boxcar::Vec<Http2Frame>> {
        self.http2_frames.clone()
    }
}

impl<I> AsyncRead for Http2Inspector<I>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

        let len = buf.filled().len();
        let me = self.project();
        let poll = me.inner.poll_read(cx, buf);

        let plen = HTTP2_PREFACE.len();
        let not_http2 = me.buf.len() >= plen && !me.buf.starts_with(HTTP2_PREFACE);
        if !not_http2 {
            me.buf.extend(&buf.filled()[len..]);
            let frames = me.http2_frames;
            while me.buf.len() > plen {
                let last = frames.iter().last().map(|f| f.1);
                if matches!(last, Some(Http2Frame::Headers(_))) {
                    break;
                }
                let (frame_len, frame) = parse_frame(&me.buf[plen..]);
                if frame_len > 0 {
                    me.buf.drain(plen..plen + frame_len);
                    if let Some(frame) = frame {
                        frames.push(frame);
                    }
                } else {
                    break;
                }
            }
        }

        poll
    }
}

impl<I> AsyncWrite for Http2Inspector<I>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.project().inner.poll_write(cx, buf)
    }

    #[inline]
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.project().inner.poll_write_vectored(cx, bufs)
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

const FRAME_HEADER_LEN: usize = 9;

fn parse_frame(data: &[u8]) -> (usize, Option<Http2Frame>) {
    if data.len() < FRAME_HEADER_LEN {
        return (0, None);
    }
    let header = &data[..FRAME_HEADER_LEN];
    let length = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
    let ty = header[3];
    let flags = header[4];
    let stream_id = u32::from_be_bytes([header[5] & 0x7f, header[6], header[7], header[8]]);
    let payload = &data[FRAME_HEADER_LEN..];
    if payload.len() < length {
        return (0, None);
    }
    let frame = (ty, flags, stream_id, &payload[..length]).try_into().ok();
    (FRAME_HEADER_LEN + length, frame)
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum Http2Frame {
    Settings(SettingsFrame),
    WindowUpdate(WindowUpdateFrame),
    Priority(PriorityFrame),
    Headers(HeadersFrame),
    Unknown(u8),
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FrameType {
    Settings,
    WindowUpdate,
    Headers,
    Priority,
    Unknown,
}

#[derive(Debug, Serialize)]
pub struct SettingsFrame {
    pub frame_type: FrameType,
    pub settings: Vec<Setting>,
}

#[derive(Debug)]
pub enum Setting {
    HeaderTableSize(u16, u32),
    EnablePush(u16, u32),
    MaxConcurrentStreams(u16, u32),
    InitialWindowSize(u16, u32),
    MaxFrameSize(u16, u32),
    MaxHeaderListSize(u16, u32),
    EnableConnectProtocol(u16, u32),
    NoRfc7540Priorities(u16, u32),
    UnknownSetting(u16, u32),
}

#[derive(Debug, Serialize)]
pub struct WindowUpdateFrame {
    pub frame_type: FrameType,
    pub length: usize,
    pub increment: u32,
}

#[derive(Debug, Serialize)]
pub struct PriorityFrame {
    pub frame_type: FrameType,
    pub stream_id: u32,
    pub length: usize,
    pub priority: Priority,
}

#[derive(Debug, Serialize)]
pub struct Priority {
    pub weight: u32,
    pub depends_on: u32,
    pub exclusive: u8,
}

#[derive(Debug, Serialize)]
pub struct HeadersFrame {
    pub frame_type: FrameType,
    pub stream_id: u32,
    pub length: usize,
    #[serde(skip)]
    pub pseudo_headers: [&'static str; 4],
    pub headers: Vec<String>,
    pub flags: HeadersFlag,
    pub priority: Option<Priority>,
}

const END_STREAM: u8 = 0x1;
const END_HEADERS: u8 = 0x4;
const PADDED: u8 = 0x8;
const PRIORITY: u8 = 0x20;

#[derive(Debug)]
pub struct HeadersFlag(u8);

/// Custom Serialize for HeadersFlag
impl Serialize for HeadersFlag {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut flags = Vec::new();

        if self.0 & END_STREAM != 0 {
            flags.push("EndStream (0x1)");
        }
        if self.0 & END_HEADERS != 0 {
            flags.push("EndHeaders (0x4)");
        }
        if self.0 & PADDED != 0 {
            flags.push("Padded (0x8)");
        }
        if self.0 & PRIORITY != 0 {
            flags.push("Priority (0x20)");
        }

        flags.serialize(serializer)
    }
}

/// ====== impl Http2Frame ======

impl TryFrom<(u8, u8, u32, &[u8])> for Http2Frame {
    type Error = ();

    fn try_from((ty, flags, stream_id, payload): (u8, u8, u32, &[u8])) -> Result<Self, ()> {
        if payload.is_empty() {
            return Err(());
        }
        match ty {
            0x1 => (flags, stream_id, payload)
                .try_into()
                .map(Http2Frame::Headers),
            0x2 => (stream_id, payload).try_into().map(Http2Frame::Priority),
            0x4 => (stream_id, payload).try_into().map(Http2Frame::Settings),
            0x8 => (stream_id, payload)
                .try_into()
                .map(Http2Frame::WindowUpdate),
            _ => Ok(Http2Frame::Unknown(ty)),
        }
    }
}

/// ====== impl SettingsFrame ======

impl TryFrom<(u32, &[u8])> for SettingsFrame {
    type Error = ();

    fn try_from((stream_id, payload): (u32, &[u8])) -> Result<Self, ()> {
        let settings = payload
            .chunks_exact(6)
            .map(|data| {
                let id = u16::from_be_bytes([data[0], data[1]]);
                let value = u32::from_be_bytes([data[2], data[3], data[4], data[5]]);
                Setting::from((id, value))
            })
            .collect();
        Ok(SettingsFrame {
            frame_type: FrameType::Settings,
            settings,
        })
    }
}

impl From<(u16, u32)> for Setting {
    fn from((id, value): (u16, u32)) -> Self {
        match id {
            1 => Setting::HeaderTableSize(id, value),
            2 => Setting::EnablePush(id, value),
            3 => Setting::MaxConcurrentStreams(id, value),
            4 => Setting::InitialWindowSize(id, value),
            5 => Setting::MaxFrameSize(id, value),
            6 => Setting::MaxHeaderListSize(id, value),
            8 => Setting::EnableConnectProtocol(id, value),
            9 => Setting::NoRfc7540Priorities(id, value),
            _ => Setting::UnknownSetting(id, value),
        }
    }
}

impl Serialize for Setting {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let value = match self {
            Setting::HeaderTableSize(_, value) => format!("HEADER_TABLE_SIZE = {}", value),
            Setting::EnablePush(_, value) => format!("ENABLE_PUSH = {}", value),
            Setting::MaxConcurrentStreams(_, value) => {
                format!("MAX_CONCURRENT_STREAMS = {}", value)
            }
            Setting::InitialWindowSize(_, value) => format!("INITIAL_WINDOW_SIZE = {}", value),
            Setting::MaxFrameSize(_, value) => format!("MAX_FRAME_SIZE = {}", value),
            Setting::MaxHeaderListSize(_, value) => format!("MAX_HEADER_LIST_SIZE = {}", value),
            Setting::EnableConnectProtocol(_, value) => {
                format!("ENABLE_CONNECT_PROTOCOL = {}", value)
            }
            Setting::NoRfc7540Priorities(_, value) => format!("NO_RFC7540_PRIORITIES = {}", value),
            Setting::UnknownSetting(_, value) => format!("UNKNOWN_SETTING = {}", value),
        };

        serializer.serialize_str(&value)
    }
}

impl Setting {
    pub fn value(&self) -> (u16, u32) {
        match self {
            Setting::HeaderTableSize(id, value) => (*id, *value),
            Setting::EnablePush(id, value) => (*id, *value),
            Setting::MaxConcurrentStreams(id, value) => (*id, *value),
            Setting::InitialWindowSize(id, value) => (*id, *value),
            Setting::MaxFrameSize(id, value) => (*id, *value),
            Setting::MaxHeaderListSize(id, value) => (*id, *value),
            Setting::EnableConnectProtocol(id, value) => (*id, *value),
            Setting::NoRfc7540Priorities(id, value) => (*id, *value),
            Setting::UnknownSetting(id, value) => (*id, *value),
        }
    }
}

/// ====== impl WindowUpdateFrame ======

impl TryFrom<(u32, &[u8])> for WindowUpdateFrame {
    type Error = ();

    fn try_from((stream_id, payload): (u32, &[u8])) -> Result<Self, ()> {
        if payload.len() != 4 {
            return Err(());
        }
        let window_size_increment =
            u32::from_be_bytes([payload[0] & 0x7f, payload[1], payload[2], payload[3]]);
        Ok(WindowUpdateFrame {
            frame_type: FrameType::WindowUpdate,
            length: payload.len(),
            increment: window_size_increment,
        })
    }
}

/// ====== impl Priority ======

impl Priority {
    pub fn load(buf: &[u8]) -> Result<Self, ()> {
        if buf.len() != 5 {
            return Err(());
        }

        let (weight, depends_on, exclusive) = {
            const STREAM_ID_MASK: u32 = 1 << 31;

            let mut ubuf = [0; 4];
            ubuf.copy_from_slice(&buf[0..4]);
            let unpacked = u32::from_be_bytes(ubuf);
            let flag = unpacked & STREAM_ID_MASK == STREAM_ID_MASK;

            // Now clear the most significant bit, as that is reserved and MUST be
            // ignored when received.
            (buf[4] as u32 + 1, unpacked & !STREAM_ID_MASK, flag as u8)
        };

        Ok(Priority {
            weight,
            depends_on,
            exclusive,
        })
    }
}

/// ====== impl PriorityFrame ======

impl TryFrom<(u32, &[u8])> for PriorityFrame {
    type Error = ();

    fn try_from((stream_id, buf): (u32, &[u8])) -> Result<Self, ()> {
        let priority = Priority::load(buf)?;

        if stream_id == priority.depends_on {
            return Err(());
        }

        Ok(PriorityFrame {
            frame_type: FrameType::Priority,
            stream_id,
            length: buf.len(),
            priority,
        })
    }
}

/// ====== impl HeadersFrame ======

impl TryFrom<(u8, u32, &[u8])> for HeadersFrame {
    type Error = ();

    fn try_from((flags, stream_id, payload): (u8, u32, &[u8])) -> Result<Self, ()> {
        let mut fragment_offset = 0;
        let padded = flags & 0x8 != 0;

        if flags & 0x20 != 0 {
            fragment_offset += 5;
        }

        if padded {
            fragment_offset += 1;
        }

        if payload.len() < fragment_offset {
            return Err(());
        }

        let padding_len = if padded { payload[0] as usize } else { 0 };
        let data = &payload[fragment_offset..];

        if data.len() < padding_len {
            return Err(());
        }

        let mut decoder = Decoder::default();
        let mut buf = data[..data.len() - padding_len].to_vec();
        let mut dst = Vec::new();

        if decoder.decode(&mut buf, &mut dst).is_err() {
            return Err(());
        }

        let mut headers = Vec::with_capacity(dst.len() - 4);
        let mut pseudo_headers = Vec::with_capacity(4);
        for (name, value, _) in dst {
            match name.as_slice() {
                b":method" => {
                    pseudo_headers.push("m");
                }
                b":authority" => {
                    pseudo_headers.push("a");
                }
                b":scheme" => {
                    pseudo_headers.push("s");
                }
                b":path" => {
                    pseudo_headers.push("p");
                }
                _ => {}
            }

            let mut kv = String::from_utf8(name).map_err(|_| ())?;
            let value = String::from_utf8(value).map_err(|_| ())?;
            kv.push_str(": ");
            kv.push_str(&value);
            headers.push(kv);
        }

        let priority = {
            if flags & 0x20 != 0 {
                let buf = &payload[fragment_offset - 5..fragment_offset];
                let priority = Priority::load(buf)?;
                Some(priority)
            } else {
                None
            }
        };

        let pseudo_headers = match pseudo_headers.try_into() {
            Ok(pseudo_headers) => pseudo_headers,
            Err(err) => {
                tracing::warn!("invalid http2 headers frame: {err:?}");
                return Err(());
            }
        };

        Ok(HeadersFrame {
            frame_type: FrameType::Headers,
            stream_id,
            length: payload.len(),
            pseudo_headers,
            headers,
            flags: HeadersFlag(flags),
            priority,
        })
    }
}
