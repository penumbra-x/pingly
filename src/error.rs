#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    IOError(#[from] std::io::Error),

    #[error(transparent)]
    ParseIntError(#[from] std::num::ParseIntError),

    #[error(transparent)]
    AddressParseError(#[from] std::net::AddrParseError),

    #[cfg(target_family = "unix")]
    #[error(transparent)]
    NixError(#[from] nix::Error),

    #[error(transparent)]
    LogParseError(#[from] tracing_subscriber::filter::ParseError),

    #[error(transparent)]
    LogSetGlobalDefaultError(#[from] tracing::subscriber::SetGlobalDefaultError),

    #[error(transparent)]
    JsonExtractorRejection(#[from] axum::extract::rejection::JsonRejection),

    #[error(transparent)]
    HttpError(#[from] axum::http::Error),

    #[error(transparent)]
    RcgenError(#[from] rcgen::Error),

    #[error(transparent)]
    JoinError(#[from] tokio::task::JoinError),
}
