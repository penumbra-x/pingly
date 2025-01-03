mod route;
mod signal;

use crate::config::Config;
use crate::Result;
use axum::Router;
use axum_server::{tls_rustls::RustlsConfig, Handle};
use tower::limit::ConcurrencyLimitLayer;
use tower_http::{
    cors::{AllowHeaders, AllowMethods, AllowOrigin, CorsLayer},
    trace::{DefaultMakeSpan, DefaultOnFailure, DefaultOnResponse, TraceLayer},
};
use tracing::Level;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

#[tokio::main]
pub async fn run(config: Config) -> Result<()> {
    // init logger
    init_logger(config.debug)?;

    // init boot message
    boot_message(&config);

    // init global layer provider
    let global_layer = tower::ServiceBuilder::new()
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
                .on_response(DefaultOnResponse::new().level(Level::INFO))
                .on_failure(DefaultOnFailure::new().level(Level::WARN)),
        )
        .layer(
            CorsLayer::new()
                .allow_credentials(true)
                .allow_headers(AllowHeaders::mirror_request())
                .allow_methods(AllowMethods::mirror_request())
                .allow_origin(AllowOrigin::mirror_request()),
        )
        .layer(ConcurrencyLimitLayer::new(config.concurrent));

    let router = Router::new()
        .fallback(route::manual_hello)
        .layer(global_layer);

    // Signal the server to shutdown using Handle.
    let handle = Handle::new();

    // Spawn a task to gracefully shutdown server.
    tokio::spawn(signal::graceful_shutdown(handle.clone()));

    // Run http server
    match (config.tls_cert.as_ref(), config.tls_key.as_ref()) {
        (Some(cert), Some(key)) => {
            // Load TLS configuration
            let tls_config = RustlsConfig::from_pem_chain_file(cert, key).await?;

            // Use TLS configuration to create a secure server
            let mut server = axum_server::bind_rustls(config.bind, tls_config);
            server.http_builder().http1().preserve_header_case(true);

            server
                .handle(handle)
                .serve(router.into_make_service())
                .await
        }
        _ => {
            // No TLS configuration, create a non-secure server
            let mut server = axum_server::bind(config.bind);
            server.http_builder().http1().preserve_header_case(true);

            server
                .handle(handle)
                .serve(router.into_make_service())
                .await
        }
    }
    .map_err(Into::into)
}

/// Print boot info message
fn boot_message(config: &Config) {
    // Server info
    tracing::info!("OS: {}", std::env::consts::OS);
    tracing::info!("Arch: {}", std::env::consts::ARCH);
    tracing::info!("Version: {}", env!("CARGO_PKG_VERSION"));
    tracing::info!("Concurrent limit: {}", config.concurrent);
    tracing::info!("Bind address: {}", config.bind);
}

/// Initialize the logger with a filter that ignores WARN level logs for netlink_proto
fn init_logger(debug: bool) -> Result<()> {
    let filter = EnvFilter::from_default_env()
        .add_directive(if debug { Level::DEBUG } else { Level::INFO }.into())
        .add_directive("netlink_proto=error".parse()?);

    tracing::subscriber::set_global_default(
        FmtSubscriber::builder().with_env_filter(filter).finish(),
    )?;

    Ok(())
}
