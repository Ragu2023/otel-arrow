// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

use std::num::NonZeroUsize;
use std::time::Duration;

use serde::Deserialize;

use crate::exporters::otlp_grpc_exporter::default_max_in_flight;
use otap_df_otap::otlp_http::bearer::DEFAULT_TOKEN_ID;
use otap_df_otap::otlp_http::client_settings::HttpClientSettings;

/// Configuration for OTLP HTTP Exporter
#[derive(Debug, Deserialize)]
pub struct Config {
    /// Configuration for the HTTP client that will be used by this exporter
    pub http: HttpClientSettings,

    /// The endpoint to which the exporter will send OTLP HTTP requests. This should include the
    /// scheme, host and port, but not the paths (/v1/logs) as these will be appended to requests
    /// automatically for each batch of signals depending on the signal type.
    ///
    /// Example: "http://localhost:4318" or "https://otel-collector:4318"
    pub endpoint: String,

    /// The target URL to send trace data to, including the path. If this setting is present the
    /// endpoint setting is ignored for traces.
    ///
    /// Example: https://example.com:4318/v1/traces
    pub traces_endpoint: Option<String>,

    /// The target URL to send metric data to, including the path. If this setting is present the
    /// endpoint setting is ignored for metrics.
    ///
    /// Example: https://example.com:4318/v1/metrics
    pub metrics_endpoint: Option<String>,

    /// The target URL to send log data to, including the path. If this setting is present the
    /// endpoint setting is ignored for logs.
    ///
    /// Example: https://example.com:4318/v1/logs
    pub logs_endpoint: Option<String>,

    /// Maximum allowed size for the body of OTLP HTTP responses. This is used to prevent unbounded
    /// memory usage when receiving responses from the OTLP server. If a response exceeds this size,
    /// the exporter will consider processing of the batch to be unsuccessful. default = 10 MiB
    #[serde(default = "default_max_response_body_length")]
    pub max_response_body_length: usize,

    /// The size of the pool of HTTP clients to use for sending export requests. This allows for
    /// multiple concurrent connections to the OTLP server, which can help with load balancing when
    /// there are multiple receiver instances running on the same port (using SO_REUSEPORT).
    pub client_pool_size: NonZeroUsize,

    /// Maximum number of concurrent in-flight export requests.
    #[serde(default = "default_max_in_flight")]
    pub max_in_flight: usize,

    /// Optional bearer-token authentication. When enabled, every outbound request is decorated
    /// with an `Authorization: Bearer <token>` header whose value is refreshed out-of-band by an
    /// external owner (e.g. a host application). Requests are dropped when no token is available.
    #[serde(default)]
    pub bearer_auth: Option<BearerAuthConfig>,
}

/// Where the refreshable bearer token comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BearerSource {
    /// The token is read from a file that an external owner keeps up to date. Used for testing and
    /// as the initial delivery mechanism.
    #[default]
    File,
    /// The token is pushed in-process through the FFI setter (`df_engine_set_bearer_token`). No
    /// polling occurs; the external application publishes the token directly.
    Ffi,
}

/// Configuration for refreshable bearer-token authentication on the OTLP HTTP exporter.
#[derive(Debug, Clone, Deserialize)]
pub struct BearerAuthConfig {
    /// Whether bearer-token authentication is active. When `false`, no `Authorization` header is
    /// added and no token source is started.
    #[serde(default)]
    pub enabled: bool,

    /// The source that supplies and refreshes the token.
    #[serde(default)]
    pub source: BearerSource,

    /// Registry key that ties the exporter (reader) to the token source (writer). Multiple
    /// exporter instances sharing an id share a single token slot and a single source.
    #[serde(default = "default_bearer_id")]
    pub id: String,

    /// Path to the token file. Required when `source` is `file`.
    #[serde(default)]
    pub path: Option<String>,

    /// How often the file source re-checks the token file for changes.
    #[serde(default = "default_bearer_reload", with = "humantime_serde")]
    pub reload: Duration,
}

fn default_bearer_id() -> String {
    DEFAULT_TOKEN_ID.to_owned()
}

fn default_bearer_reload() -> Duration {
    Duration::from_secs(5)
}

fn default_max_response_body_length() -> usize {
    10 * 1024 * 1024
}
