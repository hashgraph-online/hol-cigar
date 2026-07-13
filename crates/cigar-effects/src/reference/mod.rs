//! Hermetic reference effect connectors and injectable transport contracts.

mod demo;
mod filesystem;
mod github;
mod http;
mod support;

pub use demo::{
    DemoDispatchMode, DemoIssueConnector, DemoIssueRequest, DemoIssueService, DemoIssueSnapshot,
};
pub use filesystem::{FilesystemEffectConnector, FilesystemWriteRequest};
pub use github::{
    GitHubIssueConnector, GitHubIssueRequest, MockGitHubDispatchMode, MockGitHubIssueService,
    MockGitHubIssueSnapshot,
};
pub use http::{
    HttpLookupObservation, HttpMethod, HttpResourceBindingRequest, HttpResourceScope,
    HttpTransport, HttpTransportObservation, HttpTransportQuery, HttpTransportRequest,
    HttpTransportSecurity, IdempotentHttpConnector, IdempotentHttpRequest,
};
