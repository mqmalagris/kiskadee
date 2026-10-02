//! Content ingestion: every sender-controlled field becomes [`UntrustedText`]
//! and reaches Clients only inside the Envelope `{content, trust}`.

mod untrusted;

pub use untrusted::UntrustedText;
