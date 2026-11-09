//! kiskadee Broker core: the Verb dispatcher, Capability tokens, Profiles,
//! read budgets, Escalations and the Ledger.
//!
//! This crate must not depend on email types; mail arrives through the
//! `MailBackend` trait in `kiskadee-mail` (ADR 0002).

mod db;
pub mod ledger;
pub mod profiles;
pub mod time;
pub mod verb;
