//! The fixed Verb set: every operation an agent can ask the Broker for.
//! There is no passthrough; anything not listed here can't be called.

use std::fmt;
use std::str::FromStr;

/// One operation the Broker exposes to agents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Verb {
    List,
    Read,
    /// `read --untrusted`: full content of Quarantined mail, logged separately.
    ReadUntrusted,
    Search,
    Draft,
    Label,
    Move,
    SendRequest,
    AttachmentExtract,
    AttachmentFetch,
}

impl Verb {
    pub const ALL: [Verb; 10] = [
        Verb::List,
        Verb::Read,
        Verb::ReadUntrusted,
        Verb::Search,
        Verb::Draft,
        Verb::Label,
        Verb::Move,
        Verb::SendRequest,
        Verb::AttachmentExtract,
        Verb::AttachmentFetch,
    ];

    /// The name used in `profiles.toml` and the Ledger.
    pub fn as_str(self) -> &'static str {
        match self {
            Verb::List => "list",
            Verb::Read => "read",
            Verb::ReadUntrusted => "read-untrusted",
            Verb::Search => "search",
            Verb::Draft => "draft",
            Verb::Label => "label",
            Verb::Move => "move",
            Verb::SendRequest => "send-request",
            Verb::AttachmentExtract => "attachment.extract",
            Verb::AttachmentFetch => "attachment.fetch",
        }
    }
}

impl fmt::Display for Verb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A name that isn't in the Verb set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownVerb(pub String);

impl fmt::Display for UnknownVerb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown Verb {:?}", self.0)
    }
}

impl std::error::Error for UnknownVerb {}

impl FromStr for Verb {
    type Err = UnknownVerb;
    fn from_str(s: &str) -> Result<Self, UnknownVerb> {
        Verb::ALL
            .into_iter()
            .find(|verb| verb.as_str() == s)
            .ok_or_else(|| UnknownVerb(s.to_string()))
    }
}

impl serde::Serialize for Verb {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for Verb {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let name = <String as serde::Deserialize>::deserialize(deserializer)?;
        name.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_verb_round_trips_through_its_name() {
        for verb in Verb::ALL {
            assert_eq!(verb.as_str().parse::<Verb>(), Ok(verb));
        }
        assert!("passthrough".parse::<Verb>().is_err());
    }
}
