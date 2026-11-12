//! Profiles: named presets of scope ceilings that Capability tokens are
//! minted from (PRD glossary). Defined in a human-readable `profiles.toml`;
//! without one, [`DEFAULT_PROFILES`] applies.
//!
//! A Profile is a ceiling. A token minted from it can be narrower in every
//! dimension, never wider (see [`Scope::first_excess`]).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::time::parse_duration;
use crate::verb::Verb;

/// The Profiles used when there is no `profiles.toml`. Also the reference
/// for the file's format: copy it and edit.
///
/// `read_budget` is the number of messages whose content a token may
/// receive over its life; it's enforced by the Verb dispatcher. None of these allow `read-untrusted`,
/// `attachment.fetch` or `send-request`: add them to a Profile on purpose.
pub const DEFAULT_PROFILES: &str = r#"
# Read and search only.
[readonly]
verbs = ["list", "read", "search"]
accounts = "*"
resources = "*"
read_budget = 500
max_ttl = "8h"

# Sort mail: read, label and move.
[triage]
verbs = ["list", "read", "search", "label", "move", "attachment.extract"]
accounts = "*"
resources = "*"
read_budget = 1000
max_ttl = "8h"

# Read and write drafts; sending is never part of it.
[drafter]
verbs = ["list", "read", "search", "draft", "attachment.extract"]
accounts = "*"
resources = "*"
read_budget = 500
max_ttl = "8h"
"#;

/// The one folder name compared without case.
const INBOX: &str = "INBOX";

/// Which Accounts, or which folders and labels, a [`Scope`] covers.
/// Written `"*"` or as a list of names in `profiles.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "SelectorRepr", into = "SelectorRepr")]
pub enum Selector {
    All,
    Only(BTreeSet<String>),
}

impl Selector {
    /// Whether a call naming `name` is covered. A call that names nothing
    /// (all Accounts, all folders) is covered only by [`Selector::All`].
    pub fn allows(&self, name: Option<&str>) -> bool {
        match self {
            Selector::All => true,
            Selector::Only(names) => name.is_some_and(|name| names.contains(name)),
        }
    }

    /// [`Selector::allows`] for a folder or label. Names match exactly as
    /// the provider reports them, except `INBOX`, which IMAP treats as
    /// case-insensitive (RFC 3501). A parent never covers its subfolders.
    pub fn allows_folder(&self, name: Option<&str>) -> bool {
        let is_inbox = |name: &str| name.eq_ignore_ascii_case(INBOX);
        match (self, name) {
            (Selector::Only(names), Some(name)) if is_inbox(name) => {
                names.iter().any(|listed| is_inbox(listed))
            }
            _ => self.allows(name),
        }
    }

    /// Whether everything `self` covers is also covered by `ceiling`.
    pub fn within(&self, ceiling: &Selector) -> bool {
        match (self, ceiling) {
            (_, Selector::All) => true,
            (Selector::All, Selector::Only(_)) => false,
            (Selector::Only(mine), Selector::Only(theirs)) => mine.is_subset(theirs),
        }
    }

    /// [`Selector::within`] for folders, matching names the way
    /// [`Selector::allows_folder`] does, so a scope narrowed to `inbox`
    /// fits under a Profile that lists `INBOX`.
    pub fn within_folders(&self, ceiling: &Selector) -> bool {
        match self {
            Selector::Only(mine) => mine.iter().all(|name| ceiling.allows_folder(Some(name))),
            Selector::All => self.within(ceiling),
        }
    }

    /// False for a list that names nothing or holds an empty name.
    /// `profiles.toml` rejects both, and so does minting.
    pub fn is_valid(&self) -> bool {
        match self {
            Selector::All => true,
            Selector::Only(names) => !names.is_empty() && !names.contains(""),
        }
    }

    pub fn only<'a>(names: impl IntoIterator<Item = &'a str>) -> Self {
        Selector::Only(names.into_iter().map(str::to_string).collect())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum SelectorRepr {
    All(String),
    Only(Vec<String>),
}

impl TryFrom<SelectorRepr> for Selector {
    type Error = String;
    fn try_from(repr: SelectorRepr) -> Result<Self, String> {
        match repr {
            SelectorRepr::All(star) if star == "*" => Ok(Selector::All),
            SelectorRepr::All(other) => Err(format!(
                "{other:?}: use \"*\" for everything, or a list of names"
            )),
            SelectorRepr::Only(names) if names.is_empty() => {
                Err("an empty list allows nothing; use \"*\" or name at least one".into())
            }
            SelectorRepr::Only(names) if names.iter().any(|name| name.is_empty()) => {
                Err("names can't be empty".into())
            }
            SelectorRepr::Only(names) => Ok(Selector::Only(names.into_iter().collect())),
        }
    }
}

impl From<Selector> for SelectorRepr {
    fn from(selector: Selector) -> Self {
        match selector {
            Selector::All => SelectorRepr::All("*".into()),
            Selector::Only(names) => SelectorRepr::Only(names.into_iter().collect()),
        }
    }
}

/// What a token (or, as a ceiling, a Profile) may touch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub accounts: Selector,
    /// Folders or labels.
    pub resources: Selector,
    pub verbs: BTreeSet<Verb>,
    /// Reads allowed over the token's life.
    pub read_budget: u64,
}

impl Scope {
    /// The first field where `self` reaches past `ceiling`, if any.
    pub fn first_excess(&self, ceiling: &Scope) -> Option<&'static str> {
        if !self.accounts.within(&ceiling.accounts) {
            Some("accounts")
        } else if !self.resources.within_folders(&ceiling.resources) {
            Some("resources")
        } else if !self.verbs.is_subset(&ceiling.verbs) {
            Some("verbs")
        } else if self.read_budget > ceiling.read_budget {
            Some("read_budget")
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    pub name: String,
    pub ceiling: Scope,
    /// The longest TTL a token minted from this Profile can have.
    pub max_ttl_ms: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileEntry {
    verbs: Vec<Verb>,
    accounts: Selector,
    resources: Selector,
    read_budget: u64,
    max_ttl: String,
}

#[derive(Debug)]
pub enum ProfileError {
    Io(PathBuf, std::io::Error),
    /// The file isn't valid TOML, or a field has the wrong shape.
    Parse(String),
    Invalid {
        profile: String,
        why: String,
    },
}

impl fmt::Display for ProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProfileError::Io(path, e) => write!(f, "can't read {}: {e}", path.display()),
            ProfileError::Parse(why) => write!(f, "profiles: {why}"),
            ProfileError::Invalid { profile, why } => write!(f, "profile {profile:?}: {why}"),
        }
    }
}

impl std::error::Error for ProfileError {}

/// The set of Profiles tokens can be minted from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profiles {
    by_name: BTreeMap<String, Profile>,
}

impl Profiles {
    /// [`DEFAULT_PROFILES`].
    pub fn built_in() -> Self {
        Self::parse(DEFAULT_PROFILES).expect("DEFAULT_PROFILES is valid")
    }

    /// Reads `path`. A missing file means [`Profiles::built_in`]; a file
    /// that exists replaces the defaults entirely, it doesn't merge.
    pub fn load(path: &Path) -> Result<Self, ProfileError> {
        match std::fs::read_to_string(path) {
            Ok(text) => Self::parse(&text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::built_in()),
            Err(e) => Err(ProfileError::Io(path.to_path_buf(), e)),
        }
    }

    pub fn parse(text: &str) -> Result<Self, ProfileError> {
        let entries: BTreeMap<String, ProfileEntry> =
            toml::from_str(text).map_err(|e| ProfileError::Parse(e.to_string()))?;
        let mut by_name = BTreeMap::new();
        for (name, entry) in entries {
            let invalid = |why: &str| ProfileError::Invalid {
                profile: name.clone(),
                why: why.to_string(),
            };
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            {
                return Err(invalid("names use a-z, 0-9 and '-' only"));
            }
            if entry.verbs.is_empty() {
                return Err(invalid("verbs is empty, so the Profile allows nothing"));
            }
            let max_ttl_ms = parse_duration(&entry.max_ttl)
                .map_err(|_| invalid("max_ttl: use a duration like 30m, 8h or 7d"))?;
            let profile = Profile {
                name: name.clone(),
                ceiling: Scope {
                    accounts: entry.accounts,
                    resources: entry.resources,
                    verbs: entry.verbs.into_iter().collect(),
                    read_budget: entry.read_budget,
                },
                max_ttl_ms,
            };
            by_name.insert(name, profile);
        }
        if by_name.is_empty() {
            return Err(ProfileError::Parse("no profiles defined".into()));
        }
        Ok(Profiles { by_name })
    }

    pub fn get(&self, name: &str) -> Option<&Profile> {
        self.by_name.get(name)
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.by_name.keys().map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_folder_scope_fits_its_ceiling_with_inbox_in_any_case() {
        let ceiling = Selector::only(["INBOX", "Work"]);
        assert!(Selector::only(["inbox"]).within_folders(&ceiling));
        assert!(Selector::only(["Inbox", "Work"]).within_folders(&ceiling));
        assert!(!Selector::only(["work"]).within_folders(&ceiling));
        assert!(!Selector::only(["Work/Clients"]).within_folders(&ceiling));
        assert!(!Selector::All.within_folders(&ceiling));
        assert!(Selector::only(["anything"]).within_folders(&Selector::All));
    }

    #[test]
    fn a_selector_is_within_a_ceiling_only_when_it_covers_less() {
        let work = Selector::only(["work"]);
        let both = Selector::only(["work", "home"]);
        assert!(work.within(&both) && work.within(&Selector::All));
        assert!(!both.within(&work));
        assert!(!Selector::All.within(&both));
    }

    #[test]
    fn a_call_naming_nothing_is_covered_only_by_all() {
        assert!(Selector::All.allows(None));
        assert!(!Selector::only(["work"]).allows(None));
        assert!(Selector::only(["work"]).allows(Some("work")));
        assert!(!Selector::only(["work"]).allows(Some("home")));
    }
}
