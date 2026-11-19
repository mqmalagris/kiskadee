//! What goes inside a frame: one JSON object per request and per response,
//! each carrying the protocol version `v`.
//!
//! ```text
//! {"v":1,"op":"ping"}
//! {"v":1,"op":"call","token":"…","verb":"list","account":"work",…}
//!
//! {"v":1,"ok":{…}}
//! {"v":1,"denied":{"code":"broker.locked","message":"…"}}
//! {"v":1,"error":{"code":"internal","message":"…"}}
//! ```

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const VERSION: u64 = 1;

/// Reply codes the transport itself gives.
pub const PROTOCOL_VERSION: &str = "protocol.version";
pub const REQUEST_INVALID: &str = "request.invalid";

/// Error codes for a call that failed inside kiskadee; the detail stays in
/// the Broker's log.
pub const BACKEND: &str = "backend";
pub const INTERNAL: &str = "internal";

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "lowercase", deny_unknown_fields)]
pub enum Request {
    // A struct variant, so `deny_unknown_fields` covers it too.
    Ping {},
    Call(Call),
}

/// A Verb call. The peer pid is never taken from here: the Broker reads it
/// from the OS.
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Call {
    pub token: String,
    pub verb: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub args: Value,
}

/// The answer to a `ping`.
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Pong {
    pub pid: u32,
    pub version: String,
    /// No Verb call can succeed until the user unlocks kiskadee.
    pub locked: bool,
}

/// The answer to a `call` that ran.
#[derive(Debug, Deserialize, Serialize)]
pub struct Reply {
    pub body: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reads_used: Option<u64>,
    pub reads_remaining: u64,
}

/// A refusal or a failure, as the Client sees it.
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Problem {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reads_remaining: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_s: Option<u64>,
    /// The Broker's protocol version, on a `protocol.version` refusal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub v: Option<u64>,
}

impl Problem {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Problem {
            code: code.into(),
            message: message.into(),
            reads_remaining: None,
            retry_after_s: None,
            v: None,
        }
    }
}

/// One response frame.
#[derive(Debug, Deserialize, Serialize)]
pub struct Response {
    pub v: u64,
    #[serde(flatten)]
    pub outcome: Outcome,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Ok(Value),
    Denied(Problem),
    Error(Problem),
}

impl Outcome {
    /// The `ok` value, or the refusal or failure.
    pub fn into_ok(self) -> Result<Value, Problem> {
        match self {
            Outcome::Ok(value) => Ok(value),
            Outcome::Denied(problem) | Outcome::Error(problem) => Err(problem),
        }
    }
}

impl Response {
    pub fn ok(value: impl Serialize) -> Self {
        Response {
            v: VERSION,
            outcome: Outcome::Ok(serde_json::to_value(value).unwrap_or(Value::Null)),
        }
    }

    pub fn denied(problem: Problem) -> Self {
        Response {
            v: VERSION,
            outcome: Outcome::Denied(problem),
        }
    }

    pub fn error(problem: Problem) -> Self {
        Response {
            v: VERSION,
            outcome: Outcome::Error(problem),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("a response always serializes")
    }
}

/// Wraps `request` with the protocol version.
pub fn encode(request: &Request) -> Vec<u8> {
    let mut value = serde_json::to_value(request).expect("a request always serializes");
    if let Value::Object(map) = &mut value {
        map.insert("v".into(), VERSION.into());
    }
    serde_json::to_vec(&value).expect("a JSON value always serializes")
}

/// What the Broker makes of one request frame.
pub enum Parsed {
    Request(Request),
    /// Valid JSON the Broker answers with a refusal.
    Refuse(Problem),
    /// Not a JSON object: the connection is closed without a reply.
    Garbage,
}

pub fn parse(frame: &[u8]) -> Parsed {
    let Ok(Value::Object(mut map)) = serde_json::from_slice::<Value>(frame) else {
        return Parsed::Garbage;
    };
    match map.remove("v").and_then(|v| v.as_u64()) {
        Some(VERSION) => {}
        _ => {
            let mut problem = Problem::new(
                PROTOCOL_VERSION,
                format!(
                    "this Broker speaks protocol v{VERSION}; restart the Broker or upgrade the Client"
                ),
            );
            problem.v = Some(VERSION);
            return Parsed::Refuse(problem);
        }
    }
    match serde_json::from_value(Value::Object(map)) {
        Ok(request) => Parsed::Request(request),
        Err(e) => Parsed::Refuse(Problem::new(REQUEST_INVALID, e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_ping_round_trips_with_the_version() {
        let bytes = encode(&Request::Ping {});
        assert_eq!(bytes, br#"{"op":"ping","v":1}"#);
        assert!(matches!(parse(&bytes), Parsed::Request(Request::Ping {})));
    }

    #[test]
    fn another_protocol_version_is_refused_with_ours() {
        let Parsed::Refuse(problem) = parse(br#"{"v":2,"op":"ping"}"#) else {
            panic!("expected a refusal")
        };
        assert_eq!(
            (problem.code.as_str(), problem.v),
            (PROTOCOL_VERSION, Some(1))
        );
        assert!(matches!(parse(br#"{"op":"ping"}"#), Parsed::Refuse(_)));
    }

    #[test]
    fn non_json_and_non_objects_are_garbage() {
        assert!(matches!(parse(b"\xff\xfe"), Parsed::Garbage));
        assert!(matches!(parse(b"[1,2]"), Parsed::Garbage));
    }

    #[test]
    fn unknown_fields_and_ops_are_refused_as_invalid() {
        for frame in [
            &br#"{"v":1,"op":"exec","cmd":"UID FETCH 1:* BODY[]"}"#[..],
            br#"{"v":1,"op":"call","token":"t","verb":"list","raw":"x"}"#,
            br#"{"v":1,"op":"ping","peer_pid":1}"#,
        ] {
            let Parsed::Refuse(problem) = parse(frame) else {
                panic!("expected a refusal for {}", String::from_utf8_lossy(frame))
            };
            assert_eq!(problem.code, REQUEST_INVALID);
        }
    }
}
