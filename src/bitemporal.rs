//! Valid time and trigger scope (spec §2.2, §2.3.3).
//!
//! AHL keeps three times per anchored statement and never conflates them: `valid_time`
//! (asserted domain validity), `issued_at` (asserted creation) and the log-attested
//! incorporation time. Only `valid_time` participates in trigger scoping, and only the entry
//! index ever orders anything.
//!
//! Every RFC 3339 value in this crate is parsed into [`time::OffsetDateTime`] and compared as
//! an instant. Lexicographic comparison of RFC 3339 *strings* is not equivalent — `"2026-08-16T12:00:00Z"`
//! and `"2026-08-16T14:00:00+02:00"` denote the same instant but differ as strings, and
//! `"2026-08-16T13:00:00+02:00"` sorts after the first while preceding it in time.

use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::{AhlError, AhlResult};

/// Parse an RFC 3339 timestamp, naming the field in any error.
///
/// # Errors
///
/// Returns [`AhlError::Timestamp`] if `value` is not a valid RFC 3339 instant.
pub fn parse_rfc3339(field: &str, value: &str) -> AhlResult<OffsetDateTime> {
    OffsetDateTime::parse(value, &Rfc3339).map_err(|source| AhlError::Timestamp {
        field: field.to_owned(),
        value: value.to_owned(),
        source,
    })
}

/// A statement's asserted domain validity (spec §2.2).
///
/// Either a point in time or an interval whose upper bound may be open (`"to": null`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidTime {
    /// A single instant.
    Point(OffsetDateTime),
    /// A half-open-or-closed interval; `to` of `None` means "still valid".
    Interval {
        /// Lower bound.
        from: OffsetDateTime,
        /// Upper bound, or `None` for an open interval.
        to: Option<OffsetDateTime>,
    },
}

impl ValidTime {
    /// Read a `valid_time` member, which is either an RFC 3339 string or `{from, to}`.
    ///
    /// # Errors
    ///
    /// Returns [`AhlError::Field`] if the member is absent or neither shape, and
    /// [`AhlError::Timestamp`] if a bound is not RFC 3339.
    pub fn from_payload(payload: &Value) -> AhlResult<Self> {
        let value =
            payload.get("valid_time").ok_or_else(|| AhlError::Field("valid_time".to_owned()))?;
        if let Some(point) = value.as_str() {
            return Ok(Self::Point(parse_rfc3339("valid_time", point)?));
        }
        let object = value.as_object().ok_or_else(|| AhlError::Field("valid_time".to_owned()))?;
        let from = object
            .get("from")
            .and_then(Value::as_str)
            .ok_or_else(|| AhlError::Field("valid_time.from".to_owned()))?;
        // An absent `to` is not the same as `"to": null`; the spec spells the open interval
        // with an explicit null, so require the member to be present.
        let to =
            match object.get("to").ok_or_else(|| AhlError::Field("valid_time.to".to_owned()))? {
                Value::Null => None,
                other => Some(parse_rfc3339(
                    "valid_time.to",
                    other.as_str().ok_or_else(|| AhlError::Field("valid_time.to".to_owned()))?,
                )?),
            };
        Ok(Self::Interval { from: parse_rfc3339("valid_time.from", from)?, to })
    }

    /// Whether this valid time intersects `[effective_from, ∞)` (spec §2.3.3).
    ///
    /// For a point time: affected iff `valid_time >= effective_from`. For an interval:
    /// affected iff `to` is null or `to >= effective_from` — the lower bound is irrelevant,
    /// because an interval reaching past `effective_from` intersects the ray however early it
    /// started.
    #[must_use]
    pub fn intersects_ray(&self, effective_from: OffsetDateTime) -> bool {
        match *self {
            Self::Point(at) => at >= effective_from,
            Self::Interval { to, .. } => to.is_none_or(|end| end >= effective_from),
        }
    }
}

/// A trigger's `scope` block (spec §2.3.3). Scopeless triggers are malformed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scope {
    /// The instant from which the trigger takes effect.
    pub effective_from: OffsetDateTime,
    /// `true` — every derivation consuming the record is affected regardless of valid time.
    pub retroactive: bool,
}

impl Scope {
    /// Read the `scope` member of a trigger payload.
    ///
    /// # Errors
    ///
    /// Returns [`AhlError::Field`] if `scope`, `scope.effective_from` or `scope.retroactive` is
    /// absent or ill-typed — a scopeless trigger is malformed, never silently retroactive.
    pub fn from_payload(payload: &Value) -> AhlResult<Self> {
        let scope = payload.get("scope").ok_or_else(|| AhlError::Field("scope".to_owned()))?;
        let effective_from = scope
            .get("effective_from")
            .and_then(Value::as_str)
            .ok_or_else(|| AhlError::Field("scope.effective_from".to_owned()))?;
        let retroactive = scope
            .get("retroactive")
            .and_then(Value::as_bool)
            .ok_or_else(|| AhlError::Field("scope.retroactive".to_owned()))?;
        Ok(Self {
            effective_from: parse_rfc3339("scope.effective_from", effective_from)?,
            retroactive,
        })
    }

    /// Whether a derivation with valid time `valid_time` falls in this trigger's scope.
    #[must_use]
    pub fn covers(&self, valid_time: ValidTime) -> bool {
        self.retroactive || valid_time.intersects_ray(self.effective_from)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn at(value: &str) -> OffsetDateTime {
        parse_rfc3339("test", value).expect("test timestamp is RFC 3339")
    }

    fn scope(effective_from: &str, retroactive: bool) -> Scope {
        Scope::from_payload(&json!({
            "scope": { "effective_from": effective_from, "retroactive": retroactive }
        }))
        .expect("well-formed scope")
    }

    #[test]
    fn retroactive_scope_covers_every_valid_time() {
        let s = scope("2026-08-01T00:00:00Z", true);
        assert!(s.covers(ValidTime::Point(at("2020-01-01T00:00:00Z"))));
        assert!(s.covers(ValidTime::Interval {
            from: at("1999-01-01T00:00:00Z"),
            to: Some(at("2000-01-01T00:00:00Z")),
        }));
    }

    #[test]
    fn point_valid_time_is_affected_from_the_boundary_inclusive() {
        let s = scope("2026-08-01T00:00:00Z", false);
        assert!(!s.covers(ValidTime::Point(at("2026-07-31T23:59:59Z"))));
        assert!(s.covers(ValidTime::Point(at("2026-08-01T00:00:00Z"))));
        assert!(s.covers(ValidTime::Point(at("2026-09-01T00:00:00Z"))));
    }

    #[test]
    fn open_intervals_are_always_affected() {
        let s = scope("2026-08-01T00:00:00Z", false);
        assert!(s.covers(ValidTime::Interval { from: at("1999-01-01T00:00:00Z"), to: None }));
    }

    #[test]
    fn closed_intervals_ending_before_the_boundary_are_not_affected() {
        let s = scope("2026-08-01T00:00:00Z", false);
        assert!(!s.covers(ValidTime::Interval {
            from: at("2026-05-01T00:00:00Z"),
            to: Some(at("2026-07-01T00:00:00Z")),
        }));
        assert!(s.covers(ValidTime::Interval {
            from: at("2026-05-01T00:00:00Z"),
            to: Some(at("2026-08-01T00:00:00Z")),
        }));
    }

    #[test]
    fn offsets_are_compared_as_instants_not_as_strings() {
        let s = scope("2026-08-16T12:00:00Z", false);
        // 13:00+02:00 is 11:00Z — earlier than the boundary, though the string sorts later.
        assert!(!s.covers(ValidTime::Point(at("2026-08-16T13:00:00+02:00"))));
        assert!("2026-08-16T13:00:00+02:00" > "2026-08-16T12:00:00Z");
    }

    #[test]
    fn valid_time_reads_both_shapes() {
        assert_eq!(
            ValidTime::from_payload(&json!({ "valid_time": "2026-08-16T12:00:00Z" }))
                .expect("point"),
            ValidTime::Point(at("2026-08-16T12:00:00Z"))
        );
        assert_eq!(
            ValidTime::from_payload(&json!({
                "valid_time": { "from": "2026-08-16T12:00:00Z", "to": null }
            }))
            .expect("open interval"),
            ValidTime::Interval { from: at("2026-08-16T12:00:00Z"), to: None }
        );
    }

    #[test]
    fn a_scopeless_trigger_is_rejected_not_defaulted() {
        assert!(matches!(
            Scope::from_payload(&json!({ "type": "retraction" })),
            Err(AhlError::Field(_))
        ));
    }
}
