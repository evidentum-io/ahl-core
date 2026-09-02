//! Canonicalization descriptors, descriptor digests, and dataset id validation.
//!
//! Normative source: **AHL I-D** draft-zatona-ahl-00, revision 0.4, §2.6 ("Record Identity,
//! Canonicalization, and Commitment Modes") and §6.3 ("Canonicalization Identifier
//! Conformance"). This module implements exactly the pieces those two sections fix: the
//! canonicalization descriptor `D = {canonicalization, media_type?}`, its canonical `JCS(D)`
//! encoding and digest `ddig`, and the dataset id syntax the commitment preimage depends on.
//!
//! # Why this module exists separately
//!
//! §2.6 states that the dataset id control-octet check is "exactly the check an implementation
//! omits", because the printable-ASCII range the general syntax rule already enforces makes the
//! check *look* redundant — every control octet is already outside `0x21..=0x7E`. It is kept
//! here as [`reject_dataset_id_control_octets`], a function with its own name and its own error
//! variant, so a future refactor of the syntax check cannot silently drop it.

use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};

use crate::error::{AhlError, AhlResult};

// ---------------------------------------------------------------------------
// Dataset id (I-D §2.6)
// ---------------------------------------------------------------------------

/// Dataset id length and printable-ASCII syntax (I-D §2.6).
///
/// A dataset id is a string of at least 1 and at most 128 characters, each a printable
/// US-ASCII character in `0x21..=0x7E` inclusive — every printable ASCII character except the
/// space.
///
/// # Errors
///
/// Returns [`AhlError::DatasetIdSyntax`] if `id` is empty, longer than 128 characters, or
/// contains a byte outside `0x21..=0x7E`.
pub fn validate_dataset_id_syntax(id: &str) -> AhlResult<()> {
    let valid = (1..=128).contains(&id.len()) && id.bytes().all(|b| (0x21..=0x7E).contains(&b));
    if valid {
        Ok(())
    } else {
        Err(AhlError::DatasetIdSyntax { id: id.to_owned() })
    }
}

/// Explicit, separately named rejection of any control octet in a dataset id (I-D §2.6).
///
/// The prohibition is stated as its own normative requirement in the I-D — not merely implied
/// by the printable-ASCII range above — because it is load-bearing: a dataset id containing
/// `0x1F` makes the commitment preimage ambiguous, since a verifier scanning for the first
/// `0x1F` separator would end `dsid` inside the id itself.
///
/// # Errors
///
/// Returns [`AhlError::DatasetIdControlOctet`] if `id` contains a byte in `0x00..=0x1F` or the
/// byte `0x7F`.
pub fn reject_dataset_id_control_octets(id: &str) -> AhlResult<()> {
    if id.bytes().any(|b| matches!(b, 0x00..=0x1F | 0x7F)) {
        Err(AhlError::DatasetIdControlOctet { id: id.to_owned() })
    } else {
        Ok(())
    }
}

/// Full dataset id validation (I-D §2.6): the control-octet rule, then the general syntax rule.
///
/// The control-octet check runs first so a dataset id carrying `0x1F` or `0x7F` — the exact
/// cases §2.6 calls out as load-bearing — is always rejected *by that rule specifically*, not
/// merely by the general syntax check that happens to also exclude those bytes.
///
/// # Errors
///
/// Returns [`AhlError::DatasetIdControlOctet`] or [`AhlError::DatasetIdSyntax`].
pub fn validate_dataset_id(id: &str) -> AhlResult<()> {
    reject_dataset_id_control_octets(id)?;
    validate_dataset_id_syntax(id)
}

// ---------------------------------------------------------------------------
// Canonicalization identifier (I-D §2.6)
// ---------------------------------------------------------------------------

/// Canonicalization identifier syntax (I-D §2.6).
///
/// Lowercase ASCII, restricted to `a`-`z`, `0`-`9` and `-`, at least 1 and at most 64 characters
/// long, and MUST begin with a character in `a`-`z`. Identifiers beginning `x-` are the
/// private-use namespace and satisfy this same production.
///
/// # Errors
///
/// Returns [`AhlError::CanonicalizationIdentifierSyntax`] if `id` does not match the production.
pub fn validate_canonicalization_identifier(id: &str) -> AhlResult<()> {
    let valid = (1..=64).contains(&id.len())
        && id.bytes().all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-'))
        && id.as_bytes().first().is_some_and(u8::is_ascii_lowercase);
    if valid {
        Ok(())
    } else {
        Err(AhlError::CanonicalizationIdentifierSyntax { id: id.to_owned() })
    }
}

// ---------------------------------------------------------------------------
// Descriptor media-type production (I-D §2.6)
// ---------------------------------------------------------------------------

/// RFC 9110 `tchar`: the characters a `token` may contain.
const fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// Consume the longest leading run of `tchar` bytes, returning `(token, rest)`.
fn take_token(s: &str) -> (&str, &str) {
    let end = s.bytes().position(|b| !is_tchar(b)).unwrap_or(s.len());
    s.split_at(end)
}

/// Consume leading `OWS` (`*( SP / HTAB )`).
fn skip_ows(s: &str) -> &str {
    s.trim_start_matches([' ', '\t'])
}

/// A parsed, not-yet-normalized `media-type-decl` (I-D §2.6).
struct ParsedMediaType<'a> {
    type_: &'a str,
    subtype: &'a str,
    /// `(name, value)` pairs in declaration order, both still in their original case.
    params: Vec<(&'a str, &'a str)>,
}

/// Parse the I-D §2.6 production:
///
/// ```text
/// media-type-decl = type "/" subtype *( OWS ";" OWS param )
/// param           = param-name "=" param-value
/// type, subtype, param-name, param-value = token
/// ```
///
/// This is deliberately narrower than the general media-type grammar of RFC 9110: no
/// quoted-string parameter value, no character outside US-ASCII, and no whitespace anywhere
/// but around `;`.
fn parse_media_type(input: &str) -> core::result::Result<ParsedMediaType<'_>, &'static str> {
    if !input.is_ascii() {
        return Err("every character must be US-ASCII");
    }

    let (type_, rest) = take_token(input);
    if type_.is_empty() {
        return Err("`type` must be a non-empty token");
    }
    let rest = rest.strip_prefix('/').ok_or("`type` and `subtype` must be separated by `/`")?;
    let (subtype, mut rest) = take_token(rest);
    if subtype.is_empty() {
        return Err("`subtype` must be a non-empty token");
    }

    let mut params = Vec::new();
    while !rest.is_empty() {
        rest = skip_ows(rest);
        rest = rest.strip_prefix(';').ok_or("expected `;` before the next parameter")?;
        rest = skip_ows(rest);
        let (name, tail) = take_token(rest);
        if name.is_empty() {
            return Err("a parameter name must be a non-empty token");
        }
        let tail = tail.strip_prefix('=').ok_or("a parameter must be `name=value`")?;
        let (value, tail) = take_token(tail);
        if value.is_empty() {
            return Err(
                "a parameter value must be a non-empty token — quoted-string values are not \
                 permitted",
            );
        }
        params.push((name, value));
        rest = tail;
    }

    Ok(ParsedMediaType { type_, subtype, params })
}

/// Validate and normalize a descriptor `media_type` value against the I-D §2.6 production.
///
/// Normalization (I-D §2.6):
///
/// * every `OWS` character is removed (a consequence of parsing into tokens, never retained);
/// * `type`, `subtype` and every parameter name are lowercased;
/// * the value of a parameter whose lowercased name is `charset` is lowercased; every other
///   parameter value is left exactly as written;
/// * parameters are sorted by lowercased parameter name, ascending lexicographic order of their
///   US-ASCII bytes;
/// * the normalized form is `type/subtype`, followed for each parameter, in that order, by `;`,
///   the parameter name, `=`, and the parameter value, with no whitespace anywhere.
///
/// # Errors
///
/// Returns [`AhlError::MediaTypeSyntax`] if `raw` does not match the production, or
/// [`AhlError::MediaTypeDuplicateParam`] if two parameter names tie once lowercased.
pub fn validate_media_type_production(raw: &str) -> AhlResult<String> {
    let parsed = parse_media_type(raw)
        .map_err(|detail| AhlError::MediaTypeSyntax { media_type: raw.to_owned(), detail })?;

    let mut params: Vec<(String, &str)> =
        parsed.params.iter().map(|(name, value)| (name.to_ascii_lowercase(), *value)).collect();
    params.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    for pair in params.windows(2) {
        if pair[0].0 == pair[1].0 {
            return Err(AhlError::MediaTypeDuplicateParam {
                media_type: raw.to_owned(),
                param: pair[0].0.clone(),
            });
        }
    }

    let mut normalized =
        format!("{}/{}", parsed.type_.to_ascii_lowercase(), parsed.subtype.to_ascii_lowercase());
    for (name, value) in &params {
        let value =
            if name == "charset" { value.to_ascii_lowercase() } else { (*value).to_owned() };
        normalized.push(';');
        normalized.push_str(name);
        normalized.push('=');
        normalized.push_str(&value);
    }
    Ok(normalized)
}

// ---------------------------------------------------------------------------
// The canonicalization descriptor and its digest (I-D §2.6 rule 2)
// ---------------------------------------------------------------------------

/// A dataset's canonicalization descriptor `D = {canonicalization, media_type?}` (I-D §2.6).
///
/// Constructing one validates the `canonicalization` identifier syntax and, where present, the
/// `media_type` descriptor production — normalizing `media_type` at construction time, because
/// only the normalized form ever enters the descriptor digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalizationDescriptor {
    canonicalization: String,
    /// Already normalized, never the raw declared value.
    media_type: Option<String>,
}

impl CanonicalizationDescriptor {
    /// Build a descriptor, validating and normalizing both members.
    ///
    /// # Errors
    ///
    /// Returns [`AhlError::CanonicalizationIdentifierSyntax`] if `canonicalization` does not
    /// match the identifier production, or [`AhlError::MediaTypeSyntax`] /
    /// [`AhlError::MediaTypeDuplicateParam`] if `media_type` is present and does not match the
    /// descriptor media-type production.
    pub fn new(canonicalization: impl Into<String>, media_type: Option<String>) -> AhlResult<Self> {
        let canonicalization = canonicalization.into();
        validate_canonicalization_identifier(&canonicalization)?;
        let media_type = media_type.map(|mt| validate_media_type_production(&mt)).transpose()?;
        Ok(Self { canonicalization, media_type })
    }

    /// The `canonicalization` identifier.
    #[must_use]
    pub fn canonicalization(&self) -> &str {
        &self.canonicalization
    }

    /// The normalized `media_type`, if the descriptor carries one.
    #[must_use]
    pub fn media_type(&self) -> Option<&str> {
        self.media_type.as_deref()
    }

    /// `JCS(D)` — the canonical descriptor encoding (I-D §2.6 rule 2): an object carrying
    /// `canonicalization` and, where present, the *normalized* `media_type`, and no other
    /// member.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut object = Map::new();
        object.insert("canonicalization".to_owned(), Value::String(self.canonicalization.clone()));
        if let Some(media_type) = &self.media_type {
            object.insert("media_type".to_owned(), Value::String(media_type.clone()));
        }
        crate::jcs(&Value::Object(object))
    }

    /// `ddig = SHA-256(JCS(D))`, the raw 32-octet descriptor digest (I-D §2.6).
    #[must_use]
    pub fn ddig(&self) -> [u8; 32] {
        Sha256::digest(self.canonical_bytes()).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- dataset id --------------------------------------------------------

    #[test]
    fn dataset_id_length_bounds() {
        assert!(validate_dataset_id_syntax("").is_err(), "empty id");
        assert!(validate_dataset_id_syntax(&"a".repeat(128)).is_ok(), "128 chars is the max");
        assert!(validate_dataset_id_syntax(&"a".repeat(129)).is_err(), "129 chars is over");
        assert!(validate_dataset_id_syntax("a").is_ok(), "1 char is the min");
    }

    #[test]
    fn dataset_id_admits_the_id_examples_the_i_d_names() {
        assert!(validate_dataset_id("customer:pii").is_ok());
        assert!(validate_dataset_id("eu/customers").is_ok());
    }

    #[test]
    fn dataset_id_rejects_space() {
        // 0x20 is outside 0x21..=0x7E but is not a control octet, so this must be caught by
        // the general syntax rule rather than by the control-octet check.
        assert!(reject_dataset_id_control_octets("bad id").is_ok());
        assert!(matches!(
            validate_dataset_id_syntax("bad id"),
            Err(AhlError::DatasetIdSyntax { .. })
        ));
        assert!(matches!(validate_dataset_id("bad id"), Err(AhlError::DatasetIdSyntax { .. })));
    }

    #[test]
    fn dataset_id_rejects_control_octets_by_their_own_check() {
        let with_0x1f = format!("scores{}bad", '\u{1f}');
        let with_0x7f = format!("scores{}bad", '\u{7f}');
        assert!(matches!(
            reject_dataset_id_control_octets(&with_0x1f),
            Err(AhlError::DatasetIdControlOctet { .. })
        ));
        assert!(matches!(
            reject_dataset_id_control_octets(&with_0x7f),
            Err(AhlError::DatasetIdControlOctet { .. })
        ));
        assert!(matches!(
            validate_dataset_id(&with_0x1f),
            Err(AhlError::DatasetIdControlOctet { .. })
        ));
        assert!(matches!(
            validate_dataset_id(&with_0x7f),
            Err(AhlError::DatasetIdControlOctet { .. })
        ));
    }

    #[test]
    fn dataset_id_rejects_non_ascii_bytes() {
        // `é` (U+00E9) encodes as two bytes, both >= 0x80: not a control octet, but also not
        // printable US-ASCII, so it must be caught by the syntax rule.
        let id = "caf\u{e9}";
        assert!(reject_dataset_id_control_octets(id).is_ok());
        assert!(matches!(validate_dataset_id_syntax(id), Err(AhlError::DatasetIdSyntax { .. })));
    }

    // -- canonicalization identifier ----------------------------------------

    #[test]
    fn canonicalization_identifier_syntax() {
        assert!(validate_canonicalization_identifier("jcs").is_ok());
        assert!(validate_canonicalization_identifier("exact-bytes").is_ok());
        assert!(validate_canonicalization_identifier("x-my-format").is_ok(), "private use");
        assert!(validate_canonicalization_identifier("").is_err(), "empty");
        assert!(validate_canonicalization_identifier(&"a".repeat(65)).is_err(), "too long");
        assert!(validate_canonicalization_identifier(&"a".repeat(64)).is_ok(), "64 is the max");
        assert!(validate_canonicalization_identifier("Jcs").is_err(), "uppercase");
        assert!(validate_canonicalization_identifier("-jcs").is_err(), "leading `-`");
        assert!(validate_canonicalization_identifier("1jcs").is_err(), "leading digit");
        assert!(validate_canonicalization_identifier("jcs_v1").is_err(), "underscore not admitted");
    }

    // -- media type production ----------------------------------------------

    #[test]
    fn media_type_normalizes_case_and_whitespace() {
        assert_eq!(validate_media_type_production("text/plain").unwrap(), "text/plain");
        assert_eq!(validate_media_type_production("TEXT/PLAIN").unwrap(), "text/plain");
        assert_eq!(
            validate_media_type_production("application/json; charset=UTF-8").unwrap(),
            "application/json;charset=utf-8"
        );
        // Non-`charset` parameter values keep their case.
        assert_eq!(
            validate_media_type_production("text/plain;Name=MixedCase").unwrap(),
            "text/plain;name=MixedCase"
        );
    }

    #[test]
    fn media_type_sorts_parameters_by_lowercased_name() {
        assert_eq!(
            validate_media_type_production("text/plain;b=2;a=1").unwrap(),
            validate_media_type_production("text/plain;a=1;b=2").unwrap(),
            "declaration order must not affect the normalized form"
        );
    }

    #[test]
    fn media_type_rejects_case_insensitive_duplicate_params() {
        // The exact example the I-D uses to justify testing on lowercased names.
        assert!(matches!(
            validate_media_type_production("text/plain;Foo=1;foo=2"),
            Err(AhlError::MediaTypeDuplicateParam { .. })
        ));
    }

    #[test]
    fn media_type_rejects_quoted_strings() {
        // The RFC 9110 example the I-D calls out: a quoted value containing `;` and `=` would
        // serialize indistinguishably from two bare parameters.
        assert!(matches!(
            validate_media_type_production(r#"text/plain;a="b;c=d""#),
            Err(AhlError::MediaTypeSyntax { .. })
        ));
    }

    #[test]
    fn media_type_rejects_non_ascii_and_missing_slash() {
        assert!(matches!(
            validate_media_type_production("text/plain; \u{00e9}=1"),
            Err(AhlError::MediaTypeSyntax { .. })
        ));
        assert!(matches!(
            validate_media_type_production("textplain"),
            Err(AhlError::MediaTypeSyntax { .. })
        ));
        assert!(
            matches!(
                validate_media_type_production("text/plain "),
                Err(AhlError::MediaTypeSyntax { .. })
            ),
            "no trailing OWS is admitted outside a `;` separator"
        );
    }

    // -- descriptor digest ---------------------------------------------------

    #[test]
    fn descriptor_digest_is_deterministic_and_order_independent() {
        let a = CanonicalizationDescriptor::new("jcs", None).expect("valid");
        let b = CanonicalizationDescriptor::new("jcs", None).expect("valid");
        assert_eq!(a.ddig(), b.ddig());

        let with_media_type =
            CanonicalizationDescriptor::new("exact-bytes", Some("text/plain".to_owned()))
                .expect("valid");
        assert_ne!(a.ddig(), with_media_type.ddig());
    }

    #[test]
    fn descriptor_digest_is_stable_across_equivalent_media_type_spellings() {
        let a = CanonicalizationDescriptor::new("exact-bytes", Some("TEXT/Plain".to_owned()))
            .expect("valid");
        let b = CanonicalizationDescriptor::new("exact-bytes", Some("text/plain".to_owned()))
            .expect("valid");
        assert_eq!(a.ddig(), b.ddig(), "descriptor equality is syntactic-normalized, not raw");
    }

    #[test]
    fn descriptor_construction_rejects_invalid_members() {
        assert!(CanonicalizationDescriptor::new("Bad", None).is_err());
        assert!(
            CanonicalizationDescriptor::new("jcs", Some("not a media type".to_owned())).is_err()
        );
    }
}
