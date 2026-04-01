/// The three identity tiers in the OpenHearth auth model.
///
/// - [ghost]: No identity. No server contact. Local only.
/// - [token]: Anonymous UUID. Encrypted blob sync. No PII.
/// - [named]: Email + passkey. Full identity. GDPR erasure rights.
enum AuthTier { ghost, token, named }
