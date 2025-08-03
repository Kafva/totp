//! 
//!
//! HOTP: https://www.rfc-editor.org/rfc/rfc4226.txt
//! TOTP: https://www.rfc-editor.org/rfc/rfc6238.txt
//!
//! URL format:
//!   otpauth://totp/<label>?secret=********************************&issuer=<issuer>

pub fn decode(uri: &str) -> String {
    uri.to_string()
}
