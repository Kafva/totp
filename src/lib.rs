//! OtpAuth URIs: https://github.com/google/google-authenticator/wiki/Key-Uri-Format
//! TOTP: https://www.rfc-editor.org/rfc/rfc6238.txt
//! HOTP: https://www.rfc-editor.org/rfc/rfc4226.txt

use hmac::{digest::crypto_common, Hmac, Mac};

use std::{borrow::Cow, num::ParseIntError, str::FromStr, time::{self, UNIX_EPOCH}};

use url::{self, ParseError};

macro_rules! query_get {
    ($uri:ident, $key:literal) => (
        $uri.query_pairs().find(|k| k.0 == $key).map(|k| k.1)
    )
}

#[derive(Debug)]
pub enum TotpError {
    MissingSecret,
    DecodeError(data_encoding::DecodeError),
    UriError(url::ParseError),
    InvalidLength(crypto_common::InvalidLength),
    ParseIntError(ParseIntError)
}

impl From<ParseError> for TotpError {
    fn from(value: ParseError) -> Self {
        Self::UriError(value)
    }
}

impl From<ParseIntError> for TotpError {
    fn from(value: ParseIntError) -> Self {
        Self::ParseIntError(value)
    }
}

impl From<crypto_common::InvalidLength> for TotpError {
    fn from(value: crypto_common::InvalidLength) -> Self {
        Self::InvalidLength(value)
    }
}

fn hmac_digest(secret: Vec<u8>, counter: &[u8], algorithm: &str) -> Result<Vec<u8>,TotpError> {
    // Using `.to_vec()` here is not performant but the alternative with
    // generics is a bit too verbose.
    let digest = match algorithm {
        "sha256" | "SHA256" => {
            let mut hmac = Hmac::<sha2::Sha256>::new_from_slice(secret.as_slice())?;
            hmac.update(counter);
            hmac.finalize().into_bytes().to_vec()
        },
        "sha512" | "SHA512" => {
            let mut hmac = Hmac::<sha2::Sha512>::new_from_slice(secret.as_slice())?;
            hmac.update(counter);
            hmac.finalize().into_bytes().to_vec()
        },
        _ => {
            let mut hmac = Hmac::<sha1::Sha1>::new_from_slice(secret.as_slice())?;
            hmac.update(counter);
            hmac.finalize().into_bytes().to_vec()
        }
    };
    Ok(digest)
}

/// Calculate the digits for a TOTP URL at `seconds` since `UNIX_EPOCH`.
pub fn calculate(uri: &str, seconds: u64) -> Result<u32,TotpError> {
    // Parse URL
    let uri = url::Url::from_str(uri)?;
    let Some(secret_b32) = query_get!(uri, "secret") else {
        return Err(TotpError::MissingSecret)
    };

    let period = match query_get!(uri, "period") {
        Some(d) => str::parse::<u64>(&d)?,
        _ => 30
    };

    let digits = match query_get!(uri, "digits") {
        Some(d) => str::parse::<u32>(&d)?,
        _ => 6
    };

    let secret = match data_encoding::BASE32_NOPAD.decode(secret_b32.as_bytes()) {
        Ok(s) => s,
        Err(e) => return Err(TotpError::DecodeError(e))
    };

    let algorithm = query_get!(uri, "algorithm").unwrap_or(Cow::Borrowed("sha1")).into_owned();

    // HOTP(K,C) = Truncate(HMAC-SHA-1(K,C))
    // TOTP = HOTP(K, T)
    //
    // K = Secret key
    // C = 8 byte counter value
    // X = Time step in seconds (default 30s)
    // T = Current Unix time / X
    //
    // The value of T will remain the same as the Unix time increases
    // for X steps. This allows for some grace time between the prover's
    // calculation and the verifier's calculation.
    //
    let counter: u32 = seconds.div_euclid(period) as u32;
    let counter = counter.to_be_bytes();

    // Generate an HMAC-SHA-* value (X byte string)
    let digest = hmac_digest(secret, &counter, &algorithm)?;

    // Generate a 4-byte string (Dynamic Truncation)
    // Interpret the last 4 bits of the digest as a number (0-15)
    // and read 4 bytes from that position
    let offset = (digest.last().expect("Bad digest") & 0x0f) as usize;
    let slice = digest.as_slice();
    let value: u32 = ((slice[offset] as u32) << 24) + 
                     ((slice[offset+1] as u32) << 16) + 
                     ((slice[offset+2] as u32) << 8) + 
                     ((slice[offset+3] as u32) << 0);
    // Zero out the most significant bit
    let value = value & 0x7fffffff;

    // Return desired number of digits from the value
    let value = value % 10_u32.pow(digits);

    Ok(value)
}

/// Calculate the digits for a TOTP URL at the current time
pub fn calculate_now(uri: &str) -> Result<u32,TotpError> {
    let now = time::SystemTime::now()
        .duration_since(UNIX_EPOCH).expect("Failed to determine time");
    calculate(uri, now.as_secs())
}

#[cfg(test)]
mod test {
    use crate::calculate;

    #[test]
    fn calculate_test() {
        let uri = "otpauth://totp/:test?secret=NBSWY3DPEB4EICQ&algorithm=SHA1&digits=6&period=30";
        let code = calculate(uri, 111).unwrap();
        assert_eq!(code, 061_078)
    }
}
