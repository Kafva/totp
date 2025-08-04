//! OtpAuth URIs: https://github.com/google/google-authenticator/wiki/Key-Uri-Format
//! TOTP: https://www.rfc-editor.org/rfc/rfc6238.txt
//! HOTP: https://www.rfc-editor.org/rfc/rfc4226.txt

use hmac::{digest::crypto_common, Hmac, Mac};

use std::{borrow::Cow, num::ParseIntError, str::FromStr, time::{self, UNIX_EPOCH}};

use url::{self, ParseError};

macro_rules! query_get {
    ($url:ident, $key:literal) => (
        $url.query_pairs().find(|k| k.0 == $key).map(|k| k.1)
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

/// Calculate the digits for a TOTP URL at present time
pub fn calculate_totp_now(url: &str) -> Result<u32,TotpError> {
    let now = time::SystemTime::now()
        .duration_since(UNIX_EPOCH).expect("Failed to determine current time");
    calculate_totp(url, now.as_secs())
}

/// Calculate the digits for a TOTP URL at `epoch`
pub fn calculate_totp(url: &str, epoch: u64) -> Result<u32,TotpError> {
    let url = url::Url::from_str(url)?;

    let Some(secret_b32) = query_get!(url, "secret") else {
        return Err(TotpError::MissingSecret)
    };
    let secret = match data_encoding::BASE32_NOPAD.decode(secret_b32.as_bytes()) {
        Ok(s) => s,
        Err(e) => return Err(TotpError::DecodeError(e))
    };

    let period = match query_get!(url, "period") {
        Some(d) => str::parse::<u64>(&d)?,
        _ => 30
    };

    let digits = match query_get!(url, "digits") {
        Some(d) => str::parse::<u32>(&d)?,
        _ => 6
    };

    let algorithm = query_get!(url, "algorithm").unwrap_or(Cow::Borrowed("sha1")).into_owned();

    let counter: u64 = epoch / period;
    calculate_hotp(secret, &algorithm, digits, counter)
}

/// Calculate the digits for a HOTP
///
/// HOTP(K,C) = Truncate(HMAC-SHA-1(K,C))
/// TOTP = HOTP(K, T)
///
/// K = Secret key
/// C = 8 byte counter value
/// X = Time step in seconds (default 30s)
/// T = Current Unix time / X
///
/// The value of T will remain the same as the Unix time increases
/// for X steps. This allows for some grace time between the prover's
/// calculation and the verifier's calculation.
fn calculate_hotp(
    secret: Vec<u8>,
    algorithm: &str,
    digits: u32,
    counter: u64
) -> Result<u32,TotpError> {
    // Generate an HMAC-SHA-* value (X byte string)
    let digest = calculate_hmac(secret, counter, &algorithm)?;

    // Generate a 4-byte string (Dynamic Truncation)
    // Interpret the last 4 bits of the digest as a number (0-15)
    // and read 4 bytes from that position
    let offset = (digest.last().expect("Bad digest") & 0x0f) as usize;
    let digest = digest.as_slice();
    let value: u32 = ((digest[offset] as u32) << 24) + 
                     ((digest[offset+1] as u32) << 16) + 
                     ((digest[offset+2] as u32) << 8) + 
                     ((digest[offset+3] as u32) << 0);
    // Zero out the most significant bit
    let value = value & 0x7fffffff;

    // Return desired number of digits from the value
    let value = value % 10_u32.pow(digits);

    Ok(value)
}

fn calculate_hmac(secret: Vec<u8>, counter: u64, algorithm: &str) -> Result<Vec<u8>,TotpError> {
    // You could use generics here to deduplicate but it becomes a bit too verbose.
    let digest = match algorithm {
        "sha256" | "SHA256" => {
            let mut hmac = Hmac::<sha2::Sha256>::new_from_slice(secret.as_slice())?;
            hmac.update(&counter.to_be_bytes());
            hmac.finalize().into_bytes().to_vec()
        },
        "sha512" | "SHA512" => {
            let mut hmac = Hmac::<sha2::Sha512>::new_from_slice(secret.as_slice())?;
            hmac.update(&counter.to_be_bytes());
            hmac.finalize().into_bytes().to_vec()
        },
        _ => {
            let mut hmac = Hmac::<sha1::Sha1>::new_from_slice(secret.as_slice())?;
            hmac.update(&counter.to_be_bytes());
            hmac.finalize().into_bytes().to_vec()
        }
    };
    Ok(digest)
}

#[cfg(test)]
mod test {
    use crate::calculate_totp;

    #[test]
    fn calculate_totp_test() {
        let url = "otpauth://tester@some.email.com/:foo?secret=NBSWY3DPEB4EICQ&algorithm=SHA1&digits=6&period=30";
        let code = calculate_totp(url, 3330).unwrap();
        assert_eq!(code, 061_078);

        let url = "otpauth://tester@some.email.com/:foo?secret=NBSWY3DPEBZWQYJSGU3AU&algorithm=SHA256&digits=7";
        let code = calculate_totp(url, 3330).unwrap();
        assert_eq!(code, 2_655_304);

        let url = "otpauth://tester@some.email.com/:foo?secret=NBSWY3DPEBZWQYJVGEZAU&algorithm=SHA512&digits=8&period=10";
        let code = calculate_totp(url, 3330).unwrap();
        assert_eq!(code, 39_265_203);
    }
}
