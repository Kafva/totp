//! OtpAuth URLs: https://github.com/google/google-authenticator/wiki/Key-Uri-Format
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

#[derive(Debug, PartialEq)]
pub enum TotpError {
    MissingSecret,
    TooManyDigits,
    Base32DecodeError(data_encoding::DecodeError),
    UrlParseError(url::ParseError),
    InvalidHmacKeyLength(crypto_common::InvalidLength),
    ParseIntError(ParseIntError)
}

impl std::fmt::Display for TotpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use TotpError::*;
        match self {
            MissingSecret => f.write_str("Missing `secret=` parameter in URL"),
            TooManyDigits => f.write_str("The number of `digits=` specified is too large"),
            UrlParseError(err) => err.fmt(f),
            Base32DecodeError(err) => err.fmt(f),
            ParseIntError(err) => err.fmt(f),
            InvalidHmacKeyLength(err) => err.fmt(f),
        }
    }
}

impl From<ParseError> for TotpError {
    fn from(value: ParseError) -> Self {
        Self::UrlParseError(value)
    }
}

impl From<ParseIntError> for TotpError {
    fn from(value: ParseIntError) -> Self {
        Self::ParseIntError(value)
    }
}

impl From<crypto_common::InvalidLength> for TotpError {
    fn from(value: crypto_common::InvalidLength) -> Self {
        Self::InvalidHmacKeyLength(value)
    }
}

/// Calculate the digits for a TOTP URL at present time
pub fn calculate_totp_now(url: &str) -> Result<(String,u64),TotpError> {
    let now = time::SystemTime::now()
        .duration_since(UNIX_EPOCH).expect("Failed to determine current time");
    calculate_totp(url, now.as_secs())
}

/// Calculate the digits for a TOTP URL at `epoch`, returns the zero-padded
/// code and the validity period.
pub fn calculate_totp(url: &str, epoch: u64) -> Result<(String,u64),TotpError> {
    let url = url::Url::from_str(url)?;

    let Some(secret) = query_get!(url, "secret") else {
        return Err(TotpError::MissingSecret)
    };
    let secret = secret.to_uppercase();
    let secret = secret.as_bytes();
    let secret = match data_encoding::BASE32_NOPAD.decode(secret) {
        Ok(s) => s,
        Err(e) => {
            return Err(TotpError::Base32DecodeError(e))
        },
    };

    let period = match query_get!(url, "period") {
        Some(d) => str::parse::<u64>(&d)?,
        _ => 30
    };

    let digits = match query_get!(url, "digits") {
        Some(d) => {
            let d = str::parse::<u32>(&d)?;
            if d > 9 { return Err(TotpError::TooManyDigits); } else { d }
        },
        _ => 6
    };

    let algorithm = query_get!(url, "algorithm").unwrap_or(Cow::Borrowed("sha1")).into_owned();

    let counter: u64 = epoch / period;

    let code = calculate_hotp(secret, &algorithm, digits, counter)?;

    // Return the zero-padded result, the caller should not need to parse the
    // digits from the URL
    let code = match digits {
        6 => format!("{:0>6}", code),
        7 => format!("{:0>7}", code),
        8 => format!("{:0>8}", code),
        9 => format!("{:0>9}", code),
        _ => return Err(TotpError::TooManyDigits)
    };
    Ok((code.to_string(), period))
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

    // Return desired number of digits
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
mod tests {
    use super::{calculate_totp, calculate_totp_now, TotpError};

    #[test]
    fn calculate_totp_test() {
        let url = "otpauth://tester@some.email.com/:foo?secret=NBSWY3DPEB4EICQ&algorithm=SHA1&digits=6&period=30";
        let (code, _) = calculate_totp(url, 3330).unwrap();
        assert_eq!(code, "061078");

        let url = "otpauth://tester@some.email.com/:foo?secret=NBSWY3DPEBZWQYJSGU3AU&algorithm=SHA256&digits=7";
        let (code, _) = calculate_totp(url, 3330).unwrap();
        assert_eq!(code, "2655304");

        let url = "otpauth://tester@some.email.com/:foo?secret=NBSWY3DPEBZWQYJVGEZAU&algorithm=SHA512&digits=8&period=10";
        let (code, _) = calculate_totp(url, 1110).unwrap();
        assert_eq!(code, "39265203");
    }

    #[test]
    fn calculate_totp_errors_test() {
        let url = "otpauth://a/?secret=AA&digits=100";
        assert_eq!(calculate_totp_now(url).err().unwrap(), TotpError::TooManyDigits);

        let url = "otpauth://a/?secret=AA&digits=-10";
        let int_err = str::parse::<u64>("-10").err().unwrap();
        assert_eq!(calculate_totp_now(url).err().unwrap(), TotpError::ParseIntError(int_err));

        let url = "otpauth://a/?secret=@@@@@@@@";
        let dec_err = data_encoding::DecodeError { position: 0, kind: data_encoding::DecodeKind::Symbol };
        assert_eq!(calculate_totp_now(url).err().unwrap(), TotpError::Base32DecodeError(dec_err));

        let url = "otpauth://a/";
        assert_eq!(calculate_totp_now(url).err().unwrap(), TotpError::MissingSecret);

        let url = "";
        let url_err = url::ParseError::RelativeUrlWithoutBase;
        assert_eq!(calculate_totp_now(url).err().unwrap(), TotpError::UrlParseError(url_err));
    }
}
