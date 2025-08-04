//! OtpAuth URIs: https://github.com/google/google-authenticator/wiki/Key-Uri-Format
//! TOTP: https://www.rfc-editor.org/rfc/rfc6238.txt
//! HOTP: https://www.rfc-editor.org/rfc/rfc4226.txt

use hmac::{digest::crypto_common, Hmac, Mac};

use std::{borrow::Cow, str::FromStr, time::UNIX_EPOCH};

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
    InvalidLength(crypto_common::InvalidLength)
}

impl From<ParseError> for TotpError {
    fn from(value: ParseError) -> Self {
        Self::UriError(value)
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

pub fn calculate(uri: &str) -> Result<u32,TotpError> {
    // URL format:
    //   otpauth://totp/<label>?secret=********************************&issuer=<issuer>
    let uri = url::Url::from_str(uri)?;
    let Some(secret_b32) = query_get!(uri, "secret") else {
        return Err(TotpError::MissingSecret)
    };

    // TODO: parse digits and period

    let secret = match data_encoding::BASE32_NOPAD.decode(secret_b32.as_bytes()) {
        Ok(s) => s,
        Err(e) => return Err(TotpError::DecodeError(e))
    };

    let algorithm = query_get!(uri, "algorithm").unwrap_or(Cow::Borrowed("sha1")).into_owned();

    // TOTP = HOTP(K, T)
    //
    // K = Key, should be the same length as the output of the HMAC hash
    // X = Time step in seconds (default 30s)
    // T = Current Unix time / X
    //
    // The value of T will remain the same as the Unix time increases
    // for X steps. This allows for some grace time between the prover's
    // calculation and the verifier's calculation.
    //
    let now = std::time::SystemTime::now().duration_since(UNIX_EPOCH)
            .expect("Can not get current time");
    let counter: u32 = now.as_secs().div_euclid(30) as u32;
    let counter = counter.to_be_bytes();

    // HOTP(K,C) = Truncate(HMAC-SHA-1(K,C))
    //
    // C = 8 byte counter value, this is set to T for TOTP, in plain HOTP
    //     this counter can be based on something else than time.

    // Step 1: Generate an HMAC-SHA-1 value (20 byte string)
    let digest = hmac_digest(secret, &counter, &algorithm)?;

    // Step 2: Generate a 4-byte string (Dynamic Truncation)
    //
    // Interpret the last 4 bits of the digest as a number (0-15)
    // and read 4 bytes from that position
    let offset = digest.last().expect("Bad digest") & 0x0f;
    let trunc: Vec<u8> = digest.iter().skip(offset as usize).take(4).copied().collect();

    // Step 3: Compute an HOTP value
    // Let Snum  = StToNum(Sbits)   // Convert S to a number in 0...2^{31}-1
    let value: u32 = (trunc[0] as u32) + 
                     ((trunc[1] as u32) << 2) + 
                     ((trunc[2] as u32) << 4) + 
                     ((trunc[3] as u32) << 6);
    // Return D = Snum mod 10^Digit //  D is a number in the range 0...10^{Digit}-1
    let value = value % 10_000;

    println!("{:0>6}", value);
    Ok(value)
}

#[cfg(test)]
mod test {
    use crate::calculate;

    #[test]
    fn calculate_test() {
        let uri = "otpauth://totp/:test?secret=NBSWY3DPEB4EICQ&algorithm=SHA1&digits=6&period=30&lock=false";
        let code = calculate(uri).unwrap();
        assert_eq!(code, 111222)
    }
}
