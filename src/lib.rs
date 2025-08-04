//!
//!
//! HOTP: https://www.rfc-editor.org/rfc/rfc4226.txt
//! TOTP: https://www.rfc-editor.org/rfc/rfc6238.txt
//!

use hmac::{digest::crypto_common, Hmac, Mac};

use std::{borrow::Cow, str::FromStr};

use url::{self, ParseError};

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

fn hmac_digest(secret: [u8] algorithm: &str) -> Vec<u8> {

}

pub fn calculate(uri: &str) -> Result<u32,TotpError> {
    // URL format:
    //   otpauth://totp/<label>?secret=********************************&issuer=<issuer>
    let uri = url::Url::from_str(uri)?;
    let Some(secret_b32) = uri.query_pairs().find(|k| k.0 == "secret").map(|k| k.1) else {
        return Err(TotpError::MissingSecret)
    };

    // TODO: parse digits and period


    let secret = match data_encoding::BASE32_NOPAD.decode(secret_b32.as_bytes()) {
        Ok(s) => s,
        Err(e) => return Err(TotpError::DecodeError(e))
    };

    // Using `.to_vec()` here is not performant but the alternative with
    // generics is a bit to verbose.
    let digest = match uri.query_pairs().find(|k| k.0 == "algorithm").map(|k| k.1) {
        Some(Cow::Borrowed("sha256") | Cow::Borrowed("SHA256")) => {
            Hmac::<sha2::Sha256>::new_from_slice(secret.as_slice())?
                .finalize().into_bytes().to_vec()
        },
        Some(Cow::Borrowed("sha512") | Cow::Borrowed("SHA512")) => {
            Hmac::<sha2::Sha512>::new_from_slice(secret.as_slice())?
                .finalize().into_bytes().to_vec()
        },
        Some(_) | None => {
            Hmac::<sha1::Sha1>::new_from_slice(secret.as_slice())?
                .finalize().into_bytes().to_vec()
        }
    };

    println!("{:?}", digest);

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
    //
    // HOTP(K,C) = Truncate(HMAC-SHA-1(K,C))
    //
    // C = 8 byte counter value, this is set to T for TOTP, in plain HOTP
    //     this counter can be based on something else than time.
    //
    // All values treated as big-endian



   // Step 1: Generate an HMAC-SHA-1 value (20 byte string)

   // Step 2: Generate a 4-byte string (Dynamic Truncation)

   // Step 3: Compute an HOTP value
   // Let Snum  = StToNum(Sbits)   // Convert S to a number in
   //                                  0...2^{31}-1
   // Return D = Snum mod 10^Digit //  D is a number in the range
   //                                  0...10^{Digit}-1


    Ok(0)
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

