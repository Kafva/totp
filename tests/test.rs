use totp::{calculate_totp, calculate_totp_now, TotpError};

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
