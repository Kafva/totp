# totp

Simple decoder for TOTP URLs, if you need more functionality, e.g.
generating QR codes, consider a more complete library like
[totp_rs](https://github.com/constantoine/totp-rs).

```rust
use totp::calculate_totp_now;

fn main() {
    let url = "otpauth://tester@some.email.com/?secret=NBSWY3DPEB4EICQ&algorithm=SHA256";
    let code = calculate_totp_now(url).unwrap();
    println!("{}", code);
}
```
