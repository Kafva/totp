use std::process::ExitCode;

use clap::{Parser, crate_version};

use totp::calculate_totp_now;

#[derive(Parser)]
#[command(version = crate_version!(), about = "Decoder for TOTP URLs")]
struct Args {
    #[arg(help = "String to decode, otpauth://totp/...")]
    url: Option<String>
}

fn main() -> ExitCode {
    let args = Args::parse();

    let url = match args.url {
       Some(url) => url,
       None => {
            let mut buf = String::new();
            let Ok(_) = std::io::stdin().read_line(&mut buf) else {
                println!("Error reading input");
                return ExitCode::FAILURE
            };
            buf
       },
    };

    match calculate_totp_now(url.as_str()) {
        Ok(code) => {
            println!("{}", code);
            ExitCode::SUCCESS
        },
        Err(err) => {
            println!("Error: {}", err);
            ExitCode::FAILURE
        }
    }
}
