use std::process::ExitCode;

use clap::Parser;

use totp::calculate;

#[derive(Parser)]
#[command(version, about = "Decoder for TOTP URIs")]
struct Args {
    #[arg(help = "String to decode, otpauth://totp/...")]
    uri: Option<String>
}

fn main() -> ExitCode {
    let args = Args::parse();

    let uri = match args.uri {
       Some(uri) => uri,
       None => {
            let mut buf = String::new();
            let Ok(_) = std::io::stdin().read_line(&mut buf) else {
                println!("Error reading input");
                return ExitCode::FAILURE
            };
            buf
       },
    };

    let code = calculate(uri.as_str()).unwrap();
    println!("{}", code);

    ExitCode::SUCCESS
}
