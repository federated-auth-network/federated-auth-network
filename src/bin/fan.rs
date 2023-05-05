use clap::Parser;
use federated_auth_network::http::boot_filesystem;
use josekit::jwk::Jwk;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    author = "Erik Hollensbe <erik@hollensbe.org>",
    about = "Start a Federated Auth Network Agent"
)]
struct Args {
    #[arg(
        help = "Generate a Signing JWK, and exit",
        long = "generate-signing-jwk"
    )]
    generate_signing_jwk: bool,

    #[arg(
        help = "Path to JWK w/ Private Key For Signing",
        default_value = "/etc/fan/signing.jwk",
        short = 'k',
        long = "signing-key"
    )]
    key: PathBuf,

    #[arg(
        help = "Listen addr:port",
        default_value = "0.0.0.0:80",
        short = 'l',
        long = "listen"
    )]
    listen_addr: String,

    #[arg(
        help = "Path to root of served filesystem",
        default_value = "/etc/fan/root",
        short = 'r',
        long = "root"
    )]
    root: PathBuf,

    #[arg(
        help = "Documents are in CBOR format",
        default_value = "false",
        long = "cbor"
    )]
    cbor: bool,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), davisjr::ServerError> {
    let args = Args::parse();

    if args.generate_signing_jwk {
        let key = Jwk::generate_ec_key(josekit::jwk::alg::ec::EcCurve::P256)?;
        println!("{}", serde_json::json!(key));
        return Ok(());
    }

    let key = std::fs::read(args.key)?;
    let signing_key = Jwk::from_bytes(key)?;

    match boot_filesystem(&args.listen_addr, args.root, args.cbor, signing_key).await {
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}
