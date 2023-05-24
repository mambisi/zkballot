#![feature(error_in_core)]

mod ballot;
mod ecdsa;
mod error;
mod gadget;
mod server;

use crate::ballot::sha3;
use crate::ecdsa::{Keypair, SecretKey};
use crate::server::run_sever;
use clap::{Args, Parser, Subcommand};
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;
use std::net::IpAddr;
use std::str::FromStr;
use primitive_types::H256;
use serde_json::json;

#[derive(Parser)]
#[clap(
    version = "1.0",
    author = "sepana <mambisi@teza.ai>",
    about = "Clap4 API CLI"
)]
struct Cli {
    #[clap(subcommand)]
    pub command: Command,
}

#[derive(Parser, Debug)]
enum Command {
    #[clap(about = "Runs the server")]
    Run(Run),

    #[clap(about = "Signs a message with a secret key")]
    Sign(Sign),

    #[clap(about = "Generates a keypair")]
    Keypair(KeypairArgs),
}

#[derive(Args, Debug)]
struct Run {
    #[clap(short = 'h', long)]
    pub host: IpAddr,

    #[clap(short = 'p', long)]
    pub port: u16,
}

#[derive(Args, Debug)]
struct Sign {
    #[clap(short = 'm', long)]
    pub message: String,

    #[clap(short = 'k', long)]
    pub key: String,
}

#[derive(Args, Debug)]
struct KeypairArgs {
    #[clap(short = 'u', long)]
    pub username: Option<String>,

    #[clap(short = 'p', long)]
    pub password: Option<String>,
}

fn main() -> std::io::Result<()> {
    let opt = <Cli as Parser>::parse();

    match opt.command {
        Command::Run(run) => {
            // run the server
            run_sever(run.host, run.port)?;
            println!("Running server on host {} and port {}", run.host, run.port);
        }
        Command::Sign(sign) => {
            // sign the message
            let sk = SecretKey::from_bytes(H256::from_str(sign.key.as_str()).unwrap().as_bytes()).expect("failed to parse your key");
            println!(
                "{}",
                hex::encode(sk.sign(sign.message.as_bytes()).expect("failed to sign message").to_bytes())
            );
        }
        Command::Keypair(args) => {
            // generate keypair
            let mut rng = match (args.username, args.password) {
                (Some(username), Some(password)) => {
                    ChaChaRng::from_seed(sha3((username + &password).as_bytes()).to_fixed_bytes())
                }
                _ => ChaChaRng::from_entropy(),
            };
            let keypair = Keypair::generate(&mut rng);

            let out  = json!({
                "secret" : keypair.secret.hash(),
                "public" : keypair.secret.hash(),
            });
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
    }
    Ok(())
}
