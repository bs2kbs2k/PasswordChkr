use futures::executor::block_on;
use hex::ToHex;
use sha1::{Digest, Sha1};
use std::str::FromStr;

use std::env;
use surf::Result;

fn main() {
    let args: Vec<String> = env::args().collect();
    println!(
        "{:?}",
        check_pwned_passwords(args.get(1).expect("usage: check [password]").clone()).unwrap()
    );
}

fn check_pwned_passwords(password: String) -> Result<usize> {
    let digest = Sha1::digest(password.as_ref()).encode_hex_upper::<String>();
    let (prefix, suffix) = digest.split_at(5);
    block_on(surf::get("https://api.pwnedpasswords.com/range/".to_owned() + prefix).recv_string())?
        .lines()
        .filter(|a| a.starts_with(suffix))
        .collect::<Vec<_>>()
        .get(0)
        .map_or(Ok(0), |a| {
            Ok(usize::from_str(a.split(":").collect::<Vec<_>>().last().unwrap()).unwrap())
        })
}
