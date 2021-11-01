use std::io;
//use sha2::{Sha256, Digest};
use secp256k1::{Secp256k1, SecretKey, PublicKey};
use bitcoin_hashes::{hash160, sha256, sha256d, Hash};
use base58::ToBase58;

struct Coin {
    symbol: String,
    pubkey_address: u8,
    secret_key: u8,
}

fn main() {
    let mut passphrase = String::new();
    println!("Enter passphrase:");
    io::stdin().read_line(&mut passphrase).expect("Can't read passphrase ...");
    trim_newline(&mut passphrase); // passphrase.truncate(passphrase.len() - 1);

    //let passphrase = "myverysecretandstrongpassphrase_noneabletobrute";
    println!("Passphrase: '{}'", passphrase);
    /*
    let mut hasher = Sha256::new();
    hasher.update(passphrase);
    let mut result = hasher.finalize();
    let hash_size = result.len();
    */

    let hash_byte_array = sha256::Hash::hash(&passphrase.as_bytes()).into_inner();

    let mut result = hash_byte_array;
    let hash_size = result.len();

    result[0] &= 248;
    result[hash_size-1] &= 127;
    result[hash_size-1] |= 64;

    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&result[..]).unwrap(); //expect("32 bytes, within curve order");
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    println!("Secret Key: {}", secret_key);
    println!("Public Key: {}", public_key);

    let coins = vec![
        Coin { symbol: String::from("BTC"), pubkey_address: 0, secret_key: 128},
        Coin { symbol: String::from("KMD"), pubkey_address: 60, secret_key: 188},
        Coin { symbol: String::from("LTC"), pubkey_address: 48, secret_key: 176},
        Coin { symbol: String::from("GAME"), pubkey_address: 38, secret_key: 166},
        Coin { symbol: String::from("EMC2"), pubkey_address: 33, secret_key: 176},
        Coin { symbol: String::from("GIN"), pubkey_address: 38, secret_key: 198},
        Coin { symbol: String::from("AYA"), pubkey_address: 23, secret_key: 176},
        Coin { symbol: String::from("GleecBTC"), pubkey_address: 35, secret_key: 65},
    ];

    for cur_coin in coins {
        println!("\x1B[01;37m[ \x1B[01;32m{}\x1B[01;37m ]\x1B[0m", cur_coin.symbol);
        println!("Address: {}", addr_from_raw_pubkey(&public_key, cur_coin.pubkey_address).unwrap());
        println!("    WIF: {}", wif_from_raw_privkey(&secret_key, cur_coin.secret_key).unwrap());
    }

    // let mut pubkey_hex_str = hex::encode(public_key.serialize());
    // println!("{}", pubkey_hex_str);
}

fn addr_from_raw_pubkey(pubkey: &PublicKey, network_byte: u8) -> Result<String, String> {
    let pubkey_ser = pubkey.serialize();
    let mut addr = "< undefined >".to_string();
    if pubkey_ser.len() == 33 {
        // hash160 HASH160 (SHA256 then RIPEMD160)
       let hash_byte_array = hash160::Hash::hash(&pubkey_ser).into_inner();
       let mut hash_vec = hash_byte_array.to_vec();
       hash_vec.insert(0, network_byte);
       let checksum_sha256d = sha256d::Hash::hash(&hash_vec).into_inner();
       let checksum = &checksum_sha256d[..4];
       hash_vec.extend_from_slice(&checksum);
       addr = hash_vec.to_base58();
       Ok(addr)
    } else {
       Err(addr)
    }
}

pub fn wif_from_raw_privkey(privkey: &SecretKey, add_byte: u8) -> Result<String, String> {

    let mut wif = "< undefined >".to_string();
    if !privkey.is_empty() {
        let privkey_str = privkey.to_string();
        let privkey_vec = hex::decode(privkey_str).unwrap();
        let mut hash_vec = privkey_vec;
        hash_vec.insert(0, add_byte);
        hash_vec.push(0x01); // compressed
        let checksum_sha256d = sha256d::Hash::hash(&hash_vec).into_inner();
        let checksum = &checksum_sha256d[..4];
        hash_vec.extend_from_slice(&checksum);
        wif = hash_vec.to_base58();
        Ok(wif)
    } else {
        Err(wif)
    }
}

fn trim_newline(s: &mut String) {
    if s.ends_with('\n') {
        s.pop();
        if s.ends_with('\r') {
            s.pop();
        }
    }
}