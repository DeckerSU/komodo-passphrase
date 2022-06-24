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

const F_DISPLAY_UNCOMPRESSED: bool = false;

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
    let public_key_uncompressed_str = hex::encode(&public_key.serialize_uncompressed());

    println!("            Private Key: {}", secret_key);
    println!("  Compressed Public Key: {}", public_key);
    if F_DISPLAY_UNCOMPRESSED {
        println!("Uncompressed Public Key: {}", public_key_uncompressed_str);
    }


    let coins = vec![
        Coin { symbol: String::from("BTC"), pubkey_address: 0, secret_key: 128},
        Coin { symbol: String::from("KMD"), pubkey_address: 60, secret_key: 188},
        Coin { symbol: String::from("LTC"), pubkey_address: 48, secret_key: 176},
        Coin { symbol: String::from("GAME"), pubkey_address: 38, secret_key: 166},
        Coin { symbol: String::from("EMC2"), pubkey_address: 33, secret_key: 176},
        Coin { symbol: String::from("GIN"), pubkey_address: 38, secret_key: 198},
        Coin { symbol: String::from("AYA"), pubkey_address: 23, secret_key: 176},
        Coin { symbol: String::from("GleecBTC"), pubkey_address: 35, secret_key: 65},
        Coin { symbol: String::from("MIL"), pubkey_address: 50, secret_key: 239},
    ];

    for cur_coin in coins {
        println!("\x1B[01;37m[ \x1B[01;32m{}\x1B[01;37m ]\x1B[0m", cur_coin.symbol);
        println!("      Compressed WIF: {}", wif_from_raw_privkey(&secret_key, cur_coin.secret_key, true).unwrap());
        if F_DISPLAY_UNCOMPRESSED {
            println!("    Uncompressed WIF: {}", wif_from_raw_privkey(&secret_key, cur_coin.secret_key, false).unwrap());
        }
        println!("  Compressed Address: {}", addr_from_raw_pubkey(&public_key, cur_coin.pubkey_address, true).unwrap());
        if F_DISPLAY_UNCOMPRESSED {
            println!("Uncompressed Address: {}", addr_from_raw_pubkey(&public_key, cur_coin.pubkey_address, false).unwrap());
        }
    }

    // let mut pubkey_hex_str = hex::encode(public_key.serialize());
    // println!("{}", pubkey_hex_str);
}

fn addr_from_raw_pubkey(pubkey: &PublicKey, network_byte: u8, f_compressed: bool) -> Result<String, String> {

    let pubkey_ser : Vec<u8> = if f_compressed {
        pubkey.serialize().to_vec()
    } else {
        pubkey.serialize_uncompressed().to_vec()
    };

    let mut addr = "< undefined >".to_string();
    if !pubkey_ser.is_empty() {
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

fn wif_from_raw_privkey(privkey: &SecretKey, add_byte: u8, f_compressed: bool) -> Result<String, String> {

    let mut wif = "< undefined >".to_string();
    if !privkey.is_empty() {
        let privkey_str = privkey.to_string();
        let privkey_vec = hex::decode(privkey_str).unwrap();
        let mut hash_vec = privkey_vec;
        hash_vec.insert(0, add_byte);
        if f_compressed {
            hash_vec.push(0x01);
        }
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

#[cfg(test)]
mod tests {

    use super::*; // super - link to the parent module ..

    #[test]
    fn privpub_test() {

        let passphrase = "myverysecretandstrongpassphrase_noneabletobrute";
        let hash_byte_array = sha256::Hash::hash(&passphrase.as_bytes()).into_inner();
        let mut result = hash_byte_array;
        let hash_size = result.len();

        result[0] &= 248;
        result[hash_size-1] &= 127;
        result[hash_size-1] |= 64;

        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&result[..]).unwrap(); //expect("32 bytes, within curve order");
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        assert_eq!(format!("{}", secret_key), "907ece717a8f94e07de7bf6f8b3e9f91abb8858ebf831072cdbb9016ef53bc5d");
        assert_eq!(format!("{}", public_key), "02a854251adfee222bede8396fed0756985d4ea905f72611740867c7a4ad6488c1");
    }

    #[test]
    fn wifaddr_test() {

        let secp = Secp256k1::new();
        let key_arr = [0x90, 0x7e, 0xce, 0x71, 0x7a, 0x8f, 0x94, 0xe0, 0x7d, 0xe7, 0xbf, 0x6f, 0x8b, 0x3e, 0x9f, 0x91, 0xab, 0xb8, 0x85, 0x8e, 0xbf, 0x83, 0x10, 0x72, 0xcd, 0xbb, 0x90, 0x16, 0xef, 0x53, 0xbc, 0x5d];
        let secret_key = SecretKey::from_slice(&key_arr).unwrap();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        assert_eq!(format!("{}", wif_from_raw_privkey(&secret_key, 188, true).unwrap()),"UtrRXqvRFUAtCrCTRAHPH6yroQKUrrTJRmxt2h5U4QTUN1jCxTAh");
        assert_eq!(format!("{}", addr_from_raw_pubkey(&public_key,  60, true).unwrap()),"RVNKRr2uxPMxJeDwFnTKjdtiLtcs7UzCZn");
    }
}