#![allow(unused)]
use kaspa_addresses::{Address, Prefix, Version};
use kaspa_bip32::{DerivationPath, ExtendedPrivateKey, Language, Mnemonic, SecretKey, WordCount};
use kaspa_wallet_keys::derivation_path;
use kaspa_wallet_keys::keypair;
use kaspa_wallet_keys::prelude::PrivateKey;
use kaspa_wrpc_client::prelude::NetworkType;
use kaspa_wrpc_client::{error::Error, result::Result};
use secp256k1::Secp256k1;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufWriter;
use std::str::FromStr;

pub fn build_new_mnemonic(word_count: u8) -> Result<String> {
    let wc = match word_count {
        12 => WordCount::Words12,
        24 => WordCount::Words24,
        _ => return Err(Error::Custom(format!("Incorrect word count choice"))),
    };
    let lang = Language::English;
    let mnemonic = match Mnemonic::random(wc, lang) {
        Ok(mnemonic) => mnemonic,
        Err(e) => {
            return Err(Error::Custom(format!(
                "Failed to generate a random seed phrase: {}",
                e
            )))
        }
    };
    let phrase = mnemonic.phrase().to_string();
    Ok(phrase)
}

fn build_from_imported_mnemonic(phrase: String, index: Option<u32>) -> Result<PrivateKey> {
    let child = index.unwrap_or(0); // Use unwrap_or to set a default value of 0

    let phrase_vec: Vec<&str> = phrase.split_whitespace().collect();
    let word_count = phrase_vec.len();
    let wc = match word_count {
        12 => WordCount::Words12,
        24 => WordCount::Words24,
        _ => return Err(Error::Custom(format!("Phrase must have 12 or 24 words"))),
    };
    let lang = Language::English;
    let mnemonic = match Mnemonic::new(phrase, lang) {
        Ok(mnemonic) => mnemonic,
        Err(e) => return Err(Error::Custom(format!("Failed to create mnemonic: {}", e))),
    };
    let entropy: String = mnemonic.get_entropy();
    let seed = mnemonic.to_seed("");
    let xprv = ExtendedPrivateKey::<SecretKey>::new(seed).unwrap();

    // Use format! to correctly insert the child index into the string
    let derivation_path_str = format!("m/44'/111111'/0'/0/{}", child);
    let derivation_path = match DerivationPath::from_str(&derivation_path_str) {
        Ok(derivation_path) => derivation_path,
        Err(e) => {
            return Err(Error::Custom(format!(
                "Failed to create DerivationPath: {}",
                e
            )))
        }
    };

    let private_key = PrivateKey::from(xprv.derive_path(&derivation_path).unwrap().private_key());
    Ok(private_key)
}

fn address_from_private_key(private_key: &PrivateKey, prefix: &Prefix) -> Address {
    let secret_key = secp256k1::SecretKey::from_slice(&private_key.secret_bytes()).unwrap();
    let public_key = secp256k1::PublicKey::from_secret_key_global(&secret_key);
    let (x_only_public_key, _) = public_key.x_only_public_key();
    let payload = x_only_public_key.serialize();
    let address = Address::new(*prefix, Version::PubKey, &payload);
    address
}

pub fn write_and_build_child_keys(phrase: String, n: u32, output_file: String) -> Result<()> {
    let file = match File::create(output_file) {
        Ok(file) => file,
        Err(e) => return Err(Error::Custom(format!("Failed to create file: {e}"))),
    };
    let mut writer = BufWriter::new(file);
    let header = format!("Master Phrase: {}\n\n", phrase.clone());
    writer
        .write_all(header.as_bytes())
        .expect("Error writing to file...");
    let num_children = n + 1;
    for i in 0..num_children {
        match build_from_imported_mnemonic(phrase.clone(), Some(i)) {
            Ok(private_key) => {
                let index_header = format!("## Index: {}", i);
                writer
                    .write_all(index_header.as_bytes())
                    .expect("Error writing to file...");
                writer.write_all(b"\n").expect("Error writing to file...");
                let mainnet_address_temp =
                    address_from_private_key(&private_key, &Prefix::Mainnet).address_to_string();
                let mainnet_address = mainnet_address_temp.as_bytes();
                writer
                    .write_all(mainnet_address)
                    .expect("Error writing to file...");
                writer.write_all(b"\n").expect("Error writing to file...");
                let testnet_address_temp =
                    address_from_private_key(&private_key, &Prefix::Testnet).address_to_string();
                let testnet_address = testnet_address_temp.as_bytes();
                writer
                    .write_all(testnet_address)
                    .expect("Error writing to file...");
                writer.write_all(b"\n").expect("Error writing to file...");
                let private_key_hex_temp = private_key.to_hex();
                let private_key_hex = private_key_hex_temp.as_bytes();
                writer
                    .write_all(private_key_hex)
                    .expect("Error writing to file...");
                writer.write_all(b"\n\n").expect("Error writing to file...");
            }
            Err(e) => return Err(Error::Custom(format!("Failed to create child {i}: {e}"))),
        }
    }

    Ok(())
}
