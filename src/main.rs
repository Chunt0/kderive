mod args;
mod derive;

use args::{parse_args, Args};
use derive::{build_new_mnemonic, write_and_build_child_keys};
use kaspa_wrpc_client::{error::Error, result::Result};
use std::fs;

fn read_file_to_vec(file_path: &str) -> Result<Vec<String>> {
    // Read the entire file into a single String
    let contents = match fs::read_to_string(file_path) {
        Ok(contents) => contents,
        Err(e) => return Err(Error::Custom(format!("Failed to read file: {}", e))),
    };

    // Split the contents into lines and collect them into a Vec<String>
    let lines: Vec<String> = contents
        .lines() // This returns an iterator over &str
        .map(|line| line.to_string()) // Convert each &str to String
        .collect();

    Ok(lines)
}

fn main() -> Result<()> {
    let args: Args = parse_args();
    let input_file_path: String = args.input_file;
    let output_file_path: String = args.output_file;
    let num_children: u32 = args.num_children;

    if args.new_mnemonic {
        let word_count = if args.short_word_count { 12 } else { 24 };
        let master_phrase: String = match build_new_mnemonic(word_count) {
            Ok(phrase) => phrase,
            Err(e) => return Err(Error::Custom(format!("Error building new mnemonic: {}", e))),
        };
        let _ = write_and_build_child_keys(master_phrase, num_children, output_file_path);
    } else {
        match read_file_to_vec(&input_file_path) {
            Ok(lines) => {
                let master_phrase = lines[0].clone();
                let _ = write_and_build_child_keys(master_phrase, num_children, output_file_path);
            }
            Err(e) => eprintln!("Error: {e}"),
        }
    }
    Ok(())
}
