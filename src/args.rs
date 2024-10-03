use clap::{Arg, ArgAction, Command};

const VERSION: &str = "0.1.0";

#[derive(Debug, Clone)]
pub struct Args {
    pub input_file: String,
    pub output_file: String,
    pub num_children: u32,
    pub new_mnemonic: bool,
    pub short_word_count: bool,
}

impl Args {
    pub fn parse() -> Result<Args, clap::Error> {
        let m = Command::new("kderive")
            .about(format!(
                "kderive: Derive Master and n Child addresses and private keys for a given 12/24 mnemonic seed phrases - v{}", 
                VERSION
            ))
            .version(VERSION)
            .arg(
                Arg::new("input-file")
                    .long("input-file")
                    .short('i').required(true)
                    .help("Path to input file. Input file must be the seed phrase you wish to derive from.")
                    .value_name("FILE")
            )
            .arg(
                Arg::new("output-file")
                    .long("output-file")
                    .short('o').required(true)
                    .help("Path to output file.")
                    .value_name("FILE")
            )
            .arg(
                Arg::new("num-children")
                    .long("num-children")
                    .short('n').required(false)
                    .help("Number of child wallets to output. Default: 0")
                    .value_parser(clap::value_parser!(u32))
            )
            .arg(
                Arg::new("new-mnemonic")
                .long("new-mnemonic")
                .short('x'). required(false)
                .help("If true input-file will be ignored. New mnemonic will be created and kderive will create an output file using this new mnemonic.")
                    .action(ArgAction::SetTrue),
            )
            .arg(
                Arg::new("short-word-count")
                    .long("short-word-count")
                    .short('s').required(false)
                    .help("When set with the new-mnemonic flag also will return a mnemonic of length 12 instead of 24. Default: 24")
                    .action(ArgAction::SetTrue)
            )
        .get_matches();

        let args = Args {
            input_file: m
                .get_one::<String>("input-file")
                .unwrap_or(&"".to_string())
                .clone(),
            output_file: m
                .get_one::<String>("output-file")
                .unwrap_or(&"".to_string())
                .clone(),
            num_children: m.get_one::<u32>("num-children").unwrap_or(&0).clone(),
            new_mnemonic: *m.get_one::<bool>("new-mnemonic").unwrap_or(&false),
            short_word_count: *m.get_one::<bool>("short-word-count").unwrap_or(&false),
        };
        Ok(args)
    }
}

pub fn parse_args() -> Args {
    match Args::parse() {
        Ok(args) => args,
        Err(err) => {
            println!("{err}");
            std::process::exit(1);
        }
    }
}
