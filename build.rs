use std::string;
use std::{env, fs, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        //.out_dir("./src")
        .compile(&["./proto/services.proto"], &["./proto"])?;
    let out_dir = env::current_dir().unwrap();
    let dest_path = PathBuf::from(out_dir).join("./target/debug/config.json");
    fs::write(&dest_path, include_str!("config.json")).unwrap();
    Ok(())
}