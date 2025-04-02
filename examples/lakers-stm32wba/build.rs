use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed=link.x");
    println!("cargo:rerun-if-changed=device.x");

    Ok(())
}
