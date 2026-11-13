fn main() -> Result<(), authgo::Error> {
    println!("{}", authgo::fingerprint()?);
    Ok(())
}
