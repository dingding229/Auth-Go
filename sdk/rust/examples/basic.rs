const AUTH_CONFIG: &str = "authgo2.请在构建时替换为后台接入配置";
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = authgo::Client::new(AUTH_CONFIG)?;
    let result = client.check(&std::env::var("AUTHGO_LICENSE")?)?;
    println!("{}", result.status);
    Ok(())
}
