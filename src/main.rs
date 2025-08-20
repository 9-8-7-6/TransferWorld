pub mod qr_code;
pub mod stun;

use crate::qr_code::create_qr_code;
use crate::stun::stun_query;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    create_qr_code();
    match stun_query("stun.l.google.com:19302").await {
        Ok((ip, port)) => println!("External IP: {ip}, Port: {port}"),
        Err(e) => eprintln!("STUN query failed: {e}"),
    }
    Ok(())
}
