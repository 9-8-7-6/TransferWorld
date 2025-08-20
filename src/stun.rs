use rand::RngCore;
use rand::rng;
use std::net::Ipv4Addr;
use tokio::net::UdpSocket;
use tokio::time::{Duration, timeout};

const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;

pub async fn stun_query(server: &str) -> anyhow::Result<(String, u16)> {
    // Create UDP socket
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect(server).await?;

    // STUN Binding Request
    let mut txid = [0u8; 12];
    rng().fill_bytes(&mut txid);

    let mut req = [0u8; 20];
    req[0..2].copy_from_slice(&STUN_BINDING_REQUEST.to_be_bytes()); // type
    req[2..4].copy_from_slice(&0u16.to_be_bytes()); // length=0
    req[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes()); // cookie
    req[8..20].copy_from_slice(&txid); // txid

    socket.send(&req).await?;

    // Receive the Response
    let mut buf = [0u8; 1500];
    let (n, _) = timeout(Duration::from_secs(3), socket.recv_from(&mut buf)).await??;

    if n < 20 {
        anyhow::bail!("Response too short");
    }
    let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
    let msg_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let rx_txid = &buf[8..20];

    if cookie != STUN_MAGIC_COOKIE {
        anyhow::bail!("Invalid magic cookie");
    }
    if rx_txid != txid {
        anyhow::bail!("Transaction ID mismatch");
    }
    if msg_type != 0x0101 {
        anyhow::bail!("Not a Binding Success Response");
    }
    if 20 + msg_len > n {
        anyhow::bail!("Declared length exceeds received size");
    }

    // parse attributes
    let mut pos = 20usize;
    let end = 20 + msg_len;

    while pos + 4 <= end {
        let attr_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let attr_len = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
        pos += 4;

        if pos + attr_len > end {
            break;
        }

        let attr_val = &buf[pos..pos + attr_len];

        match attr_type {
            ATTR_XOR_MAPPED_ADDRESS => {
                if attr_len >= 8 && attr_val[1] == 0x01 {
                    // IPv4
                    let xport = u16::from_be_bytes([attr_val[2], attr_val[3]]);
                    let port = xport ^ ((STUN_MAGIC_COOKIE >> 16) as u16);

                    let mut xaddr = [0u8; 4];
                    xaddr.copy_from_slice(&attr_val[4..8]);
                    let cookie_bytes = STUN_MAGIC_COOKIE.to_be_bytes();
                    let ip = Ipv4Addr::new(
                        xaddr[0] ^ cookie_bytes[0],
                        xaddr[1] ^ cookie_bytes[1],
                        xaddr[2] ^ cookie_bytes[2],
                        xaddr[3] ^ cookie_bytes[3],
                    );
                    return Ok((ip.to_string(), port));
                }
            }
            ATTR_MAPPED_ADDRESS => {
                if attr_len >= 8 && attr_val[1] == 0x01 {
                    let port = u16::from_be_bytes([attr_val[2], attr_val[3]]);
                    let ip = Ipv4Addr::new(attr_val[4], attr_val[5], attr_val[6], attr_val[7]);
                    return Ok((ip.to_string(), port));
                }
            }
            _ => {}
        }

        // 4-byte allign
        let pad = (4 - (attr_len % 4)) % 4;
        pos += attr_len + pad;
    }

    anyhow::bail!("No XOR-MAPPED-ADDRESS / MAPPED-ADDRESS found");
}
