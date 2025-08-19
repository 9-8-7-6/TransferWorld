use image::Luma;
use qrcode::QrCode;
use std::fs;

fn create_qr_code() {
    let code = QrCode::new(b"01234567").unwrap();

    let image = code.render::<Luma<u8>>().build();

    fs::create_dir_all("./image").unwrap();

    image.save("./image/qrcode.png").unwrap();

    let _ = code.render().light_color(' ').dark_color('#').build();
}

fn main() {
    create_qr_code();
}
