//! Terminal rendering of the HomeKit setup QR code.

use qrcode::render::unicode::Dense1x2;

/// Draws `payload` as a QR code using half-height block characters, or
/// `None` if it cannot be encoded.
///
/// Light modules are drawn as solid blocks so the code reads correctly on a
/// dark terminal background.
pub fn render(payload: &str) -> Option<String> {
    let code = qrcode::QrCode::new(payload).ok()?;
    Some(code.render::<Dense1x2>().dark_color(Dense1x2::Light).light_color(Dense1x2::Dark).build())
}
