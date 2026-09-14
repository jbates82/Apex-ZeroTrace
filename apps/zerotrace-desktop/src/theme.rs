//! Visual language.
//!
//! Security software should read as an instrument of record, not a thriller.
//! No skulls, no scanlines, no pulsing red. The palette is a cool neutral, and
//! color is spent only where state genuinely differs: a desaturated green for
//! protected, amber for warning, a muted red once a vault is armed or gone.
//! Everything else is gray, so the colored thing on screen is always the
//! thing that matters.

use egui::{Color32, FontFamily, FontId, Rounding, Stroke, TextStyle, Visuals};

pub const INK: Color32 = Color32::from_rgb(0x16, 0x17, 0x1A);
pub const PANEL: Color32 = Color32::from_rgb(0x1E, 0x20, 0x24);
pub const RAISED: Color32 = Color32::from_rgb(0x27, 0x2A, 0x2F);
pub const EDGE: Color32 = Color32::from_rgb(0x33, 0x37, 0x3D);
pub const TEXT: Color32 = Color32::from_rgb(0xE8, 0xE9, 0xEA);
pub const MUTED: Color32 = Color32::from_rgb(0x8D, 0x92, 0x98);
pub const DIM: Color32 = Color32::from_rgb(0x63, 0x68, 0x6E);

pub const OK: Color32 = Color32::from_rgb(0x6F, 0xB0, 0x8A);
pub const WARN: Color32 = Color32::from_rgb(0xD6, 0xA4, 0x5C);
pub const ALERT: Color32 = Color32::from_rgb(0xD1, 0x68, 0x5C);

pub const R: Rounding = Rounding::same(5.0);

/// Color for an assurance word, so the table reads at a glance.
pub fn assurance_color(label: &str) -> Color32 {
    match label {
        "VERIFIED" => OK,
        "BEST EFFORT" => WARN,
        "FAILED" => ALERT,
        _ => DIM,
    }
}

/// Color for a deadman state.
pub fn state_color(label: &str) -> Color32 {
    match label {
        "NORMAL" => OK,
        "WARNING" => WARN,
        "CRITICAL" | "ARMED" => ALERT,
        "DESTROYED" => ALERT,
        _ => MUTED,
    }
}

pub fn install(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    style.text_styles = [
        (TextStyle::Heading, FontId::new(21.0, FontFamily::Proportional)),
        (TextStyle::Body, FontId::new(13.5, FontFamily::Proportional)),
        (TextStyle::Button, FontId::new(13.5, FontFamily::Proportional)),
        (TextStyle::Small, FontId::new(11.5, FontFamily::Proportional)),
        (TextStyle::Monospace, FontId::new(12.5, FontFamily::Monospace)),
    ]
    .into();

    let mut v = Visuals::dark();
    v.panel_fill = INK;
    v.window_fill = PANEL;
    v.extreme_bg_color = Color32::from_rgb(0x13, 0x14, 0x17);
    v.faint_bg_color = RAISED;
    v.override_text_color = Some(TEXT);
    v.window_rounding = R;
    v.window_stroke = Stroke::new(1.0_f32, EDGE);
    v.selection.bg_fill = OK.gamma_multiply(0.30);
    v.selection.stroke = Stroke::new(1.0_f32, OK);

    for w in [&mut v.widgets.inactive, &mut v.widgets.hovered, &mut v.widgets.active] {
        w.rounding = R;
    }
    v.widgets.noninteractive.rounding = R;
    v.widgets.noninteractive.bg_fill = PANEL;
    v.widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, EDGE);
    v.widgets.noninteractive.fg_stroke = Stroke::new(1.0_f32, TEXT);
    v.widgets.inactive.bg_fill = RAISED;
    v.widgets.inactive.weak_bg_fill = RAISED;
    v.widgets.inactive.bg_stroke = Stroke::new(1.0_f32, EDGE);
    v.widgets.inactive.fg_stroke = Stroke::new(1.0_f32, TEXT);
    v.widgets.hovered.bg_fill = Color32::from_rgb(0x2E, 0x32, 0x38);
    v.widgets.hovered.weak_bg_fill = Color32::from_rgb(0x2E, 0x32, 0x38);
    v.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, Color32::from_rgb(0x4A, 0x4F, 0x56));
    v.widgets.hovered.fg_stroke = Stroke::new(1.0_f32, TEXT);
    v.widgets.active.bg_fill = Color32::from_rgb(0x36, 0x3B, 0x42);
    v.widgets.active.weak_bg_fill = Color32::from_rgb(0x36, 0x3B, 0x42);
    v.widgets.active.bg_stroke = Stroke::new(1.0_f32, OK);
    v.widgets.active.fg_stroke = Stroke::new(1.0_f32, TEXT);

    style.visuals = v;
    style.spacing.item_spacing = egui::vec2(8.0, 8.0);
    style.spacing.button_padding = egui::vec2(12.0, 7.0);
    style.spacing.interact_size.y = 28.0;
    ctx.set_style(style);
}

pub fn human_bytes(n: u64) -> String {
    const U: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if v >= 100.0 { format!("{v:.0} {}", U[i]) } else { format!("{v:.1} {}", U[i]) }
}

pub fn human_duration(mut s: u64) -> String {
    let d = s / 86400;
    s %= 86400;
    let h = s / 3600;
    let m = (s % 3600) / 60;
    // Sub-hour spans are real now that a heartbeat can be five minutes and a
    // service interval can be thirty seconds. "0h 5m" and "0m" both read as
    // bugs rather than durations.
    let secs = s % 60;
    match (d, h, m) {
        (0, 0, 0) => format!("{secs}s"),
        (0, 0, _) => format!("{m}m"),
        (0, _, _) => format!("{h}h {m}m"),
        _ => format!("{d}d {h}h {m}m"),
    }
}

/// Formats a Unix timestamp as UTC.
///
/// Done by hand rather than pulling in a date library: an audit log needs a
/// legible instant, not calendar arithmetic, and a raw epoch integer is not
/// something a person can check against their memory of yesterday.
pub fn human_time(unix: i64) -> String {
    if unix <= 0 {
        return "-".into();
    }
    let days_total = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);

    // Civil-from-days, the standard algorithm shifted to a March-based year.
    let z = days_total + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };

    format!("{year:04}-{month:02}-{d:02} {h:02}:{m:02}:{s:02}")
}
