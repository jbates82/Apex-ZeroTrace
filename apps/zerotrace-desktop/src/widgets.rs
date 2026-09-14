//! Small painted pieces shared across the window.

use crate::theme::*;
use egui::{Response, Rounding, Sense, Ui, Vec2};

/// A bordered surface. Hierarchy comes from spacing and hairlines rather than
/// uniform drop shadows, which would flatten everything to the same weight.
pub fn card<R>(ui: &mut Ui, inner: impl FnOnce(&mut Ui) -> R) -> R {
    egui::Frame::none()
        .fill(PANEL)
        .stroke(egui::Stroke::new(1.0_f32, EDGE))
        .rounding(R)
        .inner_margin(egui::Margin::symmetric(15.0, 13.0))
        .show(ui, |ui| {
            // Without this a frame shrinks to its content, so a sparse card
            // ends up narrower than a dense one directly below it and the
            // column looks accidental.
            ui.set_width(ui.available_width());
            inner(ui)
        })
        .inner
}

pub fn heading(ui: &mut Ui, text: &str) {
    ui.label(
        egui::RichText::new(text.to_uppercase()).size(11.0).color(MUTED),
    );
    ui.add_space(7.0);
}

/// Label left, monospace measurement right.
pub fn readout(ui: &mut Ui, key: &str, value: &str, color: egui::Color32) {
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new(key).size(12.5).color(MUTED));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.add(
                egui::Label::new(egui::RichText::new(value).monospace().size(12.5).color(color))
                    .truncate(true),
            );
        });
    });
}

/// Confidence bar. Fills toward the required threshold, which is marked.
pub fn confidence_meter(ui: &mut Ui, confidence: u32, required: u32, color: egui::Color32) {
    let w = ui.available_width();
    let (rect, _) = ui.allocate_exact_size(Vec2::new(w, 7.0), Sense::hover());
    let p = ui.painter();
    p.rect_filled(rect, R, egui::Color32::from_rgb(0x13, 0x14, 0x17));

    let frac = (confidence.min(100) as f32) / 100.0;
    let fw = (rect.width() - 2.0) * frac;
    if fw > 1.0 {
        p.rect_filled(
            egui::Rect::from_min_size(
                rect.min + Vec2::new(1.0, 1.0),
                Vec2::new(fw, rect.height() - 2.0),
            ),
            R,
            color,
        );
    }
    // The threshold matters more than the absolute value, so it is drawn.
    if required > 0 && required <= 100 {
        let x = rect.min.x + rect.width() * (required as f32 / 100.0);
        p.line_segment(
            [egui::pos2(x, rect.min.y - 1.0), egui::pos2(x, rect.max.y + 1.0)],
            egui::Stroke::new(1.0_f32, TEXT),
        );
    }
}

pub fn primary_button(ui: &mut Ui, text: &str, enabled: bool) -> Response {
    let w = ui.available_width();
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(w, 34.0), Sense::click());
    let p = ui.painter();
    let (bg, fg) = if !enabled {
        (egui::Color32::from_rgb(0x24, 0x27, 0x2B), DIM)
    } else if resp.is_pointer_button_down_on() {
        (OK.gamma_multiply(0.82), INK)
    } else if resp.hovered() {
        (OK.gamma_multiply(1.06), INK)
    } else {
        (OK, INK)
    };
    p.rect_filled(rect, R, bg);
    p.text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        text,
        egui::FontId::proportional(14.0),
        fg,
    );
    if enabled && resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    resp
}

pub fn quiet_button(ui: &mut Ui, text: &str) -> Response {
    ui.add(egui::Button::new(egui::RichText::new(text).size(13.0)).fill(RAISED))
}

/// Outlined rather than filled: a destructive action should be reachable but
/// never the most visually inviting thing on screen.
pub fn danger_button(ui: &mut Ui, text: &str) -> Response {
    ui.add(
        egui::Button::new(egui::RichText::new(text).size(13.0).color(ALERT))
            .fill(egui::Color32::TRANSPARENT)
            .stroke(egui::Stroke::new(1.0_f32, ALERT)),
    )
}

/// A navigation entry in the sidebar.
///
/// Selection is shown by a filled background and a left accent bar rather than
/// by color alone, so it reads at a glance and does not depend on hue.
pub fn nav_item(ui: &mut Ui, label: &str, detail: Option<&str>, selected: bool) -> Response {
    let w = ui.available_width();
    let h = if detail.is_some() { 42.0 } else { 32.0 };
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(w, h), Sense::click());
    let p = ui.painter();

    if selected {
        p.rect_filled(rect, R, RAISED);
        p.rect_filled(
            egui::Rect::from_min_size(rect.min, Vec2::new(2.5, rect.height())),
            Rounding::same(1.0),
            OK,
        );
    } else if resp.hovered() {
        p.rect_filled(rect, R, egui::Color32::from_rgb(0x23, 0x25, 0x2A));
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }

    let x = rect.min.x + 13.0;
    let text_color = if selected { TEXT } else { MUTED };
    match detail {
        Some(d) => {
            p.text(
                egui::pos2(x, rect.min.y + 11.0),
                egui::Align2::LEFT_CENTER,
                label,
                egui::FontId::proportional(13.5),
                text_color,
            );
            p.text(
                egui::pos2(x, rect.min.y + 29.0),
                egui::Align2::LEFT_CENTER,
                d,
                egui::FontId::monospace(11.0),
                DIM,
            );
        }
        None => {
            p.text(
                egui::pos2(x, rect.center().y),
                egui::Align2::LEFT_CENTER,
                label,
                egui::FontId::proportional(13.5),
                text_color,
            );
        }
    }
    resp
}

/// A section title inside the content pane.
pub fn section_title(ui: &mut Ui, title: &str, subtitle: &str) {
    ui.label(egui::RichText::new(title).size(19.0).strong().color(TEXT));
    if !subtitle.is_empty() {
        ui.add_space(2.0);
        ui.label(egui::RichText::new(subtitle).size(12.5).color(MUTED));
    }
    ui.add_space(14.0);
}

/// Constrains content to a comfortable reading width.
///
/// A window can be 1400 pixels wide; a row of label and value stretched across
/// all of it is hard to read and looks accidental. Content stops at a measured
/// width and the remainder is left as margin.
pub fn measured<R>(ui: &mut Ui, max: f32, inner: impl FnOnce(&mut Ui) -> R) -> R {
    let w = ui.available_width().min(max);
    ui.allocate_ui_with_layout(
        Vec2::new(w, 0.0),
        egui::Layout::top_down(egui::Align::Min),
        inner,
    )
    .inner
}

/// A short explanation at the head of a pane.
///
/// Security software earns trust by being understood. A row of buttons whose
/// effects a person has to guess at is worse than one fewer feature, so each
/// section says plainly what its controls do before showing them.
pub fn explainer(ui: &mut Ui, text: &str) {
    egui::Frame::none()
        .fill(egui::Color32::from_rgb(0x1A, 0x1C, 0x20))
        .rounding(R)
        .inner_margin(egui::Margin::symmetric(14.0, 11.0))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(egui::RichText::new(text).size(12.0).color(MUTED));
        });
    ui.add_space(14.0);
}
