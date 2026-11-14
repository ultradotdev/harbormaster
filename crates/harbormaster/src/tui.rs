//! The terminal interface: a status dashboard. It attaches to a running
//! daemon over the control socket and only displays what the daemon
//! reports, so closing it never affects the bridge.
//!
//! The screen has a quick status box and the list of devices down the
//! left, and on the right the selected item's details with the log under
//! them, which narrows itself to the selected device.

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, IsTerminal, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use ratatui::crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers,
    MouseButton, MouseEventKind,
};
use ratatui::crossterm::execute;
use ratatui::layout::{Constraint, Layout, Position, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Clear, Paragraph};
use ratatui::Frame;

use crate::clock;
use crate::control::{self, Command, Device, LogLine, Message, State};
use crate::password::Secret;
use crate::protect_bridge::Detection;

/// Longest device name that can be typed, matching what the daemon accepts.
const MAX_NAME: usize = crate::overrides::MAX_NAME;
const MAX_AFFIX: usize = crate::overrides::MAX_AFFIX;

/// Log lines kept in the TUI for scrolling back.
const MAX_LOG_LINES: usize = 2000;

const DIM: Style = Style::new().fg(Color::DarkGray);
/// The prefix and suffix HomeKit is given, set apart from the name itself.
const AFFIX: Style = Style::new().fg(Color::White).bg(Color::DarkGray);
const GOOD: Style = Style::new().fg(Color::Green);
const WARN: Style = Style::new().fg(Color::Yellow);
const BAD: Style = Style::new().fg(Color::Red);
/// Keys to press, and the focused pane.
const KEY: Style = Style::new().fg(Color::Cyan);

enum Incoming {
    Attached,
    Detached,
    Message(Box<Message>),
}

/// A box drawn over the dashboard that takes the next keys.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Modal {
    None,
    /// Asking before a device is taken away from HomeKit.
    ConfirmUnshare { key: String, name: String },
    /// Typing a device's new name, or the prefix or suffix for all names.
    Edit { target: Target, input: String },
}

/// What a line of typed text is for.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Target {
    /// The name of the device with this key.
    Device(String),
    Prefix,
    Suffix,
    /// The UniFi Protect password, which is never shown.
    Password,
}

/// Longest password that can be typed into the dashboard.
const MAX_PASSWORD: usize = 256;

impl Target {
    fn limit(&self) -> usize {
        match self {
            Target::Password => MAX_PASSWORD,
            Target::Device(_) => MAX_NAME,
            Target::Prefix | Target::Suffix => MAX_AFFIX,
        }
    }
}

/// Something a line of the detail pane does when clicked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Action {
    /// Hide or show the pairing code.
    Pair,
    /// Select this row of the device list.
    Select(usize),
    ToggleShared,
    Rename,
    Prefix,
    Suffix,
    /// Switch a recognition sensor on or off for the selected device.
    Detect(Detection),
}

/// A clickable stretch of the detail pane: a line, or part of one.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Hit {
    line: usize,
    /// Columns inside the pane's border; the whole line when `None`.
    columns: Option<std::ops::Range<usize>>,
    action: Action,
}

impl Hit {
    fn line(line: usize, action: Action) -> Self {
        Self { line, columns: None, action }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Focus {
    Devices,
    Detail,
    Log,
}

struct App {
    attached: bool,
    state: Option<State>,
    /// The devices to list: the daemon's, or for a daemon from before the
    /// dashboard, its plain accessories.
    devices: Vec<Device>,
    logs: VecDeque<LogLine>,
    /// Row of the device list: zero is the overview, then one per device.
    selected: usize,
    /// First row of the device list on screen.
    list_offset: usize,
    detail_scroll: usize,
    /// Lines scrolled up from the newest log line; zero follows the tail.
    log_scroll: usize,
    focus: Focus,
    modal: Modal,
    /// Requests waiting to be sent to the daemon.
    outbox: Vec<Command>,
    /// What can be clicked in the detail pane, by line number.
    actions: Vec<Hit>,
    /// Where the confirmation's Yes was last drawn.
    yes_area: Rect,
    /// Where the open box was last drawn.
    modal_area: Rect,
    /// The footer's key hints, by the columns each was drawn in.
    hint_areas: Vec<(std::ops::Range<u16>, KeyCode)>,
    warnings_only: bool,
    /// Whether long log lines wrap onto more rows. They do unless `W` says not.
    log_wrap: bool,
    /// Whether the pairing code is on screen. It is unless hidden with `p`.
    show_pairing: bool,
    /// Whether the pairing box has room for the QR code, as last drawn.
    pairing_picture: bool,
    /// Whether the log narrows to the selected device.
    device_log: bool,
    /// Seconds local time is ahead of UTC at a given moment.
    zone: fn(u64) -> i64,
    /// Where the panes were last drawn, for mouse hit testing.
    status_area: Rect,
    pairing_area: Rect,
    list_area: Rect,
    /// Screen line of the list's first row, under its header if one is drawn.
    list_top: u16,
    detail_area: Rect,
    log_area: Rect,
    footer_area: Rect,
    /// How far the detail pane could scroll when last drawn.
    detail_max: usize,
}

impl App {
    fn new() -> Self {
        Self {
            attached: false,
            state: None,
            devices: Vec::new(),
            logs: VecDeque::new(),
            selected: 0,
            list_offset: 0,
            detail_scroll: 0,
            log_scroll: 0,
            focus: Focus::Devices,
            modal: Modal::None,
            outbox: Vec::new(),
            actions: Vec::new(),
            yes_area: Rect::default(),
            modal_area: Rect::default(),
            hint_areas: Vec::new(),
            warnings_only: false,
            show_pairing: true,
            log_wrap: true,
            pairing_picture: false,
            device_log: true,
            zone: clock::local_offset,
            status_area: Rect::default(),
            pairing_area: Rect::default(),
            list_area: Rect::default(),
            list_top: 0,
            detail_area: Rect::default(),
            log_area: Rect::default(),
            footer_area: Rect::default(),
            detail_max: 0,
        }
    }

    /// The daemon's clock at the last snapshot.
    fn now(&self) -> u64 {
        self.state.as_ref().map_or(0, |s| s.time)
    }

    fn selected_device(&self) -> Option<&Device> {
        self.selected.checked_sub(1).and_then(|i| self.devices.get(i))
    }

    /// The device whose log lines are wanted, if the log is narrowed.
    fn log_device(&self) -> Option<&str> {
        self.selected_device().filter(|d| self.device_log && !d.name.is_empty()).map(|d| d.name.as_str())
    }

    fn log_matches(&self, line: &LogLine) -> bool {
        (!self.warnings_only || matches!(line.level.as_str(), "WARN" | "ERROR"))
            && self.log_device().is_none_or(|name| line.message.contains(name))
    }

    fn visible_logs(&self) -> Vec<&LogLine> {
        self.logs.iter().filter(|l| self.log_matches(l)).collect()
    }

    fn receive(&mut self, incoming: Incoming) {
        match incoming {
            Incoming::Attached => {
                self.attached = true;
                // The daemon replays its backlog on attach.
                self.logs.clear();
            }
            Incoming::Detached => self.attached = false,
            Incoming::Message(message) => match *message {
                Message::State(state) => {
                    let state = *state;
                    // Keep the same device selected if the list changes.
                    let chosen = self.selected_device().map(|d| d.aid);
                    self.devices = if state.devices.is_empty() {
                        state.accessories.iter().filter(|a| a.model != "Bridge").map(plain_device).collect()
                    } else {
                        state.devices.clone()
                    };
                    self.selected = match chosen.and_then(|aid| self.devices.iter().position(|d| d.aid == aid)) {
                        Some(i) => i + 1,
                        None => self.selected.min(self.devices.len()),
                    };
                    self.state = Some(state);
                }
                // The daemon's log says how an unlock went.
                Message::Unlock(_) => {}
                Message::Log(line) => {
                    // Keep the view anchored while the user is reading history.
                    if self.log_scroll > 0 && self.log_matches(&line) {
                        self.log_scroll += 1;
                    }
                    if self.logs.len() == MAX_LOG_LINES {
                        self.logs.pop_front();
                    }
                    self.logs.push_back(line);
                }
            },
        }
    }

    fn select(&mut self, row: usize) {
        let row = row.min(self.devices.len());
        if row != self.selected {
            self.selected = row;
            self.detail_scroll = 0;
            self.log_scroll = 0;
        }
    }

    fn move_selection(&mut self, delta: isize) {
        self.select(self.selected.saturating_add_signed(delta));
    }

    fn scroll_detail(&mut self, delta: isize) {
        self.detail_scroll = self.detail_scroll.saturating_add_signed(delta).min(self.detail_max);
    }

    fn scroll_log(&mut self, delta: isize) {
        let visible = self.log_area.height.saturating_sub(2) as usize;
        let width = self.log_area.width.saturating_sub(2) as usize;
        let shown = self.visible_logs();
        // Scrolled furthest back, the oldest lines fill the pane.
        let mut rows = 0;
        let fill = shown.iter().take_while(|l| {
            rows += self.log_rows(l, width).len();
            rows <= visible
        });
        let max = shown.len() - fill.count().min(shown.len());
        self.log_scroll = self.log_scroll.saturating_add_signed(delta).min(max);
    }

    /// One log line as drawn: a single row, or wrapped at spaces to `width`
    /// with the time and level hanging to the left.
    fn log_rows(&self, l: &LogLine, width: usize) -> Vec<Line<'static>> {
        let color = match l.level.as_str() {
            "ERROR" => Color::Red,
            "WARN" => Color::Yellow,
            _ => Color::Reset,
        };
        let head = vec![
            Span::styled(format!("{} ", clock::time_of_day(l.time, (self.zone)(l.time))), DIM),
            Span::styled(format!("{:<5} ", l.level), Style::new().fg(color)),
        ];
        let indent: usize = head.iter().map(|s| s.content.chars().count()).sum();
        if !self.log_wrap || width < indent + 10 {
            let mut spans = head;
            spans.push(Span::raw(l.message.clone()));
            return vec![Line::from(spans)];
        }
        let mut rows = Vec::new();
        for (i, text) in wrap(&l.message, width - indent).into_iter().enumerate() {
            let mut spans = if i == 0 { head.clone() } else { vec![Span::raw(" ".repeat(indent))] };
            spans.push(Span::raw(text));
            rows.push(Line::from(spans));
        }
        rows
    }

    /// Moves the focused pane by `lines`, where positive is down the screen.
    fn scroll_focused(&mut self, lines: isize) {
        match self.focus {
            Focus::Devices => self.move_selection(lines),
            Focus::Detail => self.scroll_detail(lines),
            // The log counts lines up from its newest.
            Focus::Log => self.scroll_log(lines.saturating_neg()),
        }
    }

    fn page(&self) -> isize {
        let area = match self.focus {
            Focus::Devices => self.list_area,
            Focus::Detail => self.detail_area,
            Focus::Log => self.log_area,
        };
        area.height.saturating_sub(2).max(1) as isize
    }

    /// Shares the selected device, or asks before taking it away.
    fn toggle_shared(&mut self) {
        let Some((key, name, hidden)) =
            self.selected_device().and_then(|d| Some((d.key.clone()?, d.name.clone(), d.hidden)))
        else {
            return;
        };
        if hidden {
            self.outbox.push(Command::SetShared { key, shared: true });
        } else {
            self.modal = Modal::ConfirmUnshare { key, name };
        }
    }

    fn start_rename(&mut self) {
        if let Some((key, name)) = self.selected_device().and_then(|d| Some((d.key.clone()?, d.name.clone()))) {
            self.modal = Modal::Edit { target: Target::Device(key), input: name };
        }
    }

    /// The prefix and suffix on names sent to HomeKit.
    fn affix(&self) -> (&str, &str) {
        self.state.as_ref().map_or(("", ""), |s| (s.name_prefix.as_str(), s.name_suffix.as_str()))
    }

    fn edit_affix(&mut self, target: Target) {
        if self.state.is_some() {
            let (prefix, suffix) = self.affix();
            let input = if target == Target::Prefix { prefix } else { suffix }.to_owned();
            self.modal = Modal::Edit { target, input };
        }
    }

    /// A device's name as HomeKit has it: prefix, plain name, suffix, with
    /// the prefix and suffix set apart. If the whole does not fit in
    /// `width` the plain name gives way first, down to a few letters, and
    /// then the prefix and suffix.
    fn homekit_name(&self, d: &Device, width: usize) -> Vec<Span<'static>> {
        // Only shared Protect devices are published under the prefix and suffix.
        let (prefix, suffix) = if d.hidden || d.key.is_none() { ("", "") } else { self.affix() };
        let (prefix_len, suffix_len) = (prefix.chars().count(), suffix.chars().count());
        let name = fit(&d.name, width.saturating_sub(prefix_len + suffix_len).max(4));
        let room = width.saturating_sub(name.chars().count());
        let suffix_room = suffix_len.min(room.saturating_sub(prefix_len).max(room / 2));
        let mut spans = Vec::new();
        if !prefix.is_empty() {
            spans.push(Span::styled(fit(prefix, room - suffix_room), AFFIX));
        }
        spans.push(Span::raw(name));
        if !suffix.is_empty() {
            spans.push(Span::styled(fit(suffix, suffix_room), AFFIX));
        }
        spans
    }

    /// The pairing code, if the daemon sends it and it is not hidden.
    fn pairing_code(&self) -> Option<&State> {
        self.state.as_ref().filter(|s| self.attached && s.setup_code.is_some())
    }

    /// Hides or shows the pairing code.
    fn toggle_pairing(&mut self) {
        if self.pairing_code().is_some() {
            self.show_pairing = !self.show_pairing;
        }
    }

    /// Whether the daemon is waiting to be given the Protect password.
    fn waiting_for_password(&self) -> bool {
        self.attached && self.state.as_ref().is_some_and(|s| s.console.as_ref().is_some_and(|c| c.waiting_for_password))
    }

    fn start_unlock(&mut self) {
        if self.waiting_for_password() {
            self.modal = Modal::Edit { target: Target::Password, input: String::new() };
        }
    }

    /// Switches a recognition sensor: for the selected device, or from the
    /// overview for every camera that can tell.
    fn toggle_detection(&mut self, detection: Detection) {
        let word = detection.word();
        let listed = |list: &[String]| list.iter().any(|w| w == word);
        let command = match (self.selected_device(), &self.state) {
            (Some(d), _) => match &d.key {
                Some(key) if listed(&d.detects) => {
                    Some(Command::SetDetection { key: Some(key.clone()), detection: word.to_owned(), on: !listed(&d.detect_here) })
                }
                _ => None,
            },
            (None, Some(s)) if self.selected == 0 => {
                Some(Command::SetDetection { key: None, detection: word.to_owned(), on: !listed(&s.detect_everywhere) })
            }
            _ => None,
        };
        self.outbox.extend(command);
    }

    fn run(&mut self, action: Action) {
        match action {
            Action::Pair => self.toggle_pairing(),
            Action::Select(row) => self.select(row),
            Action::Detect(detection) => self.toggle_detection(detection),
            Action::ToggleShared => self.toggle_shared(),
            Action::Rename => self.start_rename(),
            Action::Prefix => self.edit_affix(Target::Prefix),
            Action::Suffix => self.edit_affix(Target::Suffix),
        }
    }

    /// Handles a key while a box is open. Returns `false` if none is.
    fn modal_key(&mut self, code: KeyCode) -> bool {
        match std::mem::replace(&mut self.modal, Modal::None) {
            Modal::None => return false,
            Modal::ConfirmUnshare { key, .. } => {
                if matches!(code, KeyCode::Char('y' | 'Y') | KeyCode::Enter) {
                    self.outbox.push(Command::SetShared { key, shared: false });
                }
            }
            Modal::Edit { target, mut input } => match code {
                KeyCode::Enter => self.outbox.push(match target {
                    Target::Device(key) => {
                        Command::Rename { key, name: Some(input.trim().to_owned()).filter(|n| !n.is_empty()) }
                    }
                    // Sent exactly as typed: the spaces are what separate it from the name.
                    Target::Prefix => Command::SetNamePrefix { text: Some(input) },
                    Target::Suffix => Command::SetNameSuffix { text: Some(input) },
                    Target::Password => Command::Unlock { password: Secret::new(input) },
                }),
                // A half-typed password is wiped rather than left in memory.
                KeyCode::Esc => zeroize::Zeroize::zeroize(&mut input),
                other => {
                    match other {
                        KeyCode::Char(c) if input.chars().count() < target.limit() => input.push(c),
                        KeyCode::Backspace => drop(input.pop()),
                        _ => {}
                    }
                    self.modal = Modal::Edit { target, input };
                }
            },
        }
        true
    }

    /// Returns `false` when the user asked to quit.
    fn handle(&mut self, event: Event) -> bool {
        match event {
            Event::Key(key) if key.kind == KeyEventKind::Press => {
                let quit = key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL);
                if !quit && self.modal_key(key.code) {
                    return true;
                }
                match key.code {
                    KeyCode::Char('q') => return false,
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return false,
                    // Back out one step: to the device list, then to the overview.
                    KeyCode::Esc => match self.focus {
                        Focus::Devices => self.select(0),
                        _ => self.focus = Focus::Devices,
                    },
                    KeyCode::Tab => {
                        self.focus = match self.focus {
                            Focus::Devices => Focus::Detail,
                            Focus::Detail => Focus::Log,
                            Focus::Log => Focus::Devices,
                        };
                    }
                    KeyCode::BackTab => {
                        self.focus = match self.focus {
                            Focus::Devices => Focus::Log,
                            Focus::Detail => Focus::Devices,
                            Focus::Log => Focus::Detail,
                        };
                    }
                    KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') if self.focus == Focus::Devices => {
                        self.focus = Focus::Detail;
                    }
                    KeyCode::Left | KeyCode::Char('h') => self.focus = Focus::Devices,
                    KeyCode::Char('p') => self.toggle_pairing(),
                    KeyCode::Char('u') => self.start_unlock(),
                    KeyCode::Char('s') => self.toggle_shared(),
                    KeyCode::Char('r') => self.start_rename(),
                    KeyCode::Char('P') => self.edit_affix(Target::Prefix),
                    KeyCode::Char('S') => self.edit_affix(Target::Suffix),
                    KeyCode::Char(c @ '1'..='4') => self.toggle_detection(Detection::ALL[c as usize - '1' as usize]),
                    KeyCode::Char('W') => {
                        self.log_wrap = !self.log_wrap;
                        self.log_scroll = 0;
                    }
                    KeyCode::Char('w') => {
                        self.warnings_only = !self.warnings_only;
                        self.log_scroll = 0;
                    }
                    KeyCode::Char('f') => {
                        self.device_log = !self.device_log;
                        self.log_scroll = 0;
                    }
                    KeyCode::Up | KeyCode::Char('k') => self.scroll_focused(-1),
                    KeyCode::Down | KeyCode::Char('j') => self.scroll_focused(1),
                    KeyCode::PageUp => self.scroll_focused(-self.page()),
                    KeyCode::PageDown => self.scroll_focused(self.page()),
                    KeyCode::Home | KeyCode::Char('g') => self.scroll_focused(isize::MIN),
                    KeyCode::End | KeyCode::Char('G') => self.scroll_focused(isize::MAX),
                    _ => {}
                }
            }
            Event::Mouse(mouse) => return self.mouse(mouse),
            _ => {}
        }
        true
    }
}

impl App {
    /// The pane under a point on the screen.
    fn pane_at(&self, at: Position) -> Option<Focus> {
        [(self.list_area, Focus::Devices), (self.detail_area, Focus::Detail), (self.log_area, Focus::Log)]
            .into_iter()
            .find(|(area, _)| area.contains(at))
            .map(|(_, pane)| pane)
    }

    /// A click or the wheel. Every click lands where a key would: it
    /// focuses the pane it is in, and a row or setting does what its key does.
    fn mouse(&mut self, mouse: event::MouseEvent) -> bool {
        let at = Position::new(mouse.column, mouse.row);
        let click = mouse.kind == MouseEventKind::Down(MouseButton::Left);
        if self.modal != Modal::None {
            if !click {
                return true;
            }
            match self.modal {
                // Yes confirms; a click anywhere else backs out.
                Modal::ConfirmUnshare { .. } => {
                    let confirm = if self.yes_area.contains(at) { KeyCode::Enter } else { KeyCode::Esc };
                    self.modal_key(confirm);
                }
                // Clicking into the box being typed in keeps it open.
                Modal::Edit { .. } if self.modal_area.contains(at) => {}
                Modal::Edit { .. } => drop(self.modal_key(KeyCode::Esc)),
                _ => self.modal = Modal::None,
            }
            return true;
        }
        if click && self.footer_area.contains(at) {
            if let Some((_, code)) = self.hint_areas.iter().find(|(columns, _)| columns.contains(&mouse.column)).cloned() {
                return self.handle(Event::Key(event::KeyEvent::new(code, KeyModifiers::NONE)));
            }
            return true;
        }
        if click && self.status_area.contains(at) {
            // The status lines are Bridge, then Console.
            match mouse.row.saturating_sub(self.status_area.y) {
                1 => self.toggle_pairing(),
                2 => self.start_unlock(),
                _ => {}
            }
            return true;
        }
        if click && self.pairing_area.contains(at) {
            self.toggle_pairing();
            return true;
        }
        // The wrap switch sits at the right end of the log's top border.
        if click && mouse.row == self.log_area.y && mouse.column + 12 >= self.log_area.right() && self.log_area.contains(at) {
            self.handle(Event::Key(event::KeyEvent::new(KeyCode::Char('W'), KeyModifiers::NONE)));
            return true;
        }
        let Some(pane) = self.pane_at(at) else { return true };
        let down = match mouse.kind {
            MouseEventKind::ScrollUp => -1,
            MouseEventKind::ScrollDown => 1,
            _ if click => 0,
            _ => return true,
        };
        if down != 0 {
            // The wheel moves whatever is under the pointer, without taking focus.
            match pane {
                Focus::Devices => self.move_selection(down),
                Focus::Detail => self.scroll_detail(down * 3),
                Focus::Log => self.scroll_log(-down * 3),
            }
            return true;
        }
        self.focus = pane;
        match pane {
            Focus::Devices => {
                let inside = mouse.row >= self.list_top && mouse.row + 1 < self.list_area.bottom();
                if inside {
                    let row = self.list_offset + (mouse.row - self.list_top) as usize;
                    if row <= self.devices.len() {
                        self.select(row);
                    }
                }
            }
            Focus::Detail if mouse.row > self.detail_area.y && mouse.column > self.detail_area.x => {
                let line = self.detail_scroll + (mouse.row - self.detail_area.y - 1) as usize;
                let column = (mouse.column - self.detail_area.x - 1) as usize;
                let hit = self.actions.iter().find(|h| {
                    h.line == line && h.columns.as_ref().is_none_or(|c| c.contains(&column))
                });
                if let Some(action) = hit.map(|h| h.action) {
                    self.run(action);
                }
            }
            _ => {}
        }
        true
    }
}

/// A row for an accessory from a daemon that does not describe devices.
fn plain_device(accessory: &control::Accessory) -> Device {
    Device {
        aid: accessory.aid,
        kind: "accessory".into(),
        name: accessory.name.clone(),
        model: accessory.model.clone(),
        serial_number: accessory.serial_number.clone(),
        readings: accessory.readings.clone(),
        ..Device::default()
    }
}

fn duration(secs: u64) -> String {
    match secs {
        0..60 => format!("{secs}s"),
        60..3600 => format!("{}m {:02}s", secs / 60, secs % 60),
        3600..86400 => format!("{}h {:02}m", secs / 3600, secs % 3600 / 60),
        _ => format!("{}d {:02}h", secs / 86400, secs % 86400 / 3600),
    }
}

/// Breaks `text` into rows of at most `width` characters, at spaces where
/// it can and inside a word only when the word alone is too long.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut rows = vec![String::new()];
    for word in text.split(' ') {
        let row = rows.last_mut().expect("never empty");
        let (used, needed) = (row.chars().count(), word.chars().count());
        if used > 0 && used + 1 + needed <= width {
            row.push(' ');
            row.push_str(word);
            continue;
        }
        if used > 0 {
            rows.push(String::new());
        }
        let mut chars = word.chars().peekable();
        while chars.peek().is_some() {
            let piece: String = chars.by_ref().take(width).collect();
            let row = rows.last_mut().expect("never empty");
            if !row.is_empty() {
                rows.push(String::new());
            }
            rows.last_mut().expect("never empty").push_str(&piece);
        }
    }
    rows
}

/// Shortens `text` to at most `width` characters, marking the cut.
fn fit(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        return text.to_owned();
    }
    let mut out: String = text.chars().take(width.saturating_sub(1)).collect();
    if width > 0 {
        out.push('…');
    }
    out
}

/// A bordered pane. The focused one has a heavier cyan border and a bold
/// title, so it can be told apart at a glance.
fn pane(title: &str, focused: bool) -> Block<'_> {
    let block = Block::bordered().title(format!(" {title} "));
    if focused {
        block
            .border_type(BorderType::Thick)
            .border_style(KEY)
            .title_style(KEY.add_modifier(Modifier::BOLD))
    } else {
        block.border_style(DIM)
    }
}

/// A filled dot for online, a hollow one for offline, a faint one when the
/// device does not say.
fn dot(online: Option<bool>) -> Span<'static> {
    match online {
        Some(true) => Span::styled("●", GOOD),
        Some(false) => Span::styled("○", BAD),
        None => Span::styled("·", DIM),
    }
}

impl App {
    fn ago(&self, at: u64) -> String {
        format!("{} ago", duration(self.now().saturating_sub(at)))
    }

    /// A past moment in local time, with how long ago it was.
    fn when(&self, at: u64) -> String {
        format!("{} ({})", clock::stamp(at, self.now(), self.zone), self.ago(at))
    }

    /// Hours and minutes, or the date for another day.
    fn short_time(&self, at: u64) -> String {
        let stamp = clock::stamp(at, self.now(), self.zone);
        // `14:03:22` loses its seconds; `Nov 10 14:03` is already short.
        if stamp.len() == 8 { stamp[..5].to_owned() } else { stamp }
    }

    /// The few words that say what a device is doing, most pressing first.
    fn summary(&self, d: &Device) -> Vec<Span<'static>> {
        let mut parts: Vec<Span> = Vec::new();
        if d.hidden {
            return vec![Span::styled("not shared", DIM)];
        }
        if d.online == Some(false) {
            // Whatever an unreachable device last said is stale.
            return vec![Span::styled("offline", BAD)];
        }
        if d.tampered == Some(true) {
            parts.push(Span::styled("tampered", BAD));
        }
        if d.low_battery == Some(true) {
            parts.push(Span::styled("low battery", WARN));
        }
        if let Some(seconds) = d.recording.as_ref().and_then(|r| r.active_secs) {
            parts.push(Span::styled(format!("recording {}", duration(seconds)), BAD));
        }
        if !d.viewers.is_empty() {
            parts.push(Span::styled(format!("{} watching", d.viewers.len()), Style::new().fg(Color::Cyan)));
        }
        match (d.motion, d.last_motion) {
            (Some(true), _) => parts.push(Span::styled("motion", WARN)),
            (_, Some(at)) => parts.push(Span::raw(format!("motion {}", self.short_time(at)))),
            _ => {}
        }
        if let Some(at) = d.last_ring {
            parts.push(Span::raw(format!("rang {}", self.short_time(at))));
        }
        match (d.light_on, d.brightness) {
            (Some(true), Some(percent)) => parts.push(Span::styled(format!("on {percent}%"), WARN)),
            (Some(true), None) => parts.push(Span::styled("on", WARN)),
            (Some(false), _) => parts.push(Span::raw("off")),
            (None, _) => {}
        }
        parts.extend(d.readings.iter().map(|r| Span::raw(r.value.clone())));
        if let (Some(percent), false) = (d.battery, d.low_battery == Some(true)) {
            parts.push(Span::raw(format!("battery {percent}%")));
        }
        if let Some(recording) = d.recording.as_ref().filter(|r| r.active_secs.is_none()) {
            parts.push(Span::styled(if recording.enabled { "rec on" } else { "rec off" }, DIM));
        }
        parts
    }

    /// `summary` as one line no wider than `width`, whole facts only.
    fn summary_line(&self, d: &Device, width: usize) -> Vec<Span<'static>> {
        let mut out: Vec<Span> = Vec::new();
        let mut used = 0;
        for part in self.summary(d) {
            let needed = part.content.chars().count() + if out.is_empty() { 0 } else { 3 };
            if used + needed > width {
                // A shorter fact further along may still fit.
                continue;
            }
            if !out.is_empty() {
                out.push(Span::styled(" · ", DIM));
            }
            used += needed;
            out.push(part);
        }
        out
    }
}

/// Inner lines the detail pane is given at most: enough for a camera with
/// all its settings. The log has the rest of the column.
const DETAIL_LINES: u16 = 20;
/// Rows the log keeps, border included, however tall the detail could be.
const LOG_ROWS: u16 = 7;

fn draw(frame: &mut Frame, app: &mut App) {
    let screen = frame.area();
    let [body, footer] = Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).areas(screen);
    let side_width = (screen.width * 32 / 100).clamp(32, 60);
    let [side, right] = Layout::horizontal([Constraint::Length(side_width), Constraint::Min(20)]).areas(body);
    let pairing = pairing_box(app, side.width.saturating_sub(2) as usize, side.height.saturating_sub(6));
    let pairing_rows = pairing.as_ref().map_or(0, |lines| lines.len() as u16 + 2);
    let [status, code, list] =
        Layout::vertical([Constraint::Length(6), Constraint::Length(pairing_rows), Constraint::Min(3)]).areas(side);
    // A fixed share, so the log does not jump as different devices are selected.
    let detail_rows = body.height.saturating_sub(LOG_ROWS).min(DETAIL_LINES + 2);
    let [detail, log] = Layout::vertical([Constraint::Length(detail_rows), Constraint::Min(0)]).areas(right);
    app.status_area = status;
    app.pairing_area = code;
    app.list_area = list;
    app.detail_area = detail;
    app.log_area = log;
    app.footer_area = footer;

    draw_status(frame, app, status);
    if let Some(lines) = pairing {
        let title = Line::from(vec![Span::raw(" Pairing code "), Span::styled("p", KEY), Span::styled(" hide ", DIM)]);
        frame.render_widget(Paragraph::new(lines).block(Block::bordered().title(title).border_style(DIM)), code);
    }
    draw_devices(frame, app, list);
    draw_detail(frame, app, detail);
    draw_log(frame, app, log);
    draw_footer(frame, app, footer);
    match &app.modal {
        Modal::None => {}
        Modal::ConfirmUnshare { name, .. } => {
            let lines = vec![
                Line::raw(format!(" Stop sharing {name} with HomeKit?")),
                Line::raw(""),
                Line::styled(" HomeKit will forget its room, automations", DIM),
                Line::styled(" and recordings. Sharing it again later", DIM),
                Line::styled(" adds it as a new accessory.", DIM),
                Line::raw(""),
                Line::from(vec![Span::raw(" "), Span::styled("[ y  Yes, stop sharing ]", BAD), Span::raw("   [ n  Keep ]")]),
            ];
            let area = draw_box(frame, "Stop sharing", lines);
            app.modal_area = area;
            // The Yes button is the start of the last line.
            app.yes_area = Rect { x: area.x + 2, y: area.bottom().saturating_sub(2), width: 24.min(area.width), height: 1 };
        }
        Modal::Edit { target, input } => {
            let cursor = Span::styled("▏", Style::new().fg(Color::Cyan));
            let (title, typed, hints) = match target {
                // One dot per character, so the password is never on screen.
                Target::Password => (
                    "UniFi Protect password",
                    Span::raw("•".repeat(input.chars().count())),
                    [" Kept in the daemon's memory only, until it", " stops. `harbormaster unlock` does the same."],
                ),
                Target::Device(_) => (
                    "Name to publish",
                    Span::raw(input.clone()),
                    [" Leave it empty to use Protect's own name.", " The prefix and suffix are added for you."],
                ),
                // Shown on a background so spaces at either end can be seen.
                Target::Prefix => (
                    "Prefix for every HomeKit name",
                    Span::styled(input.clone(), AFFIX),
                    [" Spaces count: end it with one to keep it", " apart from the name. Empty means none."],
                ),
                Target::Suffix => (
                    "Suffix for every HomeKit name",
                    Span::styled(input.clone(), AFFIX),
                    [" Spaces count: start it with one to keep it", " apart from the name. Empty means none."],
                ),
            };
            let enter = if *target == Target::Password { " Enter signs in · Esc cancels" } else { " Enter saves · Esc cancels" };
            let lines = vec![
                Line::from(vec![Span::raw(" "), typed, cursor]),
                Line::raw(""),
                Line::styled(enter, DIM),
                Line::styled(hints[0], DIM),
                Line::styled(hints[1], DIM),
            ];
            app.modal_area = draw_box(frame, title, lines);
        }
    }
}

/// The keys that work right now, most useful first, each with the key a
/// click on it presses.
fn hints(app: &App) -> Vec<(&'static str, &'static str, Option<KeyCode>)> {
    let mut hints = Vec::new();
    if app.waiting_for_password() {
        hints.push(("u", "unlock", Some(KeyCode::Char('u'))));
    }
    hints.push(("↑↓", "select", None));
    hints.push(("Tab", "pane", Some(KeyCode::Tab)));
    if app.selected_device().is_some_and(|d| d.key.is_some()) {
        hints.push(("s", "share", Some(KeyCode::Char('s'))));
        hints.push(("r", "rename", Some(KeyCode::Char('r'))));
    } else if app.selected == 0 && app.state.is_some() {
        hints.push(("P", "prefix", Some(KeyCode::Char('P'))));
        hints.push(("S", "suffix", Some(KeyCode::Char('S'))));
    }
    if app.pairing_code().is_some() {
        hints.push(("p", if app.show_pairing { "hide code" } else { "show code" }, Some(KeyCode::Char('p'))));
    }
    if app.selected_device().is_some() {
        // The log's title says which way these are switched.
        hints.push(("f", "log", Some(KeyCode::Char('f'))));
    }
    hints.push(("w", "warnings", Some(KeyCode::Char('w'))));
    // Last, as the log's border also offers it.
    hints.push(("W", "wrap", Some(KeyCode::Char('W'))));
    hints
}

/// The key hints. Those that do not fit are left off the end, but quit
/// always stays.
fn draw_footer(frame: &mut Frame, app: &mut App, area: Rect) {
    let width = area.width as usize;
    let quit = ("q", "quit", Some(KeyCode::Char('q')));
    let size = |(key, label, _): &(&str, &str, Option<KeyCode>)| 2 + key.chars().count() + 1 + label.chars().count();
    let mut shown = hints(app);
    while !shown.is_empty() && shown.iter().chain([&quit]).map(size).sum::<usize>() > width {
        shown.pop();
    }
    shown.push(quit);
    let mut spans = Vec::new();
    app.hint_areas.clear();
    let mut x = area.x;
    for (key, label, code) in shown {
        let start = x + 1;
        spans.push(Span::raw(" "));
        spans.push(Span::styled(key, KEY));
        spans.push(Span::styled(format!(" {label} "), DIM));
        x += size(&(key, label, code)) as u16;
        if let Some(code) = code {
            app.hint_areas.push((start..x, code));
        }
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

/// The pairing code for the left column, shown until hidden with `p`, paired
/// or not. The QR code goes in when the device list keeps room for every
/// device (or a dozen rows) under it; otherwise only the digits.
fn pairing_box(app: &mut App, width: usize, height: u16) -> Option<Vec<Line<'static>>> {
    app.pairing_picture = false;
    let s = app.pairing_code().filter(|_| app.show_pairing)?;
    let code = s.setup_code.clone()?;
    let mut lines = vec![Line::from(vec![Span::styled("Setup code  ", DIM), Span::styled(code, WARN)])];
    // HomeKit takes a code only while unpaired, so say so rather than leave it to be tried.
    if s.paired {
        let long = "Paired: remove the bridge from Home to use it again.";
        lines.push(Line::styled(if long.len() <= width { long } else { "Remove from Home to reuse it." }, DIM));
    }
    let list_rows = (app.devices.len() as u16 + 4).min(14);
    if let Some(qr) = s.setup_uri.as_deref().and_then(crate::qr::render) {
        let picture: Vec<Line> = qr.lines().map(|l| Line::raw(l.to_owned()).centered()).collect();
        let fits = qr.lines().all(|l| l.chars().count() <= width);
        if fits && height >= (picture.len() + lines.len() + 2) as u16 + list_rows {
            app.pairing_picture = true;
            lines.splice(0..0, picture);
            for line in &mut lines {
                line.alignment = Some(ratatui::layout::Alignment::Center);
            }
        }
    }
    Some(lines)
}

/// The quick view: is the bridge healthy, and what is it doing.
fn draw_status(frame: &mut Frame, app: &App, area: Rect) {
    let (Some(s), true) = (&app.state, app.attached) else {
        let lines = vec![
            Line::from(vec![Span::styled("✕ ", BAD), Span::styled("daemon not running", BAD)]),
            Line::styled("start it with:", DIM),
            Line::styled("  harbormaster daemon", DIM),
        ];
        frame.render_widget(Paragraph::new(lines).block(pane("Harbormaster", false)), area);
        return;
    };
    let row = |mark: Span<'static>, label: &str, rest: Vec<Span<'static>>| {
        let mut spans = vec![mark, Span::styled(format!(" {label:<8}"), DIM)];
        spans.extend(rest);
        Line::from(spans)
    };
    let bridge = if s.paired {
        row(dot(Some(true)), "Bridge", vec![Span::raw(format!("paired · {} connected", s.connections.len()))])
    } else {
        let how = if app.show_pairing && s.setup_code.is_some() { "not paired" } else { "not paired (press p)" };
        row(Span::styled("○", WARN), "Bridge", vec![Span::styled(how, WARN)])
    };
    let console = match &s.console {
        Some(c) if c.connected => {
            let age = c.last_update.map_or(String::new(), |at| format!(" · {}", duration(s.time.saturating_sub(at))));
            row(dot(Some(true)), "Console", vec![Span::raw(format!("{}{age}", c.host))])
        }
        Some(c) if c.waiting_for_password => {
            row(Span::styled("○", WARN), "Console", vec![Span::styled("needs password (u)", WARN)])
        }
        Some(c) => row(dot(Some(false)), "Console", vec![Span::styled(format!("{} down", c.host), BAD)]),
        None => row(dot(None), "Console", vec![Span::styled("not configured", DIM)]),
    };
    let shared = app.devices.iter().filter(|d| !d.hidden);
    let known = shared.clone().filter(|d| d.online.is_some()).count();
    let offline = shared.clone().filter(|d| d.online == Some(false)).count();
    let devices = match (shared.count(), offline) {
        (0, _) => row(dot(None), "Devices", vec![Span::styled("none", DIM)]),
        // Devices that do not report whether they are reachable are only counted.
        (all, 0) if known == 0 => row(dot(None), "Devices", vec![Span::raw(format!("{all} published"))]),
        (all, 0) => row(dot(Some(true)), "Devices", vec![Span::raw(format!("{all}, all online"))]),
        (all, n) => row(dot(Some(false)), "Devices", vec![Span::styled(format!("{n} of {all} offline"), BAD)]),
    };
    let watching: usize = app.devices.iter().map(|d| d.viewers.len()).sum();
    let recording = app.devices.iter().filter(|d| d.recording.as_ref().is_some_and(|r| r.active_secs.is_some())).count();
    let mut doing = Vec::new();
    if watching > 0 {
        doing.push(format!("{watching} watching"));
    }
    if recording > 0 {
        doing.push(format!("{recording} recording"));
    }
    let activity = if doing.is_empty() {
        Line::styled(format!("  idle · up {}", duration(s.uptime_secs)), DIM)
    } else {
        Line::styled(format!("  {}", doing.join(" · ")), Style::new().fg(Color::Cyan))
    };
    frame.render_widget(Paragraph::new(vec![bridge, console, devices, activity]).block(pane(&s.name, false)), area);
}

/// How wide each column of the device list is; zero for a column left out
/// for want of room.
#[derive(Debug, PartialEq, Eq)]
struct Columns {
    name: usize,
    kind: usize,
    state: usize,
    motion: usize,
}

/// Widest the state column grows.
const STATE_WIDTH: usize = 8;
/// Fewest letters of a name before columns are given up for it.
const NAME_WIDTH: usize = 16;

impl App {
    /// The one fact that best says how a device is, for the list: trouble
    /// first, then what it is doing, then how it is set.
    fn state_cell(&self, d: &Device) -> Span<'static> {
        let recording = d.recording.as_ref();
        let span = if d.hidden {
            Span::styled("unshared", DIM)
        } else if d.online == Some(false) {
            Span::styled("offline", BAD)
        } else if d.tampered == Some(true) {
            Span::styled("tampered", BAD)
        } else if recording.is_some_and(|r| r.active_secs.is_some()) {
            Span::styled("rec now", BAD)
        } else if d.low_battery == Some(true) {
            Span::styled(format!("batt {}%", d.battery.unwrap_or(0)), WARN)
        } else if !d.viewers.is_empty() {
            Span::styled("watching", KEY)
        } else if let Some(on) = d.light_on {
            match (on, d.brightness) {
                (true, Some(percent)) => Span::styled(format!("on {percent}%"), WARN),
                (true, None) => Span::styled("on", WARN),
                (false, _) => Span::styled("off", DIM),
            }
        } else if let Some(r) = recording {
            if r.enabled { Span::raw("rec on") } else { Span::styled("rec off", DIM) }
        } else if let Some(reading) = d.readings.first() {
            Span::raw(reading.value.clone())
        } else if let Some(percent) = d.battery {
            Span::raw(format!("batt {percent}%"))
        } else {
            Span::raw("")
        };
        Span::styled(fit(&span.content, STATE_WIDTH), span.style)
    }

    /// When the device last saw motion: `now`, a time today, or a date.
    fn motion_cell(&self, d: &Device) -> Span<'static> {
        if d.hidden || d.online == Some(false) {
            return Span::raw("");
        }
        match (d.motion, d.last_motion) {
            (Some(true), _) => Span::styled("now", WARN),
            // `14:03`, or `Nov 10` for another day.
            (_, Some(at)) => {
                let time = self.short_time(at);
                Span::raw(time.rsplit_once(' ').map_or(time.clone(), |(date, _)| date.to_owned()))
            }
            _ => Span::raw(""),
        }
    }

    /// Fits the columns to `width`: the name gets what is left, and the
    /// kind, then motion, then state are given up so it keeps a readable
    /// length.
    fn columns(&self, width: usize) -> Columns {
        let widest = |cell: &dyn Fn(&Device) -> usize, header: usize| {
            let most = self.devices.iter().map(cell).max().unwrap_or(0);
            if most == 0 { 0 } else { most.max(header) }
        };
        let mut columns = Columns {
            name: 0,
            kind: widest(&|d| d.kind.chars().count(), 4),
            state: widest(&|d| self.state_cell(d).content.chars().count(), 5),
            motion: widest(&|d| self.motion_cell(d).content.chars().count(), 6),
        };
        // The dot and its spaces, and a gap before each column shown.
        let rest = |c: &Columns| 3 + [c.kind, c.state, c.motion].iter().map(|w| if *w > 0 { w + 1 } else { 0 }).sum::<usize>();
        let longest = self.devices.iter().map(|d| self.homekit_name(d, usize::MAX).iter().map(|s| s.content.chars().count()).sum::<usize>());
        let longest = longest.max().unwrap_or(0).max(4);
        let wanted = longest.min(NAME_WIDTH);
        // The kind only goes in when names have room to spare.
        if width.saturating_sub(rest(&columns)) < longest.max(NAME_WIDTH + 8) {
            columns.kind = 0;
        }
        if width.saturating_sub(rest(&columns)) < wanted {
            columns.motion = 0;
        }
        if width.saturating_sub(rest(&columns)) < wanted {
            columns.state = 0;
        }
        // No wider than the longest name, so the columns sit beside the names.
        columns.name = width.saturating_sub(rest(&columns)).min(longest);
        columns
    }
}

/// Pads a cell to `width`, or leaves it out when the column is.
fn cell(spans: &mut Vec<Span<'static>>, content: Span<'static>, width: usize) {
    if width > 0 {
        let used = content.content.chars().count();
        spans.push(Span::raw(" "));
        spans.push(content);
        spans.push(Span::raw(" ".repeat(width.saturating_sub(used))));
    }
}

/// The sidebar: the overview, then every device with its state at a glance,
/// in columns under a faint header when there is room for one.
fn draw_devices(frame: &mut Frame, app: &mut App, area: Rect) {
    let (width, inner) = (area.width.saturating_sub(2) as usize, area.height.saturating_sub(2) as usize);
    let columns = app.columns(width);
    let header = inner >= 10 && columns.state + columns.motion > 0;
    let height = inner - usize::from(header);
    app.list_top = area.y + 1 + u16::from(header);
    // Keep the selected row on screen.
    if app.selected < app.list_offset {
        app.list_offset = app.selected;
    } else if height > 0 && app.selected >= app.list_offset + height {
        app.list_offset = app.selected + 1 - height;
    }
    let rows = app.devices.len() + 1;
    app.list_offset = app.list_offset.min(rows.saturating_sub(height));

    let mut lines = Vec::new();
    if header {
        let mut spans = vec![Span::raw(format!("   {:<1$}", "Name", columns.name))];
        cell(&mut spans, Span::raw("Kind"), columns.kind);
        cell(&mut spans, Span::raw("State"), columns.state);
        cell(&mut spans, Span::raw("Motion"), columns.motion);
        lines.push(Line::from(spans).style(DIM));
    }
    for row in app.list_offset..rows.min(app.list_offset + height) {
        let mut spans = match row.checked_sub(1).and_then(|i| app.devices.get(i)) {
            None => vec![Span::raw("   Overview")],
            Some(d) => {
                let mut spans = vec![Span::raw(" "), dot(d.online), Span::raw(" ")];
                let name = app.homekit_name(d, columns.name);
                let used: usize = name.iter().map(|s| s.content.chars().count()).sum();
                spans.extend(name);
                spans.push(Span::raw(" ".repeat(columns.name.saturating_sub(used))));
                cell(&mut spans, Span::styled(d.kind.clone(), DIM), columns.kind);
                cell(&mut spans, app.state_cell(d), columns.state);
                cell(&mut spans, app.motion_cell(d), columns.motion);
                spans
            }
        };
        let used: usize = spans.iter().map(|s| s.content.chars().count()).sum();
        spans.push(Span::raw(" ".repeat(width.saturating_sub(used))));
        let mut line = Line::from(spans);
        if row == app.selected {
            line = line.style(Style::new().add_modifier(Modifier::REVERSED));
        }
        lines.push(line);
    }
    let title = format!("Devices ({})", app.devices.len());
    frame.render_widget(Paragraph::new(lines).block(pane(&title, app.focus == Focus::Devices)), area);
}

fn field(label: &str, value: impl Into<Span<'static>>) -> Line<'static> {
    Line::from(vec![Span::styled(format!("{label:<12} "), DIM), value.into()])
}

fn heading(text: &str) -> Line<'static> {
    Line::styled(text.to_owned(), Style::new().add_modifier(Modifier::BOLD))
}

/// How a prefix or suffix is shown as a setting.
fn affix_setting(label: &str, key: &str, text: &str) -> Line<'static> {
    let value = if text.is_empty() { Span::styled("none", DIM) } else { Span::styled(text.to_owned(), AFFIX) };
    Line::from(vec![
        Span::styled(format!("{label:<12} "), DIM),
        value,
        Span::styled(format!("  {key}"), KEY),
        Span::styled(" to change", DIM),
    ])
}

/// What an unpaired bridge's overview shows first: how to pair, with the
/// QR code where the left column has no room for it and this pane does.
fn pairing_lines(app: &App, s: &State, width: usize) -> Vec<Line<'static>> {
    let Some(code) = s.setup_code.as_ref().filter(|_| !s.paired && app.show_pairing) else { return Vec::new() };
    // The digits are always in the left column, so they are not repeated here.
    let mut lines = vec![
        heading("Pair with the Home app"),
        Line::styled(format!("In Home choose Add Accessory, then scan or type {code}."), DIM),
        Line::raw(""),
    ];
    if let Some(qr) = s.setup_uri.as_deref().and_then(crate::qr::render).filter(|_| !app.pairing_picture) {
        if qr.lines().all(|l| l.chars().count() <= width) {
            lines.extend(qr.lines().map(|l| Line::raw(l.to_owned())));
            lines.push(Line::raw(""));
        }
    }
    lines
}

/// The lines of the overview, and what can be clicked in them.
fn overview_lines(app: &App, s: &State, width: usize) -> (Vec<Line<'static>>, Vec<Hit>) {
    let mut lines = pairing_lines(app, s, width);
    let pairing = lines.len() + 3;
    lines.extend([
        field("Bridge", format!("{}  v{}", s.name, s.version)),
        field("Listening", format!("{}  configuration {}", s.listen, s.config_number)),
        field("Uptime", duration(s.uptime_secs)),
        field(
            "Pairing",
            if s.paired {
                Span::raw(format!("paired with {} controller(s)", s.controllers.len()))
            } else {
                Span::styled("not paired", WARN)
            },
        ),
        field(
            "Console",
            match &s.console {
                Some(c) if c.connected => Span::raw(format!(
                    "{} up, updated {}",
                    c.host,
                    c.last_update.map_or("not yet".to_owned(), |at| app.ago(at))
                )),
                Some(c) if c.waiting_for_password => Span::styled(
                    "waiting for the Protect password",
                    WARN,
                ),
                Some(c) => Span::styled(
                    format!(
                        "{} down{}",
                        c.host,
                        c.last_update.map_or(String::new(), |at| format!(", heard {}", app.ago(at)))
                    ),
                    BAD,
                ),
                None => Span::styled("no UniFi Protect configured", DIM),
            },
        ),
    ]);
    // Why the console is not connected, when the daemon knows.
    if let Some(problem) = s.console.as_ref().and_then(|c| c.problem.clone()) {
        lines.push(field("", Span::styled(problem, DIM)));
    }
    // The pairing line shows the code; the next two lines are the name settings.
    let mut actions = vec![Hit::line(pairing, Action::Pair), Hit::line(lines.len(), Action::Prefix), Hit::line(lines.len() + 1, Action::Suffix)];
    // Each sensor switch on the two lines after them, by where it is drawn.
    for (number, detection) in Detection::ALL.into_iter().enumerate() {
        let start = 13 + 13 * (number % 2);
        actions.push(Hit { line: lines.len() + 2 + number / 2, columns: Some(start..start + 13), action: Action::Detect(detection) });
    }
    // Which recognition sensors every camera gets, switched by number.
    // Two short lines, since the pane is narrow on a small terminal.
    let sensors = |label: &str, shown: std::ops::Range<usize>| {
        let mut line = vec![Span::styled(format!("{label:<12} "), DIM)];
        for number in shown {
            let detection = Detection::ALL[number];
            let on = s.detect_everywhere.iter().any(|w| w == detection.word());
            line.push(Span::styled(format!("{}", number + 1), KEY));
            line.push(Span::raw(format!("{}{:<9}", if on { "[x]" } else { "[ ]" }, detection.label())));
        }
        Line::from(line)
    };
    lines.extend([
        affix_setting("Name prefix", "P", &s.name_prefix),
        affix_setting("Name suffix", "S", &s.name_suffix),
        sensors("Sensors on", 0..2),
        sensors("all cameras", 2..4),
        Line::raw(""),
        heading("Controllers"),
    ]);
    for c in &s.connections {
        let who = match &c.controller {
            // Pairing ids are long UUIDs; the first group is enough to tell them apart.
            Some(id) => {
                let admin = s.controllers.iter().any(|p| p.id == *id && p.admin);
                format!("{}{}", id.split('-').next().unwrap_or(id), if admin { " (admin)" } else { "" })
            }
            None => "not verified".to_owned(),
        };
        lines.push(Line::from(vec![
            Span::raw(format!("  {:<17}", c.peer)),
            Span::raw(format!("{who:<18}")),
            Span::styled(duration(c.connected_secs), DIM),
        ]));
    }
    if s.connections.is_empty() {
        lines.push(Line::styled("  none connected", DIM));
    }
    lines.push(Line::raw(""));
    lines.push(heading("Devices"));
    let affix = s.name_prefix.chars().count() + s.name_suffix.chars().count();
    let name_width = app.devices.iter().map(|d| d.name.chars().count()).max().unwrap_or(0).clamp(4, 22) + affix;
    for (row, d) in app.devices.iter().enumerate() {
        // Clicking a device here selects it, as in the list.
        actions.push(Hit::line(lines.len(), Action::Select(row + 1)));
        let name = app.homekit_name(d, name_width);
        let used: usize = name.iter().map(|s| s.content.chars().count()).sum();
        let mut spans = vec![Span::raw("  "), dot(d.online), Span::raw(" ")];
        spans.extend(name);
        spans.push(Span::raw(" ".repeat(name_width.saturating_sub(used) + 1)));
        spans.push(Span::styled(format!("{:<9}", d.kind), DIM));
        spans.extend(app.summary_line(d, width.saturating_sub(name_width + 14)));
        lines.push(Line::from(spans));
    }
    if app.devices.is_empty() {
        lines.push(Line::styled("  none published", DIM));
    }
    (lines, actions)
}

/// The lines of a device's pane, and which of them can be clicked.
fn device_lines(app: &App, d: &Device) -> (Vec<Line<'static>>, Vec<Hit>) {
    let mut lines = device_facts(app, d);
    let mut actions = Vec::new();
    if d.key.is_some() {
        if !lines.is_empty() {
            lines.push(Line::raw(""));
        }
        lines.push(heading("Settings"));
        let key = |k: &str| Span::styled(format!("  {k}  "), KEY);
        actions.push(Hit::line(lines.len(), Action::ToggleShared));
        lines.push(Line::from(vec![
            key("s"),
            Span::raw(if d.hidden { "[ ] Share with HomeKit" } else { "[x] Share with HomeKit" }),
        ]));
        actions.push(Hit::line(lines.len(), Action::Rename));
        let mut name = vec![key("r"), Span::raw(format!("Name: {}", d.name))];
        if let Some(own) = &d.protect_name {
            name.push(Span::styled(format!("  (Protect: {own})"), DIM));
        }
        lines.push(Line::from(name));
        // One occupancy sensor for each kind of thing the camera recognises.
        let everywhere = app.state.as_ref().map_or(&[][..], |s| s.detect_everywhere.as_slice());
        for (number, detection) in Detection::ALL.into_iter().enumerate() {
            let listed = |list: &[String]| list.iter().any(|w| w == detection.word());
            if !listed(&d.detects) {
                continue;
            }
            actions.push(Hit::line(lines.len(), Action::Detect(detection)));
            let (here, all) = (listed(&d.detect_here), listed(everywhere));
            let mut line = vec![
                key(&format!("{}", number + 1)),
                Span::raw(format!("[{}] {} sensor", if here || all { "x" } else { " " }, detection.label())),
            ];
            if all {
                line.push(Span::styled("  (on every camera)", DIM));
            }
            lines.push(Line::from(line));
        }
    }
    (lines, actions)
}

fn device_facts(app: &App, d: &Device) -> Vec<Line<'static>> {
    if d.hidden && d.aid == 0 {
        return vec![field("Status", Span::styled("not shared with HomeKit", DIM))];
    }
    let status = match d.online {
        _ if d.hidden => Span::styled("being removed from HomeKit", WARN),
        Some(true) => Span::styled("online", GOOD),
        Some(false) => Span::styled("offline", BAD),
        None => Span::styled("not reported", DIM),
    };
    let mut lines = vec![
        field("Status", status),
        field("Model", d.model.clone()),
        field("Serial", format!("{}  HomeKit id {}", d.serial_number, d.aid)),
    ];
    if app.affix() != ("", "") && d.key.is_some() && !d.hidden {
        let mut name = vec![Span::styled(format!("{:<12} ", "In HomeKit"), DIM)];
        name.extend(app.homekit_name(d, usize::MAX));
        lines.push(Line::from(name));
    }
    lines.push(Line::raw(""));
    let yes_no = |on: bool, yes: &'static str, no: &'static str| if on { Span::styled(yes, WARN) } else { Span::raw(no) };
    if d.motion.is_some() || d.last_motion.is_some() {
        let last = d.last_motion.map_or("none since the bridge started".to_owned(), |at| format!("last {}", app.when(at)));
        lines.push(field("Motion", if d.motion == Some(true) { Span::styled("now", WARN) } else { Span::raw(last) }));
    }
    if d.kind == "doorbell" || d.last_ring.is_some() {
        lines.push(field("Last ring", d.last_ring.map_or("none since the bridge started".to_owned(), |at| app.when(at))));
    }
    if let Some(on) = d.light_on {
        let level = d.brightness.map_or(String::new(), |percent| format!(", brightness {percent}%"));
        lines.push(field("Light", if on { Span::styled(format!("on{level}"), WARN) } else { Span::raw(format!("off{level}")) }));
    }
    lines.extend(d.readings.iter().map(|r| field(&r.label, r.value.clone())));
    if let Some(percent) = d.battery {
        let low = d.low_battery == Some(true);
        lines.push(field("Battery", Span::styled(format!("{percent}%{}", if low { ", low" } else { "" }), if low { WARN } else { Style::new() })));
    }
    if let Some(open) = d.tampered {
        lines.push(field("Tamper", if open { Span::styled("case opened", BAD) } else { Span::raw("no") }));
    }
    if d.recording.is_some() || !d.viewers.is_empty() {
        let mut label = "Viewers";
        for v in &d.viewers {
            lines.push(field(label, format!("{}  {}x{}  {}", v.peer, v.width, v.height, duration(v.secs))));
            label = "";
        }
        if d.viewers.is_empty() {
            lines.push(field("Viewers", Span::styled("nobody watching", DIM)));
        }
    }
    if let Some(r) = &d.recording {
        lines.push(field("Recording", yes_no(r.enabled, "switched on in HomeKit", "switched off in HomeKit")));
        if let Some(seconds) = r.active_secs {
            lines.push(field("", Span::styled(format!("in progress, {}", duration(seconds)), BAD)));
        }
        lines.push(field(
            "Last clip",
            match (r.last_at, r.last_secs) {
                (Some(at), Some(seconds)) => format!("{} for {}", app.when(at), duration(seconds)),
                _ => "none since the bridge started".to_owned(),
            },
        ));
    }
    lines
}

fn draw_detail(frame: &mut Frame, app: &mut App, area: Rect) {
    let width = area.width.saturating_sub(2) as usize;
    let (title, lines, actions) = match (&app.state, app.selected_device()) {
        (Some(_), Some(d)) => {
            let (lines, actions) = device_lines(app, d);
            (format!("{} · {}", d.name, d.kind), lines, actions)
        }
        (Some(s), None) => {
            let (lines, actions) = overview_lines(app, s, width);
            ("Overview".to_owned(), lines, actions)
        }
        (None, _) => ("Overview".to_owned(), vec![Line::styled("waiting for the daemon", DIM)], Vec::new()),
    };
    app.actions = actions;
    app.detail_max = lines.len().saturating_sub(area.height.saturating_sub(2) as usize);
    app.detail_scroll = app.detail_scroll.min(app.detail_max);
    let more = if app.detail_max > app.detail_scroll { " ↓" } else { "" };
    frame.render_widget(
        Paragraph::new(lines)
            .scroll((app.detail_scroll.min(u16::MAX as usize) as u16, 0))
            .block(pane(&format!("{title}{more}"), app.focus == Focus::Detail)),
        area,
    );
}

fn draw_log(frame: &mut Frame, app: &App, area: Rect) {
    let (visible, width) = (area.height.saturating_sub(2) as usize, area.width.saturating_sub(2) as usize);
    let shown = app.visible_logs();
    let end = shown.len().saturating_sub(app.log_scroll);
    // Back from the newest line shown until the pane is full; the oldest of
    // them may lose its first rows off the top.
    let mut lines: Vec<Line> = Vec::new();
    for l in shown[..end].iter().rev() {
        if lines.len() >= visible {
            break;
        }
        let mut rows = app.log_rows(l, width);
        rows.append(&mut lines);
        lines = rows;
    }
    let lines = lines.split_off(lines.len().saturating_sub(visible));
    let mut lines = lines;
    let mut title = "Log".to_owned();
    if let Some(name) = app.log_device() {
        title.push_str(&format!(": {name} (f for all)"));
    }
    if app.warnings_only {
        title.push_str(", warnings and errors only (w for all)");
    }
    if app.log_scroll > 0 {
        title.push_str(", scrolled (End to follow)");
    }
    if lines.is_empty() && !app.logs.is_empty() {
        lines.push(Line::styled("nothing logged that matches", DIM));
    }
    // The wrap switch, on the right of the border, where a click flips it.
    let wrap = Line::from(vec![Span::raw(" "), Span::styled("W", KEY), Span::styled(if app.log_wrap { " no wrap " } else { " wrap " }, DIM)]);
    let block = pane(&title, app.focus == Focus::Log).title(wrap.right_aligned());
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

/// Draws a titled box in the middle of the screen, sized to its lines, and
/// returns where it went.
fn draw_box(frame: &mut Frame, title: &str, lines: Vec<Line>) -> Rect {
    let widest = lines.iter().map(|l| l.width()).max().unwrap_or(0).max(title.chars().count() + 2);
    let width = widest.min(u16::MAX as usize - 4) as u16 + 4;
    let height = lines.len() as u16 + 2;
    let screen = frame.area();
    let area = Rect {
        x: screen.x + screen.width.saturating_sub(width) / 2,
        y: screen.y + screen.height.saturating_sub(height) / 2,
        width: width.min(screen.width),
        height: height.min(screen.height),
    };
    frame.render_widget(Clear, area);
    let block = Block::bordered().border_type(BorderType::Rounded).border_style(KEY).title(format!(" {title} "));
    frame.render_widget(Paragraph::new(lines).block(block), area);
    area
}

/// The way back to the daemon, present while attached.
type Requests = Arc<Mutex<Option<UnixStream>>>;

/// Sends the daemon a request. One that cannot be sent is dropped: the
/// dashboard goes on showing what is true, which is that nothing changed.
fn send_request(requests: &Requests, command: &Command) {
    let Ok(mut line) = serde_json::to_vec(command) else { return };
    line.push(b'\n');
    if let Some(stream) = requests.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).as_mut() {
        let _ = stream.write_all(&line);
    }
}

/// Connects to the daemon and forwards its messages, reconnecting forever.
fn read_daemon(socket: PathBuf, tx: mpsc::Sender<Incoming>, requests: Requests) {
    let set = |stream: Option<UnixStream>| *requests.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = stream;
    loop {
        if let Ok(stream) = UnixStream::connect(&socket) {
            set(stream.try_clone().ok());
            if tx.send(Incoming::Attached).is_err() {
                return;
            }
            for line in BufReader::new(stream).lines() {
                let Ok(line) = line else { break };
                // An unknown message means a newer daemon; skip it.
                if let Ok(message) = serde_json::from_str::<Message>(&line) {
                    if tx.send(Incoming::Message(Box::new(message))).is_err() {
                        return;
                    }
                }
            }
            set(None);
            if tx.send(Incoming::Detached).is_err() {
                return;
            }
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

pub fn run(state_dir: &Path) -> Result<()> {
    let (tx, rx) = mpsc::channel();
    let socket = state_dir.join(control::SOCKET_NAME);
    let requests = Requests::default();
    let for_reader = requests.clone();
    std::thread::spawn(move || read_daemon(socket, tx, for_reader));

    // Without a terminal there is nothing to draw on, and the library
    // underneath would abort rather than say so.
    if !(std::io::stdin().is_terminal() && std::io::stdout().is_terminal()) {
        anyhow::bail!(
            "the dashboard needs a terminal. For a report that does not, use `harbormaster service status` or `harbormaster logs`"
        );
    }
    let mut terminal = ratatui::init();
    let _ = execute!(std::io::stdout(), EnableMouseCapture);
    let mut app = App::new();
    let result = (|| -> Result<()> {
        loop {
            while let Ok(incoming) = rx.try_recv() {
                app.receive(incoming);
            }
            for command in app.outbox.drain(..) {
                send_request(&requests, &command);
            }
            terminal.draw(|frame| draw(frame, &mut app))?;
            if event::poll(Duration::from_millis(150))? && !app.handle(event::read()?) {
                return Ok(());
            }
        }
    })();
    let _ = execute!(std::io::stdout(), DisableMouseCapture);
    ratatui::restore();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::{Accessory, Connection, Console, Controller, Reading, Recording, Viewer};
    use ratatui::backend::TestBackend;
    use ratatui::crossterm::event::{KeyEvent, MouseEvent};
    use ratatui::Terminal;

    /// 2023-11-14 22:13:20 UTC, which is 14:13:20 in the test's zone.
    const NOW: u64 = 1_700_000_000;

    fn sample_state(paired: bool) -> State {
        let reading = |label: &str, value: &str| Reading { label: label.into(), value: value.into() };
        let device = |aid, kind: &str, name: &str| Device {
            aid,
            kind: kind.into(),
            name: name.into(),
            model: "G4 Doorbell Pro".into(),
            serial_number: format!("AA{aid:02}"),
            online: Some(true),
            ..Device::default()
        };
        State {
            pid: 0,
            detect_everywhere: Vec::new(),
            name: "Harbormaster 6C2C".into(),
            version: "0.1.0".into(),
            listen: "[::]:51826".into(),
            uptime_secs: 3725,
            paired,
            // The daemon sends the code whether or not it is paired.
            setup_code: Some("420-21-195".into()),
            setup_uri: Some("X-HM://0081YCYEP7OSX".into()),
            controllers: vec![Controller { id: "AAAA1111-2222".into(), admin: true }],
            connections: vec![Connection {
                peer: "192.0.2.236".into(),
                controller: Some("AAAA1111-2222".into()),
                connected_secs: 75,
            }],
            accessories: Vec::new(),
            time: NOW,
            name_prefix: String::new(),
            name_suffix: String::new(),
            config_number: 12,
            console: Some(Console { host: "192.0.2.1".into(), connected: true, last_update: Some(NOW - 2), ..Console::default() }),
            devices: vec![
                Device {
                    motion: Some(true),
                    last_motion: Some(NOW - 5),
                    last_ring: Some(NOW - 200),
                    viewers: vec![Viewer { peer: "192.0.2.236".into(), width: 1280, height: 720, secs: 65 }],
                    recording: Some(Recording {
                        enabled: true,
                        active_secs: Some(12),
                        last_at: Some(NOW - 2000),
                        last_secs: Some(19),
                    }),
                    ..device(2, "doorbell", "Front Door")
                },
                Device {
                    motion: Some(false),
                    last_motion: Some(NOW - 90_000),
                    recording: Some(Recording::default()),
                    ..device(3, "camera", "Garage")
                },
                Device { light_on: Some(true), brightness: Some(83), motion: Some(false), ..device(4, "light", "Floodlight") },
                Device {
                    online: Some(false),
                    tampered: Some(true),
                    battery: Some(93),
                    readings: vec![reading("Temperature", "0.0 °C")],
                    ..device(5, "sensor", "Yard")
                },
                Device {
                    battery: Some(96),
                    low_battery: Some(false),
                    tampered: Some(false),
                    readings: vec![reading("Contact", "closed"), reading("Temperature", "21.5 °C")],
                    ..device(6, "sensor", "Porch")
                },
            ],
        }
    }

    fn app_with(state: State) -> App {
        let mut app = App::new();
        app.zone = |_| -8 * 3600;
        app.receive(Incoming::Attached);
        app.receive(Incoming::Message(Box::new(Message::State(Box::new(state)))));
        for i in 0..40 {
            let (level, message) = match i % 4 {
                0 => ("INFO", format!("Front Door: motion event {i}")),
                1 => ("WARN", format!("Garage: ffmpeg: complaint {i}")),
                _ => ("INFO", format!("event {i}")),
            };
            let line = LogLine { time: NOW - 40 + i, level: level.into(), message };
            app.receive(Incoming::Message(Box::new(Message::Log(line))));
        }
        app
    }

    fn render_at(app: &mut App, width: u16, height: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|frame| draw(frame, app)).unwrap();
        let buffer = terminal.backend().buffer().clone();
        let mut out = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                out.push_str(buffer[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    fn render(app: &mut App) -> String {
        render_at(app, 80, 24)
    }

    fn key(code: KeyCode) -> Event {
        Event::Key(KeyEvent::new(code, KeyModifiers::NONE))
    }

    fn mouse(kind: MouseEventKind, column: u16, row: u16) -> Event {
        Event::Mouse(MouseEvent { kind, column, row, modifiers: KeyModifiers::NONE })
    }

    fn assert_shows(screen: &str, expected: &[&str]) {
        for text in expected {
            assert!(screen.contains(text), "missing {text:?} in:\n{screen}");
        }
    }

    #[test]
    fn overview_fits_an_80_by_24_terminal() {
        let mut app = app_with(sample_state(true));
        let screen = render(&mut app);
        assert_shows(
            &screen,
            &[
                // The quick view.
                "Harbormaster 6C2C",
                "paired · 1 connected",
                "192.0.2.1 · 2s",
                "1 of 5 offline",
                "1 watching · 1 recording",
                // The device list.
                "Devices (5)",
                "Overview",
                "● Front Door",
                "○ Yard",
                // The overview itself.
                "[::]:51826  configuration 12",
                "Uptime       1h 02m",
                "192.0.2.1 up, updated 2s ago",
                "Sensors on   1[ ]Person",
                "192.0.2.236",
                "AAAA1111 (admin)",
                "1m 15s",
                // The log, in local time, newest last.
                "14:13:19 INFO  event 39",
            ],
        );
        assert!(!screen.contains("event 2 "), "log should show the tail");
        assert!(screen.lines().all(|l| l.chars().count() == 80));
    }

    #[test]
    fn wide_terminal_shows_every_device_with_its_activity() {
        let mut app = app_with(sample_state(true));
        let screen = render_at(&mut app, 140, 40);
        assert_shows(
            &screen,
            &[
                "Front Door doorbell recording 12s · 1 watching · motion · rang 14:10",
                // Motion a day ago shows its date.
                "Garage     camera   motion Nov 13 13:13 · rec off",
                "Floodlight light    on 83%",
                "Yard       sensor   offline",
                "Porch      sensor   closed · 21.5 °C · battery 96%",
                "configuration 12",
                "event 39",
            ],
        );
        // An offline device's stale readings are not passed off as current.
        assert!(!screen.contains("0.0 °C"));
        // The sidebar has room for state beside the name.
        assert!(screen.contains("● Floodlight") && screen.contains("on 83% "), "{screen}");
    }

    #[test]
    fn selecting_a_device_shows_its_details_and_its_log_lines() {
        let mut app = app_with(sample_state(true));
        app.handle(key(KeyCode::Down));
        let screen = render(&mut app);
        assert_shows(
            &screen,
            &[
                "Front Door · doorbell",
                "Status       online",
                "G4 Doorbell Pro",
                "AA02  HomeKit id 2",
                "Motion       now",
                "Last ring    14:10:00 (3m 20s ago)",
                "Viewers      192.0.2.236  1280x720  1m 05s",
                "Recording    switched on in HomeKit",
                "in progress, 12s",
                "Last clip    13:40:00 (33m 20s ago) for 19s",
                "Log: Front Door",
                "Front Door: motion event 36",
            ],
        );
        assert!(!screen.contains("event 39") && !screen.contains("Garage: ffmpeg"), "{screen}");

        // f shows every line again; w keeps warnings and errors only.
        app.handle(key(KeyCode::Char('f')));
        assert!(render(&mut app).contains("event 39"));
        app.handle(key(KeyCode::Char('w')));
        let screen = render(&mut app);
        assert_shows(&screen, &["warnings and errors only", "Garage: ffmpeg: complaint 37"]);
        assert!(!screen.contains("INFO"), "{screen}");

        // A sensor shows its own facts and none of a camera's.
        app.handle(key(KeyCode::End));
        let screen = render(&mut app);
        assert_shows(&screen, &["Porch · sensor", "Contact      closed", "Temperature  21.5 °C", "Battery      96%", "Tamper       no"]);
        assert!(!screen.contains("Viewers") && !screen.contains("Recording"), "{screen}");
    }

    #[test]
    fn keyboard_moves_between_panes_and_scrolls_them() {
        let mut app = app_with(sample_state(true));
        render(&mut app);
        assert_eq!(app.focus, Focus::Devices);
        app.handle(key(KeyCode::Char('j')));
        app.handle(key(KeyCode::Char('j')));
        assert_eq!(app.selected, 2);
        app.handle(key(KeyCode::Char('k')));
        assert_eq!(app.selected, 1);
        for _ in 0..9 {
            app.handle(key(KeyCode::Down));
        }
        assert_eq!(app.selected, 5, "selection stops at the last device");

        app.handle(key(KeyCode::Tab));
        assert_eq!(app.focus, Focus::Detail);
        app.handle(key(KeyCode::Tab));
        assert_eq!(app.focus, Focus::Log);
        app.handle(key(KeyCode::Char('f')));
        render(&mut app);
        app.handle(key(KeyCode::Up));
        assert_eq!(app.log_scroll, 1);
        assert!(!render(&mut app).contains("event 39"));
        app.handle(key(KeyCode::Home));
        assert!(render(&mut app).contains("event 2 "), "Home reaches the oldest line");
        app.handle(key(KeyCode::End));
        assert_eq!(app.log_scroll, 0);
        app.handle(key(KeyCode::Tab));
        assert_eq!(app.focus, Focus::Devices);

        // Esc backs out to the overview rather than quitting.
        assert!(app.handle(key(KeyCode::Esc)));
        assert_eq!(app.selected, 0);
        assert!(!app.handle(key(KeyCode::Char('q'))));
    }

    #[test]
    fn overview_scrolls_when_it_does_not_fit() {
        let mut state = sample_state(true);
        let extra: Vec<Device> = (10..40)
            .map(|aid| Device { aid, kind: "camera".into(), name: format!("Camera {aid}"), ..Device::default() })
            .collect();
        state.devices.extend(extra);
        let mut app = app_with(state);
        let screen = render(&mut app);
        assert!(screen.contains("Overview ↓") && !screen.contains("Camera 39"), "{screen}");
        app.handle(key(KeyCode::Tab));
        app.handle(key(KeyCode::End));
        assert!(render(&mut app).contains("Camera 39  camera"), "{}", render(&mut app));

        // The device list scrolls to keep the selection in view.
        app.handle(key(KeyCode::Left));
        app.handle(key(KeyCode::End));
        assert_eq!(app.selected, 35);
        assert!(render(&mut app).contains("Camera 39 · camera"));
        assert!(app.list_offset > 0);
    }

    #[test]
    fn mouse_selects_focuses_and_scrolls() {
        let mut app = app_with(sample_state(true));
        render(&mut app);
        // Under the header, the third row of the list is the second device.
        assert_eq!(app.list_top, app.list_area.y + 2);
        let (x, y) = (app.list_area.x + 3, app.list_top + 2);
        app.handle(mouse(MouseEventKind::Down(MouseButton::Left), x, y));
        assert_eq!((app.selected, app.focus), (2, Focus::Devices));
        assert!(render(&mut app).contains("Garage · camera"));
        // Clicking the border, the header or below the last device changes nothing.
        for row in [app.list_area.y, app.list_area.y + 1, app.list_top + 6] {
            app.handle(mouse(MouseEventKind::Down(MouseButton::Left), x, row));
        }
        assert_eq!(app.selected, 2);

        app.handle(mouse(MouseEventKind::ScrollUp, x, y));
        assert_eq!(app.selected, 1);
        app.handle(mouse(MouseEventKind::Down(MouseButton::Left), app.detail_area.x + 5, app.detail_area.y + 2));
        assert_eq!(app.focus, Focus::Detail);

        // The wheel scrolls the log under the pointer without taking focus.
        app.handle(key(KeyCode::Char('f')));
        render(&mut app);
        app.handle(mouse(MouseEventKind::ScrollUp, app.log_area.x + 2, app.log_area.y + 2));
        assert_eq!((app.log_scroll, app.focus), (3, Focus::Detail));
        assert!(!render(&mut app).contains("event 39"));
        app.handle(mouse(MouseEventKind::ScrollDown, app.log_area.x + 2, app.log_area.y + 2));
        assert_eq!(app.log_scroll, 0);
        app.handle(mouse(MouseEventKind::Down(MouseButton::Left), app.log_area.x + 2, app.log_area.y + 2));
        assert_eq!(app.focus, Focus::Log);
    }

    #[test]
    fn selection_follows_a_device_when_the_list_changes() {
        let mut app = app_with(sample_state(true));
        app.select(3);
        let mut state = sample_state(true);
        state.devices.remove(0);
        app.receive(Incoming::Message(Box::new(Message::State(Box::new(state)))));
        assert_eq!(app.selected_device().unwrap().name, "Floodlight");

        // New log lines do not move a log that is scrolled back.
        app.select(0);
        render(&mut app);
        app.scroll_log(5);
        let before = render(&mut app);
        let line = LogLine { time: NOW, level: "INFO".into(), message: "later".into() };
        app.receive(Incoming::Message(Box::new(Message::Log(line))));
        assert_eq!(render(&mut app), before);
    }

    #[test]
    fn detached_tui_says_daemon_is_not_running() {
        let mut app = App::new();
        assert!(render(&mut app).contains("daemon not running"));
        // Losing the daemon later says so too, rather than showing stale health.
        let mut app = app_with(sample_state(true));
        app.receive(Incoming::Detached);
        assert!(render(&mut app).contains("daemon not running"));
    }

    #[test]
    fn waiting_for_the_password_is_shown_and_it_can_be_typed_unseen() {
        let mut state = sample_state(true);
        state.console = Some(Console {
            host: "192.0.2.1".into(),
            waiting_for_password: true,
            problem: Some("the console rejected the username or password".into()),
            ..Console::default()
        });
        let mut app = app_with(state);
        let screen = render(&mut app);
        assert_shows(&screen, &["needs password (u)", "waiting for the Protect password", "u unlock", "rejected the username"]);

        app.handle(key(KeyCode::Char('u')));
        for c in "correct horse".chars() {
            app.handle(key(KeyCode::Char(c)));
        }
        let screen = render(&mut app);
        assert_shows(&screen, &["UniFi Protect password", "•••••••••••••", "Enter signs in"]);
        assert!(!screen.contains("correct") && !screen.contains("horse"), "{screen}");
        app.handle(key(KeyCode::Enter));
        assert_eq!(app.outbox, [Command::Unlock { password: Secret::new("correct horse".into()) }]);
        assert_eq!(app.modal, Modal::None);

        // With a password in hand there is nothing to unlock.
        let mut app = app_with(sample_state(true));
        app.handle(key(KeyCode::Char('u')));
        assert_eq!(app.modal, Modal::None);
        assert!(!render(&mut app).contains("u unlock"));
    }

    #[test]
    fn console_trouble_and_absence_are_plain() {
        let mut state = sample_state(true);
        state.console = Some(Console { host: "192.0.2.1".into(), connected: false, last_update: Some(NOW - 300), ..Console::default() });
        let screen = render(&mut app_with(state));
        assert_shows(&screen, &["Console 192.0.2.1 down", "192.0.2.1 down, heard 5m 00s ago"]);

        let mut state = sample_state(true);
        state.console = None;
        assert_shows(&render(&mut app_with(state)), &["not configured", "no UniFi Protect configured"]);
    }

    #[test]
    fn older_daemon_without_devices_still_lists_its_accessories() {
        let accessory = |aid, name: &str, model: &str| Accessory {
            aid,
            name: name.into(),
            manufacturer: "Harbormaster".into(),
            model: model.into(),
            serial_number: "demo-1".into(),
            readings: vec![Reading { label: "Temperature".into(), value: "21.5 °C".into() }],
        };
        let mut state = sample_state(true);
        state.devices.clear();
        state.accessories = vec![accessory(1, "Harbormaster 6C2C", "Bridge"), accessory(2, "Demo Temperature", "Demo")];
        let mut app = app_with(state);
        let screen = render(&mut app);
        assert_shows(&screen, &["Devices (1)", "Demo Temperature", "21.5 °C"]);
        app.handle(key(KeyCode::Down));
        assert_shows(&render(&mut app), &["Demo Temperature · accessory", "Temperature  21.5 °C", "demo-1"]);
    }

    #[test]
    fn pairing_code_is_always_at_hand() {
        // Unpaired: the code is beside the list, and the overview says how to pair.
        let mut app = app_with(sample_state(false));
        let screen = render(&mut app);
        assert_shows(&screen, &["○ Bridge  not paired  ", " Pairing code p hide ", "Setup code  420-21-195", "Pair with the Home app", " p hide code "]);
        // At 80x24 the picture does not crowd the list: it goes in the overview.
        assert!(!app.pairing_picture);
        assert!(app.list_area.height >= 10, "{screen}");
        assert!(render_at(&mut app, 110, 40).contains('█'));
        // On a tall terminal it sits in the left column, and is not drawn twice.
        let tall = render_at(&mut app, 190, 55);
        assert!(app.pairing_picture && app.pairing_area.height > 15, "{tall}");
        let side = app.list_area.width as usize;
        assert!(tall.lines().all(|l| !l.chars().skip(side).any(|c| c == '█')), "drawn once, on the left: {tall}");

        // p hides it all, and shows it again.
        app.handle(key(KeyCode::Char('p')));
        let hidden = render(&mut app);
        assert!(!hidden.contains("420-21-195") && !hidden.contains('█'), "{hidden}");
        assert_shows(&hidden, &["not paired (press p)", " p show code "]);
        assert_eq!(app.pairing_area.height, 0);
        app.handle(key(KeyCode::Char('p')));
        assert!(render(&mut app).contains("Setup code  420-21-195"));

        // Paired: still shown by default, with the plain truth about it.
        let mut app = app_with(sample_state(true));
        let screen = render(&mut app);
        assert_shows(&screen, &["Setup code  420-21-195", "Remove from Home to reuse it.", " p hide code "]);
        assert!(!screen.contains("Pair with the Home app"), "the overview no longer leads with it: {screen}");
        let tall = render_at(&mut app, 190, 55);
        assert_shows(&tall, &["Paired: remove the bridge from Home to use it again."]);
        assert!(tall.contains('█'), "{tall}");

        // A daemon from before the code was always sent: nothing to show or toggle.
        let mut state = sample_state(true);
        (state.setup_code, state.setup_uri) = (None, None);
        let mut app = app_with(state);
        let screen = render(&mut app);
        assert!(!screen.contains("Setup code") && !screen.contains("p hide"), "{screen}");
    }

    #[test]
    fn the_left_column_runs_the_full_height_and_the_log_sits_under_the_detail() {
        for (width, height) in [(80, 24), (190, 55)] {
            let mut app = app_with(sample_state(true));
            render_at(&mut app, width, height);
            // Status box, then the list down to the footer.
            assert_eq!(app.list_area.bottom(), height - 1);
            assert_eq!((app.log_area.x, app.log_area.width), (app.detail_area.x, app.detail_area.width));
            assert_eq!((app.detail_area.y, app.log_area.y), (0, app.detail_area.bottom()));
            assert_eq!(app.log_area.bottom(), height - 1);
        }
        // On a tall screen the detail stops at what a camera needs, and the
        // log gets the rest: far more than the old 30%.
        let mut app = app_with(sample_state(true));
        render_at(&mut app, 190, 55);
        assert_eq!(app.detail_area.height, DETAIL_LINES + 2);
        assert!(app.log_area.height >= 30, "{:?}", app.log_area);
        // The log keeps its rows on a small one.
        render(&mut app);
        assert_eq!(app.log_area.height, LOG_ROWS);
    }

    #[test]
    fn device_list_is_a_table_that_gives_way_on_narrow_terminals() {
        let mut app = app_with(with_affix(editable(sample_state(true))));
        let wide = render_at(&mut app, 190, 55);
        // A faint header, then one aligned row per device, the HomeKit name first.
        assert_shows(
            &wide,
            &[
                "   Name               Kind     State    Motion",
                " ● HM Front Door (UP) doorbell rec now  now",
                " ● HM Garage (UP)     camera   rec off  Nov 13",
                " ● HM Floodlight (UP) light    on 83%",
                " ○ HM Yard (UP)       sensor   offline",
                " ● HM Porch (UP)      sensor   closed",
                " · Side Gate          camera   unshared",
            ],
        );
        // Every state starts in the same column.
        let state_column = |screen: &str, name: &str| {
            // Only the device list, on the left.
            let side: String = screen.lines().map(|l| l.chars().take(60).collect::<String>() + "\n").collect();
            let line = side.lines().find(|l| l.contains(name)).unwrap_or_else(|| panic!("{name} in {screen}")).to_owned();
            let state = ["rec ", "on 83%", "offline", "closed", "unshared"].iter().find_map(|s| line.find(s)).unwrap();
            line[..state].chars().count()
        };
        let column = state_column(&wide, "Front Door (UP)");
        for name in ["Garage (UP)", "Floodlight (UP)", "Yard (UP)", "Porch (UP)", "Side Gate"] {
            assert_eq!(state_column(&wide, name), column, "{name}:\n{wide}");
        }

        // At 80 columns the kind and motion give way so names keep their length.
        let narrow = render(&mut app);
        assert_shows(&narrow, &["   Name               State", " ● HM Front Door (UP) rec now", " · Side Gate          unshared"]);
        assert!(!narrow.contains("Motion") && !narrow.contains("doorbell rec"), "{narrow}");
        for name in ["HM Garage (UP)", "HM Floodlight (UP)", "Side Gate"] {
            assert_eq!(state_column(&narrow, name), state_column(&narrow, "Front Door (UP)"), "{name}:\n{narrow}");
        }

        // A long name is cut with a mark, not left to push the state out.
        let mut state = sample_state(true);
        state.devices[2].name = "Garage Exterior Turret Northwest Corner".into();
        let screen = render(&mut app_with(state));
        assert!(screen.contains("● Garage Exterior Tu… on 83%"), "{screen}");
        assert!(screen.lines().all(|l| l.chars().count() == 80));
    }

    #[test]
    fn footer_offers_pairing_and_fits_80_columns_in_every_state() {
        let footer = |app: &mut App| render(app).lines().last().unwrap().to_owned();
        let mut waiting = sample_state(true);
        waiting.console.as_mut().unwrap().waiting_for_password = true;
        let mut unpaired = editable(sample_state(false));
        unpaired.console.as_mut().unwrap().waiting_for_password = true;
        for state in [sample_state(true), editable(sample_state(true)), waiting, unpaired] {
            for row in 0..=5 {
                let mut app = app_with(state.clone());
                app.select(row);
                app.warnings_only = row % 2 == 0;
                let line = footer(&mut app);
                assert!(line.chars().count() <= 80);
                assert_shows(&line, &[" p hide code ", " q quit"]);
            }
        }
        // Detached, there is no code to show.
        assert!(!footer(&mut App::new()).contains("code"));
    }

    #[test]
    fn every_key_hint_and_quick_status_line_can_be_clicked() {
        let mut app = app_with(editable(sample_state(true)));
        app.select(1);
        let screen = render(&mut app);
        let footer = screen.lines().last().unwrap();
        let at = |text: &str| footer.find(text).map(|i| footer[..i].chars().count() as u16).unwrap();
        let click = |app: &mut App, x: u16, y: u16| app.handle(mouse(MouseEventKind::Down(MouseButton::Left), x, y));
        let bottom = app.footer_area.y;
        // A hint does what its key does.
        click(&mut app, at("p hide code"), bottom);
        assert!(!app.show_pairing);
        click(&mut app, at("w warnings") + 2, bottom);
        assert!(app.warnings_only);
        click(&mut app, at("r rename"), bottom);
        assert!(matches!(app.modal, Modal::Edit { .. }));
        // Clicking inside the box being typed in keeps it open; outside, closes it.
        render(&mut app);
        let inside = (app.modal_area.x + 2, app.modal_area.y + 1);
        click(&mut app, inside.0, inside.1);
        assert!(matches!(app.modal, Modal::Edit { .. }));
        click(&mut app, 0, 0);
        assert_eq!(app.modal, Modal::None);
        // The quick status's Bridge line shows the code again, and the
        // code's own box hides it.
        let bridge = app.status_area.y + 1;
        click(&mut app, 4, bridge);
        assert!(app.show_pairing);
        render(&mut app);
        let code = (app.pairing_area.x + 3, app.pairing_area.y + 1);
        click(&mut app, code.0, code.1);
        assert!(!app.show_pairing);
        // And quit quits.
        assert!(!click(&mut app, at("q quit"), bottom));
    }

    #[test]
    fn overview_rows_and_sensor_switches_can_be_clicked() {
        let mut app = app_with(sample_state(true));
        let screen = render_at(&mut app, 120, 50);
        let row = |text: &str| screen.lines().position(|l| l.contains(text)).unwrap() as u16;
        let click = |app: &mut App, x: u16, y: u16| app.handle(mouse(MouseEventKind::Down(MouseButton::Left), x, y));
        let x = app.detail_area.x + 1;
        // Each of the two switches on a line is its own target.
        click(&mut app, x + 13 + 13 + 2, row("all cameras"));
        assert_eq!(app.outbox, [Command::SetDetection { key: None, detection: "package".into(), on: true }]);
        click(&mut app, x + 2, row("all cameras"));
        assert_eq!(app.outbox.len(), 1, "the label is not a switch");
        click(&mut app, x + 14, row("Sensors on"));
        assert_eq!(app.outbox[1], Command::SetDetection { key: None, detection: "person".into(), on: true });
        // The pairing line hides or shows the code.
        click(&mut app, x + 4, row("Pairing      paired"));
        assert!(!app.show_pairing);
        // A device in the overview's table selects it.
        click(&mut app, x + 4, row("Floodlight light"));
        assert_eq!(app.selected_device().unwrap().name, "Floodlight");
    }

    fn editable(mut state: State) -> State {
        for device in &mut state.devices {
            device.key = Some(format!("protect:{}:{}", device.kind, device.aid));
        }
        state.devices[1].protect_name = Some("Garage Cam".into());
        state.devices.push(Device {
            key: Some("protect:camera:9".into()),
            kind: "camera".into(),
            name: "Side Gate".into(),
            hidden: true,
            ..Device::default()
        });
        state
    }

    #[test]
    fn recognition_sensors_are_switched_by_number_or_by_clicking() {
        let mut state = editable(sample_state(true));
        state.detect_everywhere = vec!["vehicle".into()];
        state.devices[0].detects = vec!["person".into(), "vehicle".into()];
        state.devices[0].detect_here = vec!["person".into()];
        let mut app = app_with(state);
        // From the overview a number switches a sensor for every camera.
        assert_shows(&render(&mut app), &["Sensors on   1[ ]Person   2[x]Vehicle", "all cameras  3[ ]Animal   4[ ]Package"]);
        app.handle(key(KeyCode::Char('1')));
        app.handle(key(KeyCode::Char('2')));
        let everywhere = |detection: &str, on| Command::SetDetection { key: None, detection: detection.into(), on };
        assert_eq!(app.outbox, [everywhere("person", true), everywhere("vehicle", false)]);
        app.outbox.clear();

        // On a device it switches that device's own, and only kinds the
        // device can recognise are offered.
        app.handle(key(KeyCode::Down));
        let screen = render_at(&mut app, 100, 40);
        assert_shows(&screen, &["1  [x] Person sensor", "2  [x] Vehicle sensor  (on every camera)"]);
        assert!(!screen.contains("Animal sensor"), "{screen}");
        app.handle(key(KeyCode::Char('1')));
        app.handle(key(KeyCode::Char('3')));
        let key_of = app.devices[0].key.clone();
        assert_eq!(app.outbox, [Command::SetDetection { key: key_of.clone(), detection: "person".into(), on: false }]);
        app.outbox.clear();
        let row = app.actions.iter().find(|h| h.action == Action::Detect(Detection::Vehicle)).unwrap().line;
        let (x, y) = (app.detail_area.x + 3, app.detail_area.y + 1 + row as u16);
        app.handle(mouse(MouseEventKind::Down(MouseButton::Left), x, y));
        assert_eq!(app.outbox, [Command::SetDetection { key: key_of, detection: "vehicle".into(), on: true }]);
    }

    #[test]
    fn unsharing_asks_first_and_sharing_does_not() {
        let mut app = app_with(editable(sample_state(true)));
        app.handle(key(KeyCode::Down));
        let screen = render(&mut app);
        assert_shows(&screen, &["Settings", "s  [x] Share with HomeKit", "r  Name: Front Door", "s share  r rename"]);

        app.handle(key(KeyCode::Char('s')));
        let screen = render(&mut app);
        assert_shows(&screen, &["Stop sharing Front Door with HomeKit?", "forget its room", "[ y  Yes, stop sharing ]"]);
        // Anything but yes backs out, including q, which must not quit here.
        assert!(app.handle(key(KeyCode::Char('q'))));
        assert!(app.outbox.is_empty() && app.modal == Modal::None);

        app.handle(key(KeyCode::Char('s')));
        app.handle(key(KeyCode::Char('y')));
        assert_eq!(app.outbox, [Command::SetShared { key: "protect:doorbell:2".into(), shared: false }]);
        app.outbox.clear();

        // A device that is not shared is listed last, and shares at once.
        app.handle(key(KeyCode::End));
        let screen = render(&mut app);
        assert_shows(&screen, &["Side Gate", "not shared", "Status       not shared with HomeKit", "[ ] Share with HomeKit"]);
        assert!(screen.contains("1 of 5 offline"), "a device that is not shared is not counted: {screen}");
        app.handle(key(KeyCode::Char('s')));
        assert_eq!(app.outbox, [Command::SetShared { key: "protect:camera:9".into(), shared: true }]);

        // The overview and the demo sensor have nothing to edit.
        app.outbox.clear();
        app.handle(key(KeyCode::Home));
        app.handle(key(KeyCode::Char('s')));
        app.handle(key(KeyCode::Char('r')));
        assert!(app.outbox.is_empty() && app.modal == Modal::None);
    }

    #[test]
    fn renaming_edits_the_name_in_a_box() {
        let mut app = app_with(editable(sample_state(true)));
        app.select(2);
        assert_shows(&render(&mut app), &["r  Name: Garage  (Protect: Garage Cam)"]);
        app.handle(key(KeyCode::Char('r')));
        assert_shows(&render(&mut app), &["Name to publish", " Garage▏", "Enter saves"]);
        for _ in 0..6 {
            app.handle(key(KeyCode::Backspace));
        }
        for c in "Car port q".chars() {
            app.handle(key(KeyCode::Char(c)));
        }
        assert!(render(&mut app).contains(" Car port q▏"));
        app.handle(key(KeyCode::Enter));
        assert_eq!(app.outbox, [Command::Rename { key: "protect:camera:3".into(), name: Some("Car port q".into()) }]);

        // Esc cancels; an emptied name asks for Protect's own.
        app.outbox.clear();
        app.handle(key(KeyCode::Char('r')));
        app.handle(key(KeyCode::Esc));
        assert!(app.outbox.is_empty() && app.modal == Modal::None);
        app.handle(key(KeyCode::Char('r')));
        for _ in 0..10 {
            app.handle(key(KeyCode::Backspace));
        }
        app.handle(key(KeyCode::Enter));
        assert_eq!(app.outbox, [Command::Rename { key: "protect:camera:3".into(), name: None }]);
        // Names stop growing at the limit.
        app.handle(key(KeyCode::Char('r')));
        for _ in 0..100 {
            app.handle(key(KeyCode::Char('x')));
        }
        assert!(matches!(&app.modal, Modal::Edit { input, .. } if input.chars().count() == MAX_NAME));
    }

    #[test]
    fn settings_can_be_clicked() {
        let mut app = app_with(editable(sample_state(true)));
        app.select(4);
        let screen = render(&mut app);
        let row = |text: &str| screen.lines().position(|l| l.contains(text)).unwrap() as u16;
        let x = app.detail_area.x + 8;
        app.handle(mouse(MouseEventKind::Down(MouseButton::Left), x, row("Name: Yard")));
        assert!(matches!(app.modal, Modal::Edit { target: Target::Device(_), .. }));
        // A click outside the box closes it.
        app.handle(mouse(MouseEventKind::Down(MouseButton::Left), 0, 0));
        assert_eq!(app.modal, Modal::None);

        app.handle(mouse(MouseEventKind::Down(MouseButton::Left), x, row("Share with HomeKit")));
        assert!(matches!(app.modal, Modal::ConfirmUnshare { .. }));
        let screen = render(&mut app);
        let yes = screen.lines().position(|l| l.contains("Yes, stop sharing")).unwrap() as u16;
        assert_eq!(app.yes_area.y, yes);
        // Clicking Keep, beside Yes, changes nothing.
        app.handle(mouse(MouseEventKind::Down(MouseButton::Left), app.yes_area.right() + 5, yes));
        assert!(app.outbox.is_empty() && app.modal == Modal::None);
        app.handle(key(KeyCode::Char('s')));
        render(&mut app);
        app.handle(mouse(MouseEventKind::Down(MouseButton::Left), app.yes_area.x + 3, yes));
        assert_eq!(app.outbox, [Command::SetShared { key: "protect:sensor:5".into(), shared: false }]);
    }

    fn with_affix(mut state: State) -> State {
        state.name_prefix = "HM ".into();
        state.name_suffix = " (UP)".into();
        state
    }

    /// The text drawn on the affix background, row by row.
    fn affix_cells(app: &mut App, width: u16, height: u16) -> Vec<String> {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|frame| draw(frame, app)).unwrap();
        let buffer = terminal.backend().buffer().clone();
        (0..height)
            .map(|y| {
                (0..width)
                    .filter(|x| buffer[(*x, y)].bg == Color::DarkGray)
                    .map(|x| buffer[(x, y)].symbol().to_owned())
                    .collect()
            })
            .collect()
    }

    #[test]
    fn prefix_and_suffix_are_set_apart_from_the_name() {
        let mut app = app_with(with_affix(editable(sample_state(true))));
        let screen = render(&mut app);
        // The whole HomeKit name reads naturally at 80 columns...
        assert_shows(&screen, &["● HM Front Door (UP)", "● HM Garage (UP)", "Name prefix  HM   P to change", "Name suffix   (UP)  S to change"]);
        // ...and only the prefix and suffix sit on the background.
        let marked = affix_cells(&mut app, 80, 24);
        let row = screen.lines().position(|l| l.contains("● HM Garage (UP)")).unwrap();
        assert!(marked[row].starts_with("HM  (UP)"), "{:?}", marked[row]);
        let wide = render_at(&mut app, 140, 40);
        let table = wide.lines().position(|l| l.contains("HM Garage (UP)") && l.contains("camera   motion")).unwrap();
        let marked_wide = affix_cells(&mut app, 140, 40);
        assert!(marked_wide[table].ends_with("HM  (UP)"), "the overview table marks them too: {:?}", marked_wide[table]);
        // A device that is not shared has no HomeKit name to decorate.
        assert!(!screen.contains("HM Side Gate"));

        // The device pane spells out what HomeKit is given.
        app.select(2);
        let screen = render(&mut app);
        assert_shows(&screen, &["Garage · camera", "In HomeKit   HM Garage (UP)", "r  Name: Garage  (Protect: Garage Cam)"]);

        // With neither set, nothing is marked and no line is spent on it.
        let mut plain = app_with(editable(sample_state(true)));
        plain.select(2);
        assert!(!render(&mut plain).contains("In HomeKit"));
        assert!(affix_cells(&mut plain, 80, 24).iter().all(String::is_empty));
        plain.select(0);
        assert_shows(&render(&mut plain), &["Name prefix  none  P to change"]);
    }

    #[test]
    fn long_affixes_squeeze_the_name_not_themselves() {
        let mut state = with_affix(editable(sample_state(true)));
        state.name_prefix = "Harbormaster bridge ".into();
        let mut app = app_with(state);
        let screen = render(&mut app);
        assert!(screen.contains("● Harborma…Fro… (UP) rec now"), "{screen}");
        assert!(screen.lines().all(|l| l.chars().count() == 80));
    }

    #[test]
    fn the_log_filter_and_selection_go_by_the_plain_name() {
        let mut app = app_with(with_affix(editable(sample_state(true))));
        app.handle(key(KeyCode::Down));
        assert_eq!(app.selected_device().unwrap().name, "Front Door");
        let screen = render(&mut app);
        // The log knows devices by their plain names, so that is what is matched.
        assert_shows(&screen, &["Log: Front Door (f for all)", "Front Door: motion event 36"]);
        assert!(!screen.contains("nothing logged that matches") && !screen.contains("Garage: ffmpeg"), "{screen}");
        // Renaming starts from the plain name: the affix is never typed.
        app.handle(key(KeyCode::Char('r')));
        assert_eq!(app.modal, Modal::Edit { target: Target::Device("protect:doorbell:2".into()), input: "Front Door".into() });
        assert_shows(&render(&mut app), &["The prefix and suffix are added for you."]);
    }

    #[test]
    fn prefix_and_suffix_are_edited_from_the_keyboard_or_by_clicking() {
        let mut app = app_with(with_affix(editable(sample_state(true))));
        render(&mut app);
        app.handle(key(KeyCode::Char('P')));
        let screen = render(&mut app);
        assert_shows(&screen, &["Prefix for every HomeKit name", " HM ▏", "Spaces count"]);
        // The typed text sits on the background, so its trailing space shows.
        assert!(affix_cells(&mut app, 80, 24).iter().any(|row| row == "HM "));
        for _ in 0..3 {
            app.handle(key(KeyCode::Backspace));
        }
        for c in "UP: ".chars() {
            app.handle(key(KeyCode::Char(c)));
        }
        app.handle(key(KeyCode::Enter));
        assert_eq!(app.outbox, [Command::SetNamePrefix { text: Some("UP: ".into()) }], "sent exactly as typed");

        // Emptying the suffix asks for none; the limit is the config's.
        app.outbox.clear();
        app.handle(key(KeyCode::Char('S')));
        for _ in 0..9 {
            app.handle(key(KeyCode::Backspace));
        }
        app.handle(key(KeyCode::Enter));
        assert_eq!(app.outbox, [Command::SetNameSuffix { text: Some(String::new()) }]);
        app.outbox.clear();
        app.handle(key(KeyCode::Char('S')));
        for _ in 0..40 {
            app.handle(key(KeyCode::Char('x')));
        }
        assert!(matches!(&app.modal, Modal::Edit { input, .. } if input.chars().count() == MAX_AFFIX));
        app.handle(key(KeyCode::Esc));
        assert!(app.outbox.is_empty());

        // Clicking the setting's line on the overview opens the same box.
        let screen = render(&mut app);
        let row = screen.lines().position(|l| l.contains("Name suffix")).unwrap() as u16;
        app.handle(mouse(MouseEventKind::Down(MouseButton::Left), app.detail_area.x + 6, row));
        assert_eq!(app.modal, Modal::Edit { target: Target::Suffix, input: " (UP)".into() });
        app.handle(key(KeyCode::Esc));
        // The keys work from a device's pane too.
        app.select(3);
        app.handle(key(KeyCode::Char('P')));
        assert!(matches!(app.modal, Modal::Edit { target: Target::Prefix, .. }));
    }

    #[test]
    fn long_log_lines_wrap_until_w_turns_it_off() {
        let mut app = app_with(sample_state(true));
        let long = "Front Door: recording for HomeKit at 1600x1200, 2000 kbps, no sound, reaching back 4 s (16 buffered)";
        app.receive(Incoming::Message(Box::new(Message::Log(LogLine { time: NOW, level: "INFO".into(), message: long.into() }))));
        let screen = render(&mut app);
        // On by default: broken at spaces, the rest hanging under the message.
        assert_shows(
            &screen,
            &[
                "│14:13:20 INFO  Front Door: recording for      │",
                "│               HomeKit at 1600x1200, 2000     │",
                "│               s (16 buffered)                │",
                "─ W no wrap ┐",
            ],
        );
        // Older lines still fill the rows above it.
        assert!(screen.contains("event 39"), "{screen}");

        app.handle(key(KeyCode::Char('W')));
        let screen = render(&mut app);
        assert!(!app.log_wrap && !screen.contains("back 4 s") && screen.contains(" W wrap "), "{screen}");
        assert!(screen.contains("14:13:20 INFO  Front Door: recording for HomeK│"), "{screen}");

        // A click on the switch in the border turns it back on.
        let (x, y) = (app.log_area.right() - 4, app.log_area.y);
        app.handle(mouse(MouseEventKind::Down(MouseButton::Left), x, y));
        assert!(app.log_wrap);

        // Scrolled all the way back, the oldest lines fill the pane.
        app.handle(key(KeyCode::Char('f')));
        app.focus = Focus::Log;
        render(&mut app);
        app.handle(key(KeyCode::Home));
        let screen = render(&mut app);
        assert!(screen.contains("event 0 ") && !screen.contains("back 4 s"), "{screen}");
    }

    #[test]
    fn wrapping_breaks_at_spaces_and_splits_only_overlong_words() {
        assert_eq!(wrap("one two three", 7), ["one two", "three"]);
        assert_eq!(wrap("abcdefghij kl", 4), ["abcd", "efgh", "ij", "kl"]);
        assert_eq!(wrap("", 5), [""]);
        assert_eq!(wrap("a b", 0), ["a", "b"]);
    }

    #[test]
    fn tiny_terminals_do_not_panic() {
        let mut app = app_with(sample_state(true));
        app.select(1);
        for (width, height) in [(1, 1), (10, 3), (27, 9), (40, 12)] {
            render_at(&mut app, width, height);
        }
    }

    #[test]
    fn formats_durations_and_fits_text() {
        assert_eq!(duration(59), "59s");
        assert_eq!(duration(125), "2m 05s");
        assert_eq!(duration(90000), "1d 01h");
        assert_eq!(fit("Front Door", 10), "Front Door");
        assert_eq!(fit("Front Door", 6), "Front…");
        assert_eq!(fit("Front Door", 0), "");
    }
}
