//! The terminal interface: a status dashboard. It attaches to a running
//! daemon over the control socket and only displays what the daemon
//! reports, so closing it never affects the bridge.
//!
//! The screen has a quick status box and the list of devices on the left,
//! the selected item's details on the right, and the log underneath, which
//! narrows itself to the selected device.

use std::collections::VecDeque;
use std::io::{BufRead, BufReader};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
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
use ratatui::widgets::{Block, Clear, Paragraph};
use ratatui::Frame;

use crate::clock;
use crate::control::{self, Device, LogLine, Message, State};

/// Log lines kept in the TUI for scrolling back.
const MAX_LOG_LINES: usize = 2000;

const DIM: Style = Style::new().fg(Color::DarkGray);
const GOOD: Style = Style::new().fg(Color::Green);
const WARN: Style = Style::new().fg(Color::Yellow);
const BAD: Style = Style::new().fg(Color::Red);

enum Incoming {
    Attached,
    Detached,
    Message(Box<Message>),
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
    show_setup: bool,
    warnings_only: bool,
    /// Whether the log narrows to the selected device.
    device_log: bool,
    /// Seconds local time is ahead of UTC at a given moment.
    zone: fn(u64) -> i64,
    /// Where the panes were last drawn, for mouse hit testing.
    list_area: Rect,
    detail_area: Rect,
    log_area: Rect,
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
            show_setup: false,
            warnings_only: false,
            device_log: true,
            zone: clock::local_offset,
            list_area: Rect::default(),
            detail_area: Rect::default(),
            log_area: Rect::default(),
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
        let max = self.visible_logs().len().saturating_sub(visible);
        self.log_scroll = self.log_scroll.saturating_add_signed(delta).min(max);
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

    /// Returns `false` when the user asked to quit.
    fn handle(&mut self, event: Event) -> bool {
        match event {
            Event::Key(key) if key.kind == KeyEventKind::Press => {
                if self.show_setup {
                    self.show_setup = false;
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
                    KeyCode::Char('p') => self.show_setup = true,
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
            Event::Mouse(mouse) => {
                let at = Position::new(mouse.column, mouse.row);
                let over = if self.list_area.contains(at) {
                    Some(Focus::Devices)
                } else if self.detail_area.contains(at) {
                    Some(Focus::Detail)
                } else if self.log_area.contains(at) {
                    Some(Focus::Log)
                } else {
                    None
                };
                match (mouse.kind, over) {
                    (MouseEventKind::Down(MouseButton::Left), _) if self.show_setup => self.show_setup = false,
                    (MouseEventKind::Down(MouseButton::Left), Some(pane)) => {
                        self.focus = pane;
                        // Rows start one line below the pane's top border.
                        let inside = mouse.row > self.list_area.y && mouse.row + 1 < self.list_area.bottom();
                        if pane == Focus::Devices && inside {
                            let row = self.list_offset + (mouse.row - self.list_area.y - 1) as usize;
                            if row <= self.devices.len() {
                                self.select(row);
                            }
                        }
                    }
                    // The wheel moves whatever is under the pointer.
                    (MouseEventKind::ScrollUp, Some(Focus::Devices)) => self.move_selection(-1),
                    (MouseEventKind::ScrollDown, Some(Focus::Devices)) => self.move_selection(1),
                    (MouseEventKind::ScrollUp, Some(Focus::Detail)) => self.scroll_detail(-3),
                    (MouseEventKind::ScrollDown, Some(Focus::Detail)) => self.scroll_detail(3),
                    (MouseEventKind::ScrollUp, Some(Focus::Log)) => self.scroll_log(3),
                    (MouseEventKind::ScrollDown, Some(Focus::Log)) => self.scroll_log(-3),
                    _ => {}
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

fn pane(title: &str, focused: bool) -> Block<'_> {
    let style = if focused { Style::new().fg(Color::Cyan) } else { DIM };
    Block::bordered().title(format!(" {title} ")).border_style(style)
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
                break;
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

fn draw(frame: &mut Frame, app: &mut App) {
    let screen = frame.area();
    let log_height = (screen.height * 3 / 10).max(5);
    let [top, log, footer] =
        Layout::vertical([Constraint::Min(8), Constraint::Length(log_height), Constraint::Length(1)]).areas(screen);
    let side_width = (screen.width * 3 / 10).clamp(32, 44);
    let [side, detail] = Layout::horizontal([Constraint::Length(side_width), Constraint::Min(20)]).areas(top);
    let [status, list] = Layout::vertical([Constraint::Length(6), Constraint::Min(3)]).areas(side);
    app.list_area = list;
    app.detail_area = detail;
    app.log_area = log;

    draw_status(frame, app, status);
    draw_devices(frame, app, list);
    draw_detail(frame, app, detail);
    draw_log(frame, app, log);
    let hints = " ↑↓ select  Tab pane  Enter open  w warnings  f device log  p pairing  q quit";
    frame.render_widget(Paragraph::new(hints).style(DIM), footer);
    if app.show_setup {
        draw_setup(frame, app);
    }
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
        row(Span::styled("○", WARN), "Bridge", vec![Span::styled("not paired (press p)", WARN)])
    };
    let console = match &s.console {
        Some(c) if c.connected => {
            let age = c.last_update.map_or(String::new(), |at| format!(" · {}", duration(s.time.saturating_sub(at))));
            row(dot(Some(true)), "Console", vec![Span::raw(format!("{}{age}", c.host))])
        }
        Some(c) => row(dot(Some(false)), "Console", vec![Span::styled(format!("{} down", c.host), BAD)]),
        None => row(dot(None), "Console", vec![Span::styled("not configured", DIM)]),
    };
    let known = app.devices.iter().filter(|d| d.online.is_some()).count();
    let offline = app.devices.iter().filter(|d| d.online == Some(false)).count();
    let devices = match (app.devices.len(), offline) {
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

/// The sidebar: the overview, then every device with its state at a glance.
fn draw_devices(frame: &mut Frame, app: &mut App, area: Rect) {
    let (width, height) = (area.width.saturating_sub(2) as usize, area.height.saturating_sub(2) as usize);
    // Keep the selected row on screen.
    if app.selected < app.list_offset {
        app.list_offset = app.selected;
    } else if height > 0 && app.selected >= app.list_offset + height {
        app.list_offset = app.selected + 1 - height;
    }
    let rows = app.devices.len() + 1;
    app.list_offset = app.list_offset.min(rows.saturating_sub(height));

    let mut lines = Vec::new();
    for row in app.list_offset..rows.min(app.list_offset + height) {
        let mut spans = match row.checked_sub(1).and_then(|i| app.devices.get(i)) {
            None => vec![Span::raw("  Overview")],
            Some(d) => {
                // The name keeps at least half the row; the rest is state.
                let name = fit(&d.name, width.saturating_sub(3));
                let room = width.saturating_sub(4 + name.chars().count());
                let mut spans = vec![Span::raw(" "), dot(d.online), Span::raw(format!(" {name}"))];
                let state = app.summary_line(d, room);
                let used: usize = state.iter().map(|s| s.content.chars().count()).sum();
                spans.push(Span::raw(" ".repeat(room.saturating_sub(used) + 1)));
                spans.extend(state);
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

fn overview_lines(app: &App, s: &State, width: usize) -> Vec<Line<'static>> {
    let mut lines = vec![
        field("Bridge", format!("{}  v{}", s.name, s.version)),
        field("Listening", format!("{}  configuration {}", s.listen, s.config_number)),
        field("Uptime", duration(s.uptime_secs)),
        field(
            "Pairing",
            if s.paired {
                Span::raw(format!("paired with {} controller(s)", s.controllers.len()))
            } else {
                Span::styled("not paired (press p to pair)", WARN)
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
        Line::raw(""),
        heading("Controllers"),
    ];
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
    let name_width = app.devices.iter().map(|d| d.name.chars().count()).max().unwrap_or(0).clamp(4, 22);
    for d in &app.devices {
        let mut spans = vec![
            Span::raw("  "),
            dot(d.online),
            Span::raw(format!(" {:<name_width$} ", fit(&d.name, name_width))),
            Span::styled(format!("{:<9}", d.kind), DIM),
        ];
        spans.extend(app.summary_line(d, width.saturating_sub(name_width + 14)));
        lines.push(Line::from(spans));
    }
    if app.devices.is_empty() {
        lines.push(Line::styled("  none published", DIM));
    }
    lines
}

fn device_lines(app: &App, d: &Device) -> Vec<Line<'static>> {
    let status = match d.online {
        Some(true) => Span::styled("online", GOOD),
        Some(false) => Span::styled("offline", BAD),
        None => Span::styled("not reported", DIM),
    };
    let mut lines = vec![
        field("Status", status),
        field("Model", d.model.clone()),
        field("Serial", format!("{}  HomeKit id {}", d.serial_number, d.aid)),
        Line::raw(""),
    ];
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
    let (title, lines) = match (&app.state, app.selected_device()) {
        (Some(_), Some(d)) => (format!("{} · {}", d.name, d.kind), device_lines(app, d)),
        (Some(s), None) => ("Overview".to_owned(), overview_lines(app, s, width)),
        (None, _) => ("Overview".to_owned(), vec![Line::styled("waiting for the daemon", DIM)]),
    };
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
    let visible = area.height.saturating_sub(2) as usize;
    let shown = app.visible_logs();
    let end = shown.len().saturating_sub(app.log_scroll);
    let start = end.saturating_sub(visible);
    let mut lines: Vec<Line> = shown[start..end]
        .iter()
        .map(|l| {
            let color = match l.level.as_str() {
                "ERROR" => Color::Red,
                "WARN" => Color::Yellow,
                _ => Color::Reset,
            };
            Line::from(vec![
                Span::styled(format!("{} ", clock::time_of_day(l.time, (app.zone)(l.time))), DIM),
                Span::styled(format!("{:<5} ", l.level), Style::new().fg(color)),
                Span::raw(l.message.clone()),
            ])
        })
        .collect();
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
    frame.render_widget(Paragraph::new(lines).block(pane(&title, app.focus == Focus::Log)), area);
}

fn draw_setup(frame: &mut Frame, app: &App) {
    let Some(state) = &app.state else { return };
    let mut lines: Vec<Line> = Vec::new();
    match (&state.setup_code, &state.setup_uri) {
        (Some(code), uri) => {
            if let Some(qr) = uri.as_deref().and_then(crate::qr::render) {
                // Leave room for the border, the code line and the hint.
                if qr.lines().count() as u16 + 6 <= frame.area().height {
                    lines.extend(qr.lines().map(|l| Line::raw(l.to_owned())));
                    lines.push(Line::raw(""));
                }
            }
            lines.push(Line::raw(format!("Setup code: {code}")).centered());
        }
        _ => lines.push(Line::raw("Already paired. Remove the bridge in the Home app to pair again.")),
    }
    lines.push(Line::raw(""));
    lines.push(Line::styled("press any key to close", DIM).centered());

    let width = lines.iter().map(|l| l.width() as u16).max().unwrap_or(0) + 4;
    let height = lines.len() as u16 + 2;
    let screen = frame.area();
    let area = Rect {
        x: screen.x + screen.width.saturating_sub(width) / 2,
        y: screen.y + screen.height.saturating_sub(height) / 2,
        width: width.min(screen.width),
        height: height.min(screen.height),
    };
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(lines).block(Block::bordered().title(" Pair with the Home app ")),
        area,
    );
}

/// Connects to the daemon and forwards its messages, reconnecting forever.
fn read_daemon(socket: PathBuf, tx: mpsc::Sender<Incoming>) {
    loop {
        if let Ok(stream) = UnixStream::connect(&socket) {
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
    std::thread::spawn(move || read_daemon(socket, tx));

    let mut terminal = ratatui::init();
    let _ = execute!(std::io::stdout(), EnableMouseCapture);
    let mut app = App::new();
    let result = (|| -> Result<()> {
        loop {
            while let Ok(incoming) = rx.try_recv() {
                app.receive(incoming);
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
            name: "Harbormaster 6C2C".into(),
            version: "0.1.0".into(),
            listen: "[::]:51826".into(),
            uptime_secs: 3725,
            paired,
            setup_code: (!paired).then(|| "420-21-195".into()),
            setup_uri: (!paired).then(|| "X-HM://0081YCYEP7OSX".into()),
            controllers: vec![Controller { id: "AAAA1111-2222".into(), admin: true }],
            connections: vec![Connection {
                peer: "192.0.2.236".into(),
                controller: Some("AAAA1111-2222".into()),
                connected_secs: 75,
            }],
            accessories: Vec::new(),
            time: NOW,
            config_number: 12,
            console: Some(Console { host: "192.0.2.1".into(), connected: true, last_update: Some(NOW - 2) }),
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
                "● Front Door doorbell recording 12s",
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
        // The third row of the list is the second device.
        let (x, y) = (app.list_area.x + 3, app.list_area.y + 3);
        app.handle(mouse(MouseEventKind::Down(MouseButton::Left), x, y));
        assert_eq!((app.selected, app.focus), (2, Focus::Devices));
        assert!(render(&mut app).contains("Garage · camera"));
        // Clicking the border or below the last device changes nothing.
        app.handle(mouse(MouseEventKind::Down(MouseButton::Left), x, app.list_area.y));
        app.handle(mouse(MouseEventKind::Down(MouseButton::Left), x, app.list_area.y + 7));
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
    fn console_trouble_and_absence_are_plain() {
        let mut state = sample_state(true);
        state.console = Some(Console { host: "192.0.2.1".into(), connected: false, last_update: Some(NOW - 300) });
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
    fn pairing_popup_shows_code_only_while_unpaired() {
        let mut app = app_with(sample_state(false));
        assert!(render(&mut app).contains("not paired (press p)"));
        app.handle(key(KeyCode::Char('p')));
        let screen = render_at(&mut app, 110, 34);
        assert!(screen.contains("Setup code: 420-21-195"), "{screen}");
        assert!(screen.contains('█'), "QR code should be drawn");
        // Too short for the code's picture: the digits alone still fit.
        assert!(render(&mut app).contains("Setup code: 420-21-195"));
        app.handle(key(KeyCode::Char('x')));
        assert!(!app.show_setup);

        let mut app = app_with(sample_state(true));
        app.handle(key(KeyCode::Char('p')));
        assert!(render(&mut app).contains("Already paired"));
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
