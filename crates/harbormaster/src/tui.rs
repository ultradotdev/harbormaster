//! The terminal interface. It attaches to a running daemon over the control
//! socket and only displays what the daemon reports, so closing it never
//! affects the bridge.

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
use ratatui::widgets::{Block, Clear, List, ListItem, ListState, Paragraph};
use ratatui::Frame;

use crate::control::{self, LogLine, Message, State};

/// Log lines kept in the TUI for scrolling back.
const MAX_LOG_LINES: usize = 2000;

enum Incoming {
    Attached,
    Detached,
    Message(Box<Message>),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Focus {
    Accessories,
    Log,
}

struct App {
    attached: bool,
    state: Option<State>,
    logs: VecDeque<LogLine>,
    selected: usize,
    /// Lines scrolled up from the newest log line; zero follows the tail.
    log_scroll: usize,
    focus: Focus,
    show_setup: bool,
    /// Where the panes were last drawn, for mouse hit testing.
    list_area: Rect,
    log_area: Rect,
}

impl App {
    fn new() -> Self {
        Self {
            attached: false,
            state: None,
            logs: VecDeque::new(),
            selected: 0,
            log_scroll: 0,
            focus: Focus::Accessories,
            show_setup: false,
            list_area: Rect::default(),
            log_area: Rect::default(),
        }
    }

    fn accessory_count(&self) -> usize {
        self.state.as_ref().map_or(0, |s| s.accessories.len())
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
                    self.selected = self.selected.min(state.accessories.len().saturating_sub(1));
                    self.state = Some(state);
                }
                Message::Log(line) => {
                    if self.logs.len() == MAX_LOG_LINES {
                        self.logs.pop_front();
                    }
                    self.logs.push_back(line);
                    // Keep the view anchored while the user is reading history.
                    if self.log_scroll > 0 {
                        self.log_scroll = (self.log_scroll + 1).min(self.logs.len());
                    }
                }
            },
        }
    }

    fn move_selection(&mut self, delta: isize) {
        let last = self.accessory_count().saturating_sub(1);
        self.selected = self.selected.saturating_add_signed(delta).min(last);
    }

    fn scroll_log(&mut self, delta: isize) {
        let visible = self.log_area.height.saturating_sub(2) as usize;
        let max = self.logs.len().saturating_sub(visible);
        self.log_scroll = self.log_scroll.saturating_add_signed(delta).min(max);
    }

    /// Returns `false` when the user asked to quit.
    fn handle(&mut self, event: Event) -> bool {
        match event {
            Event::Key(key) if key.kind == KeyEventKind::Press => {
                if self.show_setup {
                    self.show_setup = false;
                    return true;
                }
                let page = self.log_area.height.saturating_sub(2).max(1) as isize;
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => return false,
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return false,
                    KeyCode::Tab | KeyCode::BackTab => {
                        self.focus = match self.focus {
                            Focus::Accessories => Focus::Log,
                            Focus::Log => Focus::Accessories,
                        };
                    }
                    KeyCode::Char('p') => self.show_setup = true,
                    KeyCode::Up | KeyCode::Char('k') => match self.focus {
                        Focus::Accessories => self.move_selection(-1),
                        Focus::Log => self.scroll_log(1),
                    },
                    KeyCode::Down | KeyCode::Char('j') => match self.focus {
                        Focus::Accessories => self.move_selection(1),
                        Focus::Log => self.scroll_log(-1),
                    },
                    KeyCode::PageUp => self.scroll_log(page),
                    KeyCode::PageDown => self.scroll_log(-page),
                    KeyCode::End => self.log_scroll = 0,
                    KeyCode::Home => self.scroll_log(isize::MAX),
                    _ => {}
                }
            }
            Event::Mouse(mouse) => {
                let at = Position::new(mouse.column, mouse.row);
                let (in_list, in_log) = (self.list_area.contains(at), self.log_area.contains(at));
                match mouse.kind {
                    MouseEventKind::Down(MouseButton::Left) if self.show_setup => self.show_setup = false,
                    MouseEventKind::Down(MouseButton::Left) if in_list => {
                        self.focus = Focus::Accessories;
                        // Rows start one line below the pane's top border.
                        let row = mouse.row.saturating_sub(self.list_area.y + 1) as usize;
                        if mouse.row > self.list_area.y && row < self.accessory_count() {
                            self.selected = row;
                        }
                    }
                    MouseEventKind::Down(MouseButton::Left) if in_log => self.focus = Focus::Log,
                    MouseEventKind::ScrollUp if in_log => self.scroll_log(3),
                    MouseEventKind::ScrollDown if in_log => self.scroll_log(-3),
                    MouseEventKind::ScrollUp if in_list => self.move_selection(-1),
                    MouseEventKind::ScrollDown if in_list => self.move_selection(1),
                    _ => {}
                }
            }
            _ => {}
        }
        true
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

fn clock(unix_secs: u64) -> String {
    let day = unix_secs % 86400;
    format!("{:02}:{:02}:{:02}Z", day / 3600, day % 3600 / 60, day % 60)
}

fn pane(title: &str, focused: bool) -> Block<'_> {
    let style = if focused { Style::new().fg(Color::Cyan) } else { Style::new().fg(Color::DarkGray) };
    Block::bordered().title(format!(" {title} ")).border_style(style)
}

fn draw(frame: &mut Frame, app: &mut App) {
    let [header, body, log, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(8),
        Constraint::Percentage(35),
        Constraint::Length(1),
    ])
    .areas(frame.area());
    let [list, right] =
        Layout::horizontal([Constraint::Percentage(40), Constraint::Percentage(60)]).areas(body);
    let [details, controllers] =
        Layout::vertical([Constraint::Percentage(55), Constraint::Percentage(45)]).areas(right);
    app.list_area = list;
    app.log_area = log;

    draw_header(frame, app, header);
    draw_accessories(frame, app, list);
    draw_details(frame, app, details);
    draw_controllers(frame, app, controllers);
    draw_log(frame, app, log);
    frame.render_widget(
        Paragraph::new(" ↑↓ select   Tab switch pane   PgUp/PgDn scroll log   p pairing code   q quit")
            .style(Style::new().fg(Color::DarkGray)),
        footer,
    );
    if app.show_setup {
        draw_setup(frame, app);
    }
}

fn draw_header(frame: &mut Frame, app: &App, area: Rect) {
    let bold = Style::new().add_modifier(Modifier::BOLD);
    let line = match (&app.state, app.attached) {
        (Some(s), true) => {
            let pairing = if s.paired {
                Span::styled(
                    format!("● paired ({} controllers)", s.controllers.len()),
                    Style::new().fg(Color::Green),
                )
            } else {
                Span::styled("○ not paired (press p)", Style::new().fg(Color::Yellow))
            };
            Line::from(vec![
                Span::styled(format!(" {} ", s.name), bold),
                Span::raw(format!("v{}   ", s.version)),
                pairing,
                Span::raw(format!(
                    "   {} connections   up {}   {}",
                    s.connections.len(),
                    duration(s.uptime_secs),
                    s.listen
                )),
            ])
        }
        _ => Line::from(vec![
            Span::styled(" Harbormaster ", bold),
            Span::styled(
                "✕ daemon not running (start it with: harbormaster daemon)",
                Style::new().fg(Color::Red),
            ),
        ]),
    };
    frame.render_widget(Paragraph::new(line), area);
}

fn draw_accessories(frame: &mut Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = app
        .state
        .iter()
        .flat_map(|s| &s.accessories)
        .map(|a| {
            let summary = a.readings.first().map_or(String::new(), |r| format!("  {}", r.value));
            ListItem::new(Line::from(vec![
                Span::raw(a.name.clone()),
                Span::styled(summary, Style::new().fg(Color::DarkGray)),
            ]))
        })
        .collect();
    let list = List::new(items)
        .block(pane("Accessories", app.focus == Focus::Accessories))
        .highlight_style(Style::new().add_modifier(Modifier::REVERSED));
    let mut state = ListState::default().with_selected(Some(app.selected));
    frame.render_stateful_widget(list, area, &mut state);
}

fn draw_details(frame: &mut Frame, app: &App, area: Rect) {
    let dim = Style::new().fg(Color::DarkGray);
    let mut lines = Vec::new();
    if let Some(a) = app.state.as_ref().and_then(|s| s.accessories.get(app.selected)) {
        let field = |label: &str, value: &str| {
            Line::from(vec![Span::styled(format!("{label:<14}"), dim), Span::raw(value.to_owned())])
        };
        lines.push(field("Name", &a.name));
        lines.push(field("Manufacturer", &a.manufacturer));
        lines.push(field("Model", &a.model));
        lines.push(field("Serial", &a.serial_number));
        lines.push(field("HomeKit id", &a.aid.to_string()));
        if !a.readings.is_empty() {
            lines.push(Line::raw(""));
        }
        lines.extend(a.readings.iter().map(|r| field(&r.label, &r.value)));
    }
    frame.render_widget(Paragraph::new(lines).block(pane("Details", false)), area);
}

fn draw_controllers(frame: &mut Frame, app: &App, area: Rect) {
    let dim = Style::new().fg(Color::DarkGray);
    let mut lines = Vec::new();
    if let Some(s) = &app.state {
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
                Span::raw(format!("{:<18}", c.peer)),
                Span::raw(format!("{who:<20}")),
                Span::styled(duration(c.connected_secs), dim),
            ]));
        }
        if lines.is_empty() {
            lines.push(Line::styled("no controllers connected", dim));
        }
    }
    frame.render_widget(Paragraph::new(lines).block(pane("Connections", false)), area);
}

fn draw_log(frame: &mut Frame, app: &App, area: Rect) {
    let visible = area.height.saturating_sub(2) as usize;
    let end = app.logs.len().saturating_sub(app.log_scroll);
    let start = end.saturating_sub(visible);
    let lines: Vec<Line> = app
        .logs
        .range(start..end)
        .map(|l| {
            let color = match l.level.as_str() {
                "ERROR" => Color::Red,
                "WARN" => Color::Yellow,
                _ => Color::Reset,
            };
            Line::from(vec![
                Span::styled(format!("{} ", clock(l.time)), Style::new().fg(Color::DarkGray)),
                Span::styled(format!("{:<5} ", l.level), Style::new().fg(color)),
                Span::raw(l.message.clone()),
            ])
        })
        .collect();
    let title = if app.log_scroll > 0 { "Log (scrolled, End to follow)" } else { "Log" };
    frame.render_widget(Paragraph::new(lines).block(pane(title, app.focus == Focus::Log)), area);
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
    lines.push(Line::styled("press any key to close", Style::new().fg(Color::DarkGray)).centered());

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
    use crate::control::{Accessory, Connection, Controller, Reading};
    use ratatui::backend::TestBackend;
    use ratatui::crossterm::event::{KeyEvent, MouseEvent};
    use ratatui::Terminal;

    fn sample_state(paired: bool) -> State {
        let accessory = |aid, name: &str, value: &str| Accessory {
            aid,
            name: name.into(),
            manufacturer: "Harbormaster".into(),
            model: "Demo".into(),
            serial_number: "demo-1".into(),
            readings: vec![Reading { label: "Temperature".into(), value: value.into() }],
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
            accessories: vec![accessory(1, "Bridge", "n/a"), accessory(2, "Porch", "21.5 °C")],
        }
    }

    fn app_with(state: State) -> App {
        let mut app = App::new();
        app.receive(Incoming::Attached);
        app.receive(Incoming::Message(Box::new(Message::State(state))));
        for i in 0..40 {
            let line = LogLine { time: 71717 + i, level: "INFO".into(), message: format!("event {i}") };
            app.receive(Incoming::Message(Box::new(Message::Log(line))));
        }
        app
    }

    fn render(app: &mut App) -> String {
        let mut terminal = Terminal::new(TestBackend::new(110, 34)).unwrap();
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

    fn key(code: KeyCode) -> Event {
        Event::Key(KeyEvent::new(code, KeyModifiers::NONE))
    }

    #[test]
    fn shows_status_accessories_connections_and_log_tail() {
        let mut app = app_with(sample_state(true));
        let screen = render(&mut app);
        for expected in [
            "Harbormaster 6C2C",
            "paired (1 controllers)",
            "up 1h 02m",
            "Porch",
            "192.0.2.236",
            "AAAA1111 (admin)",
            "event 39",
        ] {
            assert!(screen.contains(expected), "missing {expected:?} in:\n{screen}");
        }
        assert!(!screen.contains("event 0 "), "log should show the tail");
    }

    #[test]
    fn detached_tui_says_daemon_is_not_running() {
        let mut app = App::new();
        assert!(render(&mut app).contains("daemon not running"));
    }

    #[test]
    fn keyboard_and_mouse_navigation() {
        let mut app = app_with(sample_state(true));
        render(&mut app);
        assert!(app.handle(key(KeyCode::Down)));
        assert_eq!(app.selected, 1);
        assert!(app.handle(key(KeyCode::Down)));
        assert_eq!(app.selected, 1, "selection stops at the last accessory");
        assert!(render(&mut app).contains("demo-1"));

        // Click the first row of the accessory list.
        let (x, y) = (app.list_area.x + 2, app.list_area.y + 1);
        let click = MouseEvent { kind: MouseEventKind::Down(MouseButton::Left), column: x, row: y, modifiers: KeyModifiers::NONE };
        app.handle(Event::Mouse(click));
        assert_eq!(app.selected, 0);

        // Scroll the log with the wheel, then jump back to the tail.
        let wheel = MouseEvent { kind: MouseEventKind::ScrollUp, column: app.log_area.x + 2, row: app.log_area.y + 2, modifiers: KeyModifiers::NONE };
        app.handle(Event::Mouse(wheel));
        assert_eq!(app.log_scroll, 3);
        assert!(!render(&mut app).contains("event 39"));
        app.handle(key(KeyCode::End));
        assert_eq!(app.log_scroll, 0);

        assert!(!app.handle(key(KeyCode::Char('q'))));
    }

    #[test]
    fn pairing_popup_shows_code_only_while_unpaired() {
        let mut app = app_with(sample_state(false));
        app.handle(key(KeyCode::Char('p')));
        let screen = render(&mut app);
        assert!(screen.contains("Setup code: 420-21-195"), "{screen}");
        assert!(screen.contains('█'), "QR code should be drawn");
        app.handle(key(KeyCode::Char('x')));
        assert!(!app.show_setup);

        let mut app = app_with(sample_state(true));
        app.handle(key(KeyCode::Char('p')));
        assert!(render(&mut app).contains("Already paired"));
    }

    #[test]
    fn formats_durations_and_clock() {
        assert_eq!(duration(59), "59s");
        assert_eq!(duration(125), "2m 05s");
        assert_eq!(duration(90000), "1d 01h");
        assert_eq!(clock(71717), "19:55:17Z");
    }
}
