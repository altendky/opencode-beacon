use std::collections::HashSet;
use std::env;
use std::error::Error;
use std::fmt::Write as _;
use std::io::{self, IsTerminal};
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};
use crossterm::cursor::{Hide, Show};
use crossterm::event::{DisableMouseCapture, EnableMouseCapture, EventStream};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use futures_util::StreamExt;
use opencode_beacon::client::{BasicAuth, ClientConfig};
use opencode_beacon::discovery::{
    DiscoveryConfig, DiscoveryReport, LinuxProcfsDiscovery, ManagedDiscoveryConfig,
    ManagedServiceDiscovery,
};
use opencode_beacon::model::BeaconEvent;
use opencode_beacon::state::ServerState;
use opencode_beacon::{Monitor, MonitorConfig};
use secrecy::SecretString;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

mod attachment;
mod dashboard;
mod focus;
mod memory;

use attachment::AttachmentSampler;
use dashboard::{DashboardAction, DashboardModel};
use focus::{FocusResult, focus_client};
use memory::CgroupMemorySampler;

const MEMORY_SAMPLE_INTERVAL: Duration = Duration::from_secs(10);

#[derive(Debug, Parser)]
#[command(version, about = "Monitor local OpenCode server activity")]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,
    /// Cadence of cheap procfs listener-table gate checks.
    #[arg(long, global = true, default_value = "1s", value_parser = parse_duration)]
    discover_interval: Duration,
    /// Cadence of full authoritative process and health verification.
    #[arg(long, global = true, default_value = "5m", value_parser = parse_duration)]
    full_verification_interval: Duration,
    #[arg(long, global = true, default_value = "30s", value_parser = parse_duration)]
    resync_interval: Duration,
    #[arg(long, global = true, default_value = "500ms", value_parser = parse_duration)]
    connect_timeout: Duration,
    #[arg(long, global = true, default_value = "3s", value_parser = parse_duration)]
    request_timeout: Duration,
    #[arg(long, global = true, default_value = "3s", value_parser = parse_duration)]
    event_header_timeout: Duration,
    #[arg(long, global = true, default_value_t = 1024)]
    event_capacity: usize,
    #[arg(long, global = true, env = "OPENCODE_BEACON_USERNAME")]
    username: Option<String>,
    #[arg(long, global = true, default_value = "OPENCODE_BEACON_PASSWORD")]
    password_env: String,
    #[arg(long, global = true)]
    once: bool,
    /// Emit diagnostics; with watch, diagnostics go to stderr only.
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Subcommand)]
enum Command {
    /// Show only user-facing attention events in a plain-text table.
    Watch(WatchArgs),
    /// Show a persistent interactive working-set dashboard.
    Dashboard,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, clap::Args)]
struct WatchArgs {
    /// Print the table header once at startup.
    #[arg(long)]
    header: bool,
}

impl Args {
    fn validate(self) -> Result<Self, clap::Error> {
        if self.command.is_some() && self.once {
            return Err(clap::Error::raw(
                clap::error::ErrorKind::ArgumentConflict,
                "--once cannot be used with continuous subcommands",
            ));
        }
        Ok(self)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse()
        .validate()
        .unwrap_or_else(|error| error.exit());
    let auth = load_auth(&args)?;
    let client = ClientConfig {
        connect_timeout: args.connect_timeout,
        request_timeout: args.request_timeout,
        event_header_timeout: args.event_header_timeout,
        auth,
    };
    let monitor = Monitor::new(monitor_config(&args, client.clone()))?;
    if args.once {
        return run_once(&args, &client).await;
    }
    if let Some(Command::Watch(watch)) = args.command {
        return run_watch(&args, monitor, watch).await;
    }
    if matches!(args.command, Some(Command::Dashboard)) {
        return run_dashboard(monitor).await;
    }
    run_raw(&args, monitor).await
}

struct TerminalGuard {
    active: bool,
}

trait TerminalCleanup {
    fn leave_screen(&mut self) -> io::Result<()>;
    fn leave_raw_mode(&mut self) -> io::Result<()>;
}

struct CrosstermCleanup;

impl TerminalCleanup for CrosstermCleanup {
    fn leave_screen(&mut self) -> io::Result<()> {
        execute!(
            io::stdout(),
            DisableMouseCapture,
            Show,
            LeaveAlternateScreen
        )
    }

    fn leave_raw_mode(&mut self) -> io::Result<()> {
        disable_raw_mode()
    }
}

fn restore_terminal(cleanup: &mut impl TerminalCleanup) -> io::Result<()> {
    let terminal_result = cleanup.leave_screen();
    let raw_result = cleanup.leave_raw_mode();
    terminal_result.and(raw_result)
}

impl TerminalGuard {
    fn enter() -> io::Result<Self> {
        enable_raw_mode()?;
        let mut guard = Self { active: true };
        let mut stdout = io::stdout();
        if let Err(error) = execute!(stdout, EnterAlternateScreen, Hide, EnableMouseCapture) {
            let _ = guard.restore();
            return Err(error);
        }
        Ok(guard)
    }

    fn restore(&mut self) -> io::Result<()> {
        if !self.active {
            return Ok(());
        }
        self.active = false;
        restore_terminal(&mut CrosstermCleanup)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

fn validate_dashboard_terminal(
    stdin_tty: bool,
    stdout_tty: bool,
    term: Option<&str>,
) -> Result<(), String> {
    if !stdin_tty || !stdout_tty {
        return Err(
            "dashboard requires stdin and stdout terminals; use `opencode-beacon watch` for pipes"
                .to_owned(),
        );
    }
    if term.is_none_or(|term| term.is_empty() || term.eq_ignore_ascii_case("dumb")) {
        return Err(
            "dashboard requires a non-dumb TERM; use `opencode-beacon watch` instead".to_owned(),
        );
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn run_dashboard(monitor: Monitor) -> Result<(), Box<dyn Error>> {
    validate_dashboard_terminal(
        io::stdin().is_terminal(),
        io::stdout().is_terminal(),
        env::var("TERM").ok().as_deref(),
    )?;
    let mut guard = TerminalGuard::enter()?;
    let backend = ratatui::backend::CrosstermBackend::new(io::stdout());
    let mut terminal = ratatui::Terminal::new(backend)?;
    let mut events = EventStream::new();
    let mut model = DashboardModel::default();
    let mut attachment_sampler = AttachmentSampler::default();
    let mut memory_sampler = CgroupMemorySampler::default();
    let mut next_memory_sample = Instant::now();
    let mut runtime = monitor.spawn();
    let control = runtime.control.clone();
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut resync = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1())?;
    let mut result = Ok(());

    terminal.draw(|frame| model.render_at(frame, Instant::now()))?;
    loop {
        let redraw_deadline = model.next_redraw(Instant::now());
        let redraw_timer = async {
            match redraw_deadline {
                Some(deadline) => tokio::time::sleep_until(deadline.into()).await,
                None => std::future::pending().await,
            }
        };
        let memory_timer = tokio::time::sleep_until(next_memory_sample.into());
        tokio::select! {
            signal = tokio::signal::ctrl_c() => {
                if let Err(error) = signal {
                    result = Err(error);
                }
                control.shutdown();
                break;
            }
            _ = terminate.recv() => {
                control.shutdown();
                break;
            }
            _ = resync.recv() => control.request_resync(),
            terminal_event = events.next() => {
                let Some(terminal_event) = terminal_event else {
                    control.shutdown();
                    break;
                };
                match terminal_event {
                    Ok(event) => {
                        let viewport = terminal.size().map_or(1, |size| usize::from(size.height.saturating_sub(5)));
                        match model.handle_terminal_event(&event, viewport) {
                            DashboardAction::Quit => {
                                control.shutdown();
                                break;
                            }
                            DashboardAction::Redraw => {
                                if let Err(error) = terminal.draw(|frame| model.render_at(frame, Instant::now())) {
                                    result = Err(error);
                                    control.shutdown();
                                    break;
                                }
                            }
                            DashboardAction::Focus(request) => {
                                let message = focus_result_message(
                                    &request.name,
                                    focus_client(&request.target).await,
                                );
                                model.report_focus_result(&message);
                                if let Err(error) = terminal.draw(|frame| model.render_at(frame, Instant::now())) {
                                    result = Err(error);
                                    control.shutdown();
                                    break;
                                }
                            }
                            DashboardAction::Continue => {}
                        }
                    }
                    Err(error) => {
                        result = Err(error);
                        control.shutdown();
                        break;
                    }
                }
            }
            event = runtime.events.recv() => {
                let Some(event) = event else { break };
                attachment_sampler.observe(&event);
                memory_sampler.observe(&event);
                model.apply_at(event, Instant::now());
                if let Err(error) = terminal.draw(|frame| model.render_at(frame, Instant::now())) {
                    result = Err(error);
                    control.shutdown();
                    break;
                }
            }
            () = redraw_timer => {
                if let Err(error) = terminal.draw(|frame| model.render_at(frame, Instant::now())) {
                    result = Err(error);
                    control.shutdown();
                    break;
                }
            }
            () = memory_timer => {
                let now = Instant::now();
                model.apply_attachments(attachment_sampler.sample(), now);
                model.apply_memory(memory_sampler.sample(now));
                next_memory_sample = now + MEMORY_SAMPLE_INTERVAL;
                if let Err(error) = terminal.draw(|frame| model.render_at(frame, Instant::now())) {
                    result = Err(error);
                    control.shutdown();
                    break;
                }
            }
        }
    }

    runtime.wait().await?;
    guard.restore()?;
    result.map_err(Into::into)
}

fn focus_result_message(name: &str, result: FocusResult) -> String {
    match result {
        FocusResult::Requested => format!("Requested focus for {name}"),
        FocusResult::TabSelected => format!(
            "Selected tab for {name}; compositor activation unavailable for multi-window Konsole"
        ),
        FocusResult::KittySelected => {
            format!("Selected Kitty pane for {name}; compositor activation was not confirmed")
        }
        FocusResult::NoOp(reason) => format!("Cannot focus {name}: {reason}"),
        FocusResult::Error(error) => format!("Focus failed for {name}: {error}"),
    }
}

async fn run_raw(args: &Args, monitor: Monitor) -> Result<(), Box<dyn Error>> {
    let mut runtime = monitor.spawn();
    let control = runtime.control.clone();
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut resync = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1())?;

    loop {
        tokio::select! {
            signal = tokio::signal::ctrl_c() => {
                signal?;
                control.shutdown();
                break;
            }
            _ = terminate.recv() => {
                control.shutdown();
                break;
            }
            _ = resync.recv() => control.request_resync(),
            event = runtime.events.recv() => {
                let Some(event) = event else { break };
                print_event(event, args.verbose > 0);
            }
        }
    }

    while let Some(event) = runtime.events.recv().await {
        print_event(event, args.verbose > 0);
    }
    runtime.wait().await?;
    Ok(())
}

async fn run_watch(args: &Args, monitor: Monitor, watch: WatchArgs) -> Result<(), Box<dyn Error>> {
    let mut stdout = io::stdout();
    let mut stderr = io::stderr();
    if let Err(error) = write_watch_header(&mut stdout, watch.header) {
        return if error.kind() == io::ErrorKind::BrokenPipe {
            Ok(())
        } else {
            Err(error.into())
        };
    }

    let mut runtime = monitor.spawn();
    let control = runtime.control.clone();
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut resync = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1())?;
    let mut write_error = None;

    loop {
        tokio::select! {
            signal = tokio::signal::ctrl_c() => {
                signal?;
                control.shutdown();
                break;
            }
            _ = terminate.recv() => {
                control.shutdown();
                break;
            }
            _ = resync.recv() => control.request_resync(),
            event = runtime.events.recv() => {
                let Some(event) = event else { break };
                if let Err(error) = write_watch_event(
                    &mut stdout,
                    &mut stderr,
                    event,
                    args.verbose > 0,
                    &watch_timestamp(),
                ) {
                    control.shutdown();
                    if error.kind() != io::ErrorKind::BrokenPipe {
                        write_error = Some(error);
                    }
                    break;
                }
            }
        }
    }

    runtime.wait().await?;
    if let Some(error) = write_error {
        return Err(error.into());
    }
    Ok(())
}

const WATCH_TIME_WIDTH: usize = 20;
const WATCH_SESSION_WIDTH: usize = 30;
const WATCH_REASON_WIDTH: usize = 10;

fn write_watch_header(writer: &mut impl io::Write, enabled: bool) -> io::Result<()> {
    if enabled {
        write_line(writer, &watch_header())
    } else {
        Ok(())
    }
}

fn watch_header() -> String {
    format!(
        "{:<WATCH_TIME_WIDTH$}  {:<WATCH_SESSION_WIDTH$}  {:<WATCH_REASON_WIDTH$}  TITLE",
        "TIME", "SESSION", "REASON"
    )
}

fn watch_row(timestamp: &str, attention: &opencode_beacon::model::AttentionEvent) -> String {
    format!(
        "{}  {}  {}  {}",
        fixed_ascii(timestamp, WATCH_TIME_WIDTH),
        minimum_width(
            &sanitize_title(&attention.root_session_id),
            WATCH_SESSION_WIDTH
        ),
        fixed_ascii(&attention.kind.to_string(), WATCH_REASON_WIDTH),
        sanitize_title(attention.name()),
    )
}

fn minimum_width(value: &str, width: usize) -> String {
    let character_count = value.chars().count();
    if character_count < width {
        format!("{value}{:padding$}", "", padding = width - character_count)
    } else {
        value.to_owned()
    }
}

fn fixed_ascii(value: &str, width: usize) -> String {
    let sanitized = value
        .chars()
        .map(|character| {
            if character.is_ascii() && !character.is_ascii_control() {
                character
            } else {
                '?'
            }
        })
        .collect::<String>();
    let value = if sanitized.len() > width {
        format!("{}...", &sanitized[..width.saturating_sub(3)])
    } else {
        sanitized
    };
    format!("{value:<width$}")
}

fn sanitize_title(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() || matches!(character, '\u{2028}' | '\u{2029}') {
                ' '
            } else {
                character
            }
        })
        .collect()
}

fn watch_timestamp() -> String {
    let now = OffsetDateTime::now_utc();
    now.replace_nanosecond(0)
        .unwrap_or(now)
        .format(&Rfc3339)
        .unwrap_or_else(|_| "0000-00-00T00:00:00Z".to_owned())
}

fn write_watch_event(
    stdout: &mut impl io::Write,
    stderr: &mut impl io::Write,
    event: BeaconEvent,
    verbose: bool,
    timestamp: &str,
) -> io::Result<()> {
    match event {
        BeaconEvent::Attention { attention, .. } => {
            write_line(stdout, &watch_row(timestamp, &attention))
        }
        BeaconEvent::Diagnostic {
            endpoint,
            message,
            verbose_only: _,
        } if verbose => {
            let server = endpoint.map_or_else(|| "-".to_owned(), |endpoint| endpoint.to_string());
            write_line(
                stderr,
                &format!(
                    "{timestamp} server={server} diagnostic={}",
                    quoted(&message)
                ),
            )
        }
        _ => Ok(()),
    }
}

fn write_line(writer: &mut impl io::Write, line: &str) -> io::Result<()> {
    writeln!(writer, "{line}")?;
    writer.flush()
}

fn monitor_config(args: &Args, client: ClientConfig) -> MonitorConfig {
    MonitorConfig {
        discovery_interval: args.discover_interval,
        full_verification_interval: args.full_verification_interval,
        resync_interval: args.resync_interval,
        event_capacity: args.event_capacity,
        client,
        ..MonitorConfig::default()
    }
}

async fn run_once(args: &Args, client_config: &ClientConfig) -> Result<(), Box<dyn Error>> {
    let discovery_config = DiscoveryConfig::default();
    let discovery = LinuxProcfsDiscovery::new(discovery_config.clone());
    let managed = ManagedServiceDiscovery::new(
        ManagedDiscoveryConfig::default(),
        discovery_config.proc_root,
    );
    let (procfs, managed_result) = tokio::join!(
        discovery.discover(client_config),
        managed.discover(client_config)
    );
    let (report, managed_report) = match (procfs, managed_result) {
        (Ok(report), Ok(managed_report)) => (report, managed_report),
        (Ok(report), Err(error)) => {
            if args.verbose > 0 {
                eprintln!(
                    "{} diagnostic={}",
                    timestamp(),
                    quoted(&format!("v2 discovery failed: {error}"))
                );
            }
            (report, DiscoveryReport::default())
        }
        (Err(error), Ok(managed_report)) => {
            if args.verbose > 0 {
                eprintln!(
                    "{} diagnostic={}",
                    timestamp(),
                    quoted(&format!("v1 discovery failed: {error}"))
                );
            }
            (DiscoveryReport::default(), managed_report)
        }
        (Err(procfs), Err(managed)) => {
            return Err(
                format!("v1 discovery failed: {procfs}; v2 discovery failed: {managed}").into(),
            );
        }
    };
    if args.verbose > 0 {
        for diagnostic in report.diagnostics.iter().chain(&managed_report.diagnostics) {
            eprintln!("{} diagnostic={}", timestamp(), quoted(&diagnostic.message));
        }
    }
    let managed_endpoints = managed_report
        .instances
        .iter()
        .map(|instance| instance.endpoint)
        .collect::<HashSet<_>>();
    for instance in report
        .instances
        .iter()
        .filter(|instance| !managed_endpoints.contains(&instance.endpoint))
    {
        print_event(BeaconEvent::ServerFound(instance.clone()), args.verbose > 0);
        print_once_snapshot(
            instance.clone(),
            report.snapshot_for(instance, client_config.clone()).await,
            args.verbose > 0,
        );
    }
    for instance in &managed_report.instances {
        print_event(BeaconEvent::ServerFound(instance.clone()), args.verbose > 0);
        let snapshot = managed_report
            .snapshot_for(instance, client_config.clone())
            .await;
        print_once_snapshot(instance.clone(), snapshot, args.verbose > 0);
    }
    Ok(())
}

#[cfg(test)]
async fn managed_once_snapshot(
    managed: &ManagedServiceDiscovery,
    instance: &opencode_beacon::model::ServerInstance,
    client_config: &ClientConfig,
) -> Result<opencode_beacon::model::Snapshot, String> {
    let client = managed
        .client_for(instance, client_config.clone())
        .map_err(|error| format!("managed client setup failed: {error}"))?;
    client.snapshot().await.map_err(|error| error.to_string())
}

fn print_once_snapshot(
    instance: opencode_beacon::model::ServerInstance,
    snapshot: Result<opencode_beacon::model::Snapshot, String>,
    verbose: bool,
) {
    match snapshot {
        Ok(snapshot) => {
            let mut state = ServerState::default();
            let update = state.reconcile_with_updates(snapshot, true);
            print_event(
                BeaconEvent::InitialState {
                    endpoint: instance.endpoint,
                    active_sessions: state.active_session_count(),
                },
                verbose,
            );
            for transition in update.transitions {
                print_event(
                    BeaconEvent::Transition {
                        endpoint: instance.endpoint,
                        transition,
                    },
                    verbose,
                );
            }
            for attention in update.attention {
                print_event(
                    BeaconEvent::Attention {
                        endpoint: instance.endpoint,
                        attention,
                    },
                    verbose,
                );
            }
            print_event(
                BeaconEvent::StateProjection(opencode_beacon::ServerProjection {
                    instance_key: instance.key,
                    endpoint: instance.endpoint,
                    sessions: state.projection(),
                }),
                verbose,
            );
        }
        Err(error) => eprintln!(
            "{} server={} snapshot_error={}",
            timestamp(),
            instance.endpoint,
            quoted(&error)
        ),
    }
}

fn load_auth(args: &Args) -> Result<Option<BasicAuth>, Box<dyn Error>> {
    let password = env::var(&args.password_env).ok();
    match (&args.username, password) {
        (None, None) => Ok(None),
        (Some(_), None) => Err(format!("{} is not set", args.password_env).into()),
        (None, Some(_)) => Err("a username is required when a password is configured".into()),
        (Some(username), Some(password)) => Ok(Some(BasicAuth::new(
            username.clone(),
            SecretString::from(password),
        ))),
    }
}

fn print_event(event: BeaconEvent, verbose: bool) {
    match event {
        BeaconEvent::ServerFound(instance) => println!(
            "{} server={} event=server_found protocol={} version={}",
            timestamp(),
            instance.endpoint,
            instance.protocol,
            quoted(&instance.version)
        ),
        BeaconEvent::ServerRemoved(instance) => println!(
            "{} server={} event=server_removed",
            timestamp(),
            instance.endpoint
        ),
        BeaconEvent::Connected(endpoint) => {
            println!("{} server={} event=connected", timestamp(), endpoint);
        }
        BeaconEvent::Disconnected { endpoint, reason } => {
            eprintln!("{}", raw_disconnect_line(&timestamp(), endpoint, &reason));
        }
        BeaconEvent::InitialState {
            endpoint,
            active_sessions,
        } => println!(
            "{} server={} event=initial_state active_sessions={active_sessions}",
            timestamp(),
            endpoint
        ),
        BeaconEvent::Observed { endpoint, event } => {
            let mut line = format!(
                "{} server={} source=sse observed={}",
                timestamp(),
                endpoint,
                quoted(&event.kind)
            );
            append(&mut line, "session", event.session_id.as_deref());
            append(&mut line, "request", event.request_id.as_deref());
            append(&mut line, "detail", event.detail.as_deref());
            println!("{line}");
        }
        BeaconEvent::Transition {
            endpoint,
            transition,
        } => println!(
            "{} server={} source={} session={} state={}->{}",
            timestamp(),
            endpoint,
            transition.source,
            quoted(&transition.session_id),
            transition.previous,
            transition.current
        ),
        BeaconEvent::Attention {
            endpoint,
            attention,
        } => println!("{}", attention_line(&timestamp(), endpoint, &attention)),
        BeaconEvent::StateProjection(projection) => println!(
            "{} server={} event=state_projection instance_pid={} socket_inode={} sessions={}",
            timestamp(),
            projection.endpoint,
            projection.instance_key.pid,
            projection.instance_key.socket_inode,
            projection.sessions.len()
        ),
        BeaconEvent::Diagnostic {
            endpoint,
            message,
            verbose_only,
        } if verbose || !verbose_only => {
            let server = endpoint.map_or_else(|| "-".to_owned(), |endpoint| endpoint.to_string());
            eprintln!(
                "{} server={} diagnostic={}",
                timestamp(),
                server,
                quoted(&message)
            );
        }
        _ => {}
    }
}

fn raw_disconnect_line(
    timestamp: &str,
    endpoint: opencode_beacon::model::ServerEndpoint,
    reason: &str,
) -> String {
    format!(
        "{timestamp} server={endpoint} event=disconnected reason={}",
        quoted(reason)
    )
}

fn attention_line(
    timestamp: &str,
    endpoint: opencode_beacon::model::ServerEndpoint,
    attention: &opencode_beacon::model::AttentionEvent,
) -> String {
    let mut line = format!(
        "{} server={} source={} event=attention attention={} name={} root={} subject={}",
        timestamp,
        endpoint,
        attention.source,
        attention.kind,
        quoted(attention.name()),
        quoted(&attention.root_session_id),
        quoted(&attention.subject_session_id),
    );
    append(&mut line, "request", attention.request_id.as_deref());
    let _ = write!(
        line,
        " initial={} root_resolved={}",
        attention.initial, attention.root_resolved
    );
    line
}

fn append(line: &mut String, name: &str, value: Option<&str>) {
    if let Some(value) = value {
        line.push(' ');
        line.push_str(name);
        line.push('=');
        line.push_str(&quoted(value));
    }
}

fn quoted(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"<invalid>\"".to_owned())
}

fn timestamp() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "unknown-time".to_owned())
}

fn parse_duration(value: &str) -> Result<Duration, String> {
    let (number, multiplier) = if let Some(value) = value.strip_suffix("ms") {
        (value, 1_u64)
    } else if let Some(value) = value.strip_suffix('s') {
        (value, 1_000)
    } else if let Some(value) = value.strip_suffix('m') {
        (value, 60_000)
    } else {
        return Err("duration must end in ms, s, or m".to_owned());
    };
    let amount = number
        .parse::<u64>()
        .map_err(|_| "duration must contain an integer".to_owned())?;
    let millis = amount
        .checked_mul(multiplier)
        .ok_or_else(|| "duration is too large".to_owned())?;
    if millis == 0 {
        return Err("duration must be greater than zero".to_owned());
    }
    Ok(Duration::from_millis(millis))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_focus_status_reports_exact_tab_selection() {
        assert_eq!(
            focus_result_message("Root", FocusResult::TabSelected),
            "Selected tab for Root; compositor activation unavailable for multi-window Konsole"
        );
        assert_eq!(
            focus_result_message("Root", FocusResult::KittySelected),
            "Selected Kitty pane for Root; compositor activation was not confirmed"
        );
    }

    fn attention(
        kind: opencode_beacon::AttentionKind,
        root_session_id: &str,
        title: Option<&str>,
        slug: Option<&str>,
    ) -> opencode_beacon::AttentionEvent {
        opencode_beacon::AttentionEvent {
            kind,
            root_session_id: root_session_id.to_owned(),
            root_title: title.map(ToOwned::to_owned),
            root_slug: slug.map(ToOwned::to_owned),
            subject_session_id: root_session_id.to_owned(),
            request_id: None,
            source: opencode_beacon::TransitionSource::Live,
            initial: false,
            root_resolved: true,
        }
    }

    fn server_instance_for_test() -> opencode_beacon::model::ServerInstance {
        opencode_beacon::model::ServerInstance {
            key: opencode_beacon::model::InstanceKey {
                network_namespace_inode: 1,
                socket_inode: 2,
                listener: endpoint_for_test().address(),
                pid: 3,
                source: opencode_beacon::model::InstanceSource::LinuxProcfs,
            },
            endpoint: endpoint_for_test(),
            protocol: opencode_beacon::OpenCodeProtocol::V1,
            executable: None,
            version: "test".to_owned(),
        }
    }

    #[tokio::test]
    async fn managed_once_setup_failures_are_per_instance_results() {
        use std::os::unix::fs::MetadataExt;

        let directory =
            tempfile::tempdir().unwrap_or_else(|error| unreachable!("temp directory: {error}"));
        let proc_root = directory.path().join("proc");
        let self_root = proc_root.join("self");
        assert!(std::fs::create_dir_all(&self_root).is_ok());
        let uid = std::fs::metadata(&self_root)
            .unwrap_or_else(|error| unreachable!("self metadata: {error}"))
            .uid();
        assert!(
            std::fs::write(
                self_root.join("status"),
                format!("Name:\ttest\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n")
            )
            .is_ok()
        );
        let managed = ManagedServiceDiscovery::new(
            ManagedDiscoveryConfig {
                state_dir: Some(directory.path().join("state")),
            },
            proc_root,
        );
        let mut failures = Vec::new();
        for index in 0..2_u16 {
            let endpoint = opencode_beacon::model::ServerEndpoint::new(std::net::SocketAddr::from(
                ([127, 0, 0, 1], 5000 + index),
            ))
            .unwrap_or_else(|error| unreachable!("test endpoint is local: {error}"));
            let instance = opencode_beacon::model::ServerInstance {
                key: opencode_beacon::model::InstanceKey {
                    network_namespace_inode: 0,
                    socket_inode: 0,
                    listener: endpoint.address(),
                    pid: u32::from(index) + 1,
                    source: opencode_beacon::model::InstanceSource::ManagedService {
                        registration: directory.path().join(format!("service-{index}.json")),
                        id: Some(format!("service-{index}")),
                    },
                },
                endpoint,
                protocol: opencode_beacon::OpenCodeProtocol::V2,
                executable: None,
                version: "2.0.0".to_owned(),
            };
            let failure = managed_once_snapshot(&managed, &instance, &ClientConfig::default())
                .await
                .err()
                .unwrap_or_else(|| unreachable!("missing registration must fail setup"));
            failures.push(failure);
        }
        assert_eq!(failures.len(), 2);
        assert!(
            failures
                .iter()
                .all(|error| error.contains("managed client setup failed"))
        );
    }

    #[test]
    fn parses_supported_durations() {
        assert_eq!(parse_duration("500ms"), Ok(Duration::from_millis(500)));
        assert_eq!(parse_duration("2s"), Ok(Duration::from_secs(2)));
        assert_eq!(parse_duration("3m"), Ok(Duration::from_secs(180)));
        assert!(parse_duration("0s").is_err());
        assert!(parse_duration("2h").is_err());
    }

    #[test]
    fn parses_watch_and_preserves_no_subcommand_behavior() {
        let default = Args::try_parse_from(["opencode-beacon"])
            .and_then(Args::validate)
            .unwrap_or_else(|error| unreachable!("default arguments parse: {error}"));
        assert_eq!(default.command, None);
        assert!(!default.once);

        let watch = Args::try_parse_from(["opencode-beacon", "watch", "--verbose"])
            .and_then(Args::validate)
            .unwrap_or_else(|error| unreachable!("watch arguments parse: {error}"));
        assert_eq!(
            watch.command,
            Some(Command::Watch(WatchArgs { header: false }))
        );
        assert_eq!(watch.verbose, 1);

        let with_header = Args::try_parse_from(["opencode-beacon", "watch", "--header"])
            .and_then(Args::validate)
            .unwrap_or_else(|error| unreachable!("watch header arguments parse: {error}"));
        assert_eq!(
            with_header.command,
            Some(Command::Watch(WatchArgs { header: true }))
        );

        assert!(
            Args::try_parse_from(["opencode-beacon", "watch", "--once"])
                .and_then(Args::validate)
                .is_err()
        );
        assert!(
            Args::try_parse_from(["opencode-beacon", "--once", "watch"])
                .and_then(Args::validate)
                .is_err()
        );

        let dashboard = Args::try_parse_from(["opencode-beacon", "dashboard"])
            .and_then(Args::validate)
            .unwrap_or_else(|error| unreachable!("dashboard arguments parse: {error}"));
        assert_eq!(dashboard.command, Some(Command::Dashboard));
        assert!(
            Args::try_parse_from(["opencode-beacon", "dashboard", "--once"])
                .and_then(Args::validate)
                .is_err()
        );
    }

    #[test]
    fn dashboard_requires_real_terminals_and_non_dumb_term() {
        assert!(validate_dashboard_terminal(true, true, Some("xterm-256color")).is_ok());
        for result in [
            validate_dashboard_terminal(false, true, Some("xterm")),
            validate_dashboard_terminal(true, false, Some("xterm")),
            validate_dashboard_terminal(true, true, Some("dumb")),
            validate_dashboard_terminal(true, true, None),
        ] {
            assert!(result.is_err_and(|message| message.contains("watch")));
        }
    }

    #[test]
    fn terminal_cleanup_attempts_screen_then_raw_even_after_error() {
        struct Cleanup {
            calls: Vec<&'static str>,
            screen_fails: bool,
        }

        impl TerminalCleanup for Cleanup {
            fn leave_screen(&mut self) -> io::Result<()> {
                self.calls.push("screen");
                if self.screen_fails {
                    Err(io::Error::other("screen"))
                } else {
                    Ok(())
                }
            }

            fn leave_raw_mode(&mut self) -> io::Result<()> {
                self.calls.push("raw");
                Ok(())
            }
        }

        let mut cleanup = Cleanup {
            calls: Vec::new(),
            screen_fails: true,
        };
        assert!(restore_terminal(&mut cleanup).is_err());
        assert_eq!(cleanup.calls, ["screen", "raw"]);
    }

    #[test]
    fn watch_header_and_rows_have_fixed_column_boundaries() {
        let header = watch_header();
        assert_eq!(header.len(), 71);
        assert_eq!(&header[..WATCH_TIME_WIDTH], "TIME                ");
        assert_eq!(&header[22..52], "SESSION                       ");
        assert_eq!(&header[54..64], "REASON    ");
        assert_eq!(&header[66..], "TITLE");

        for kind in [
            opencode_beacon::AttentionKind::Ready,
            opencode_beacon::AttentionKind::Question,
            opencode_beacon::AttentionKind::Permission,
        ] {
            let row = watch_row(
                "2026-08-11T16:00:00Z",
                &attention(kind, "ses_short", Some("Complete title"), None),
            );
            assert_eq!(&row[..20], "2026-08-11T16:00:00Z");
            assert_eq!(&row[22..52], "ses_short                     ");
            assert_eq!(row[54..64].trim(), kind.to_string());
            assert_eq!(row[66..].to_owned(), "Complete title");
            assert_eq!(row.lines().count(), 1);
        }
    }

    #[test]
    fn watch_header_is_opt_in_and_emitted_once_when_requested() {
        let mut output = Vec::new();
        assert!(write_watch_header(&mut output, false).is_ok());
        assert!(output.is_empty());
        assert!(write_watch_header(&mut output, true).is_ok());
        assert_eq!(
            String::from_utf8_lossy(&output),
            format!("{}\n", watch_header())
        );
    }

    #[test]
    fn watch_session_ids_are_never_truncated() {
        let short = watch_row(
            "2026-08-11T16:00:00Z",
            &attention(
                opencode_beacon::AttentionKind::Ready,
                "ses_short",
                Some("Short"),
                None,
            ),
        );
        assert_eq!(&short[22..52], "ses_short                     ");
        assert!(short.ends_with("Short"));

        let canonical_id = "ses_0123456789ABCDEFGHIJKLMNOP";
        assert_eq!(canonical_id.len(), WATCH_SESSION_WIDTH);
        let canonical = watch_row(
            "2026-08-11T16:00:00Z",
            &attention(
                opencode_beacon::AttentionKind::Question,
                canonical_id,
                Some("Canonical"),
                None,
            ),
        );
        assert_eq!(&canonical[22..52], canonical_id);
        assert_eq!(&canonical[66..], "Canonical");

        let unexpected = "ses_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZunexpected";
        let long = watch_row(
            "2026-08-11T16:00:00Z",
            &attention(
                opencode_beacon::AttentionKind::Permission,
                unexpected,
                Some("Long"),
                None,
            ),
        );
        assert!(long.contains(unexpected));
        assert!(!long.contains("..."));
        let title_start = 20 + 2 + unexpected.len() + 2 + WATCH_REASON_WIDTH + 2;
        assert_eq!(&long[title_start..], "Long");
    }

    #[test]
    fn watch_titles_retain_unicode_and_follow_fallback_order() {
        let unicode = watch_row(
            "2026-08-11T16:00:00Z",
            &attention(
                opencode_beacon::AttentionKind::Question,
                "root",
                Some("Résumé 日本語 Δ"),
                Some("unused"),
            ),
        );
        assert!(unicode.ends_with("Résumé 日本語 Δ"));

        let slug = watch_row(
            "2026-08-11T16:00:00Z",
            &attention(
                opencode_beacon::AttentionKind::Permission,
                "root",
                Some(""),
                Some("slug-fallback"),
            ),
        );
        assert!(slug.ends_with("slug-fallback"));

        let id = watch_row(
            "2026-08-11T16:00:00Z",
            &attention(opencode_beacon::AttentionKind::Ready, "root-id", None, None),
        );
        assert!(id.ends_with("root-id"));
    }

    #[test]
    fn watch_titles_neutralize_controls_and_ansi() {
        let title = "alpha\tbeta\ngamma\rdelta\u{1b}[31mred\u{7f}\u{2028}line\u{2029}🙂";
        let sanitized = sanitize_title(title);
        assert_eq!(sanitized, "alpha beta gamma delta [31mred  line 🙂");
        assert_eq!(sanitized.lines().count(), 1);
        assert!(!sanitized.chars().any(char::is_control));
        assert!(!sanitized.contains('\u{1b}'));
    }

    fn beacon_events_for_watch_test() -> Vec<BeaconEvent> {
        let instance = server_instance_for_test();
        vec![
            BeaconEvent::ServerFound(instance.clone()),
            BeaconEvent::ServerRemoved(instance),
            BeaconEvent::Connected(endpoint_for_test()),
            BeaconEvent::Disconnected {
                endpoint: endpoint_for_test(),
                reason: "SSE stream ended".to_owned(),
            },
            BeaconEvent::InitialState {
                endpoint: endpoint_for_test(),
                active_sessions: 1,
            },
            BeaconEvent::Observed {
                endpoint: endpoint_for_test(),
                event: opencode_beacon::model::ObservedEvent {
                    kind: "question.asked".to_owned(),
                    session_id: Some("s".to_owned()),
                    request_id: Some("q".to_owned()),
                    detail: None,
                },
            },
            BeaconEvent::Transition {
                endpoint: endpoint_for_test(),
                transition: opencode_beacon::model::StateTransition {
                    session_id: "s".to_owned(),
                    previous: opencode_beacon::ActivityState::Working,
                    current: opencode_beacon::ActivityState::Idle,
                    source: opencode_beacon::TransitionSource::Live,
                },
            },
            BeaconEvent::Attention {
                endpoint: endpoint_for_test(),
                attention: attention(
                    opencode_beacon::AttentionKind::Question,
                    "root",
                    Some("Needs attention"),
                    None,
                ),
            },
            BeaconEvent::StateProjection(opencode_beacon::ServerProjection {
                instance_key: server_instance_for_test().key,
                endpoint: endpoint_for_test(),
                sessions: Vec::new(),
            }),
            BeaconEvent::Diagnostic {
                endpoint: Some(endpoint_for_test()),
                message: "important diagnostic".to_owned(),
                verbose_only: false,
            },
            BeaconEvent::Diagnostic {
                endpoint: Some(endpoint_for_test()),
                message: "routine diagnostic".to_owned(),
                verbose_only: true,
            },
        ]
    }

    #[test]
    fn watch_routes_only_attention_by_default_for_every_event_variant() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let time = "2026-08-11T16:00:00Z";
        for event in beacon_events_for_watch_test() {
            assert!(write_watch_event(&mut stdout, &mut stderr, event, false, time).is_ok());
        }
        assert_eq!(String::from_utf8_lossy(&stdout).lines().count(), 1);
        assert!(String::from_utf8_lossy(&stdout).contains("Needs attention"));
        assert!(stderr.is_empty());
    }

    #[test]
    fn verbose_watch_adds_only_diagnostics_on_stderr() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let time = "2026-08-11T16:00:00Z";
        for event in beacon_events_for_watch_test() {
            assert!(write_watch_event(&mut stdout, &mut stderr, event, true, time).is_ok());
        }
        let stdout = String::from_utf8_lossy(&stdout);
        let stderr = String::from_utf8_lossy(&stderr);
        assert_eq!(stdout.lines().count(), 1);
        assert!(stdout.contains("Needs attention"));
        assert_eq!(stderr.lines().count(), 2);
        assert!(stderr.contains("important diagnostic"));
        assert!(stderr.contains("routine diagnostic"));
        assert!(!stderr.contains("disconnected"));
        assert!(!stderr.contains("SSE stream ended"));
    }

    #[test]
    fn raw_mode_disconnect_rendering_remains_available() {
        let line = raw_disconnect_line(
            "2026-08-11T16:00:00Z",
            endpoint_for_test(),
            "SSE stream ended",
        );
        assert_eq!(
            line,
            "2026-08-11T16:00:00Z server=127.0.0.1:4096 event=disconnected reason=\"SSE stream ended\""
        );
    }

    #[test]
    fn watch_keeps_initial_attention_visible_without_extra_columns() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut event = attention(
            opencode_beacon::AttentionKind::Question,
            "root",
            Some("Startup question"),
            None,
        );
        event.initial = true;
        assert!(
            write_watch_event(
                &mut stdout,
                &mut stderr,
                BeaconEvent::Attention {
                    endpoint: endpoint_for_test(),
                    attention: event,
                },
                false,
                "2026-08-11T16:00:00Z",
            )
            .is_ok()
        );
        let output = String::from_utf8_lossy(&stdout);
        assert!(output.contains("question"));
        assert!(output.contains("Startup question"));
        assert!(!output.contains("initial"));
        assert!(stderr.is_empty());
    }

    struct BrokenPipe;

    impl io::Write for BrokenPipe {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }
    }

    #[test]
    fn watch_writes_are_fallible_for_clean_pipeline_shutdown() {
        let mut stderr = Vec::new();
        let result = write_watch_event(
            &mut BrokenPipe,
            &mut stderr,
            BeaconEvent::Attention {
                endpoint: endpoint_for_test(),
                attention: attention(
                    opencode_beacon::AttentionKind::Ready,
                    "root",
                    Some("Title"),
                    None,
                ),
            },
            false,
            "2026-08-11T16:00:00Z",
        );
        assert!(result.is_err_and(|error| error.kind() == io::ErrorKind::BrokenPipe));
        assert!(write_watch_header(&mut BrokenPipe, false).is_ok());
        assert!(
            write_watch_header(&mut BrokenPipe, true)
                .is_err_and(|error| error.kind() == io::ErrorKind::BrokenPipe)
        );
    }

    #[test]
    fn quotes_untrusted_output_on_one_line() {
        assert_eq!(quoted("a\nb"), "\"a\\nb\"");
    }

    #[test]
    fn attention_output_quotes_names_and_omits_request_payloads() {
        let attention = opencode_beacon::model::AttentionEvent {
            kind: opencode_beacon::model::AttentionKind::Question,
            root_session_id: "root\n\u{1b}[31m".to_owned(),
            root_title: Some("title\r\nquoted \"name\"".to_owned()),
            root_slug: Some("unused-secret-slug".to_owned()),
            subject_session_id: "child\nsubject".to_owned(),
            request_id: Some("request\nidentifier".to_owned()),
            source: opencode_beacon::model::TransitionSource::Live,
            initial: false,
            root_resolved: true,
        };
        let line = attention_line("time", endpoint_for_test(), &attention);
        assert_eq!(line.lines().count(), 1);
        assert!(line.contains("name=\"title\\r\\nquoted \\\"name\\\"\""));
        assert!(line.contains("root=\"root\\n\\u001b[31m\""));
        assert!(line.contains("request=\"request\\nidentifier\""));
        assert!(!line.contains("unused-secret-slug"));
        assert!(!line.contains("question text"));
        assert!(!line.contains("permission pattern"));
    }

    fn endpoint_for_test() -> opencode_beacon::model::ServerEndpoint {
        opencode_beacon::model::ServerEndpoint::new(
            "127.0.0.1:4096"
                .parse()
                .unwrap_or_else(|error| unreachable!("static endpoint parses: {error}")),
        )
        .unwrap_or_else(|error| unreachable!("static endpoint is loopback: {error}"))
    }

    #[test]
    fn cli_event_capacity_reaches_typed_monitor_validation() {
        let args = Args::try_parse_from(["opencode-beacon", "--event-capacity", "0"]);
        assert!(args.is_ok());
        let args = args.unwrap_or_else(|error| unreachable!("arguments parse: {error}"));
        let monitor = Monitor::new(monitor_config(&args, ClientConfig::default()));
        assert!(matches!(
            monitor,
            Err(opencode_beacon::MonitorConfigError::ZeroCapacity {
                field: "event_capacity"
            })
        ));
    }
}
