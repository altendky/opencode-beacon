use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixDatagram, UnixStream};
use tokio::process::Command;

use crate::attachment::{
    ClientFocusTarget, FocusTarget, KittyTarget, KonsoleTarget, focus_process_matches,
    kitty_target_for_process, kitty_target_matches, process_key,
};

const COMMAND_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_COMMAND_OUTPUT: usize = 64 * 1024;
const KWIN_SCRIPT_TEMPLATE: &str = include_str!("kwin_focus.js");
const KWIN_PID_TOKEN: &str = "__KONSOLE_OWNER_PID__";
const BRIDGE_INTERFACE: &str = "org.altendky.OpenCodeBeacon.KonsoleActivationBridge1";
const BRIDGE_CAPABILITY: &str = "activate-session-with-xdg-token";
const MAX_ACTIVATION_TOKEN_SIZE: usize = 4096;
const CURRENT_SESSION_VERIFY_ATTEMPTS: usize = 6;
const CURRENT_SESSION_VERIFY_INTERVAL: Duration = Duration::from_millis(40);
const CURRENT_SESSION_VERIFY_TIMEOUT: Duration = Duration::from_millis(500);
const KITTY_BRIDGE_PROTOCOL_VERSION: &str = "2";
const KITTY_BRIDGE_KITTEN: &str = "opencode_beacon_focus.py";
const KITTY_BRIDGE_PROBE_OK: &str = "opencode-beacon-kitty-bridge/2 target-ready";
const KITTY_BRIDGE_ACTIVATE_OK: &str = "opencode-beacon-kitty-bridge/2 activated";
const KITTY_BRIDGE_SOURCE_OK: &str = "opencode-beacon-kitty-bridge/2 source-ready";
const KITTY_BRIDGE_SOURCE_REQUESTED: &str = "opencode-beacon-kitty-bridge/2 source-token-requested";
const KITTY_COMMAND_PREFIX: &[u8] = b"\x1bP@kitty-cmd";
const KITTY_COMMAND_SUFFIX: &[u8] = b"\x1b\\";
const KITTY_SOURCE_CALLBACK_PREFIX: &str = "opencode-beacon-source-";
const MAX_KITTY_SOURCE_DATAGRAM_SIZE: usize = 8 * 1024;
const MAX_KITTY_SOURCE_DATAGRAMS: usize = 8;

#[derive(Debug, Eq, PartialEq)]
pub enum FocusResult {
    Requested,
    TabSelected,
    KittySelected,
    NoOp(String),
    Error(String),
}

pub async fn focus_client(target: &FocusTarget) -> FocusResult {
    let proc_root = Path::new("/proc");
    let mut broker = ActivationTokenBroker::new(proc_root);
    match &target.client {
        ClientFocusTarget::Konsole(_) => {
            focus_konsole_with(
                target,
                proc_root,
                &mut QdbusCommands::default(),
                &mut broker,
            )
            .await
        }
        ClientFocusTarget::Kitty(kitty) => {
            focus_kitty_with(
                target,
                kitty,
                proc_root,
                &mut SystemKittyCommands,
                &mut broker,
            )
            .await
        }
    }
}

trait FocusCommands {
    async fn qdbus(&mut self, arguments: &[&str]) -> Result<String, CommandError>;
    async fn bridge_version(&mut self, service: &str, path: &str) -> Result<u32, ()>;
    async fn bridge_capabilities(&mut self, service: &str, path: &str) -> Result<Vec<String>, ()>;
    async fn bridge_activate(
        &mut self,
        service: &str,
        path: &str,
        session_id: i32,
        token: &SecretString,
    ) -> Result<bool, ()>;
}

#[derive(Default)]
struct QdbusCommands {
    connection: Option<zbus::Connection>,
}

#[derive(Debug)]
struct ActivationSource {
    service: String,
    session_path: String,
    cookie: SecretString,
}

impl ActivationSource {
    fn from_environment() -> Option<Self> {
        let service = std::env::var("KONSOLE_DBUS_SERVICE").ok()?;
        let session_path = std::env::var("KONSOLE_DBUS_SESSION").ok()?;
        let cookie = std::env::var("KONSOLE_DBUS_ACTIVATION_COOKIE").ok()?;
        (valid_service(&service) && session_id(&session_path).is_some() && valid_cookie(&cookie))
            .then(|| Self {
                service,
                session_path,
                cookie: SecretString::from(cookie),
            })
    }
}

trait ActivationTokenSource {
    async fn activation_token(&mut self) -> Option<SecretString>;
}

struct KittyActivationTokenProvider {
    proc_root: PathBuf,
}

impl ActivationTokenSource for KittyActivationTokenProvider {
    async fn activation_token(&mut self) -> Option<SecretString> {
        kitty_source_activation_token(&self.proc_root).await
    }
}

#[derive(Default)]
struct KonsoleActivationTokenProvider {
    qdbus: QdbusCommands,
}

impl ActivationTokenSource for KonsoleActivationTokenProvider {
    async fn activation_token(&mut self) -> Option<SecretString> {
        let source = QdbusCommands::activation_source()?;
        self.qdbus.activation_token(&source).await.ok()
    }
}

struct ActivationTokenBroker<K, C> {
    kitty: K,
    konsole: C,
}

impl ActivationTokenBroker<KittyActivationTokenProvider, KonsoleActivationTokenProvider> {
    fn new(proc_root: &Path) -> Self {
        Self {
            kitty: KittyActivationTokenProvider {
                proc_root: proc_root.to_owned(),
            },
            konsole: KonsoleActivationTokenProvider::default(),
        }
    }
}

impl<K: ActivationTokenSource, C: ActivationTokenSource> ActivationTokenSource
    for ActivationTokenBroker<K, C>
{
    async fn activation_token(&mut self) -> Option<SecretString> {
        if let Some(token) = self.kitty.activation_token().await {
            return Some(token);
        }
        self.konsole.activation_token().await
    }
}

impl QdbusCommands {
    fn activation_source() -> Option<ActivationSource> {
        ActivationSource::from_environment()
    }

    async fn activation_token(&mut self, source: &ActivationSource) -> Result<SecretString, ()> {
        let proxy = self
            .proxy(
                &source.service,
                &source.session_path,
                "org.kde.konsole.Session",
            )
            .await?;
        let token: String = tokio::time::timeout(
            COMMAND_TIMEOUT,
            proxy.call("activationToken", &(source.cookie.expose_secret())),
        )
        .await
        .map_err(|_| ())?
        .map_err(|_| ())?;
        valid_activation_token(&token)
            .then(|| SecretString::from(token))
            .ok_or(())
    }

    async fn connection(&mut self) -> Result<&zbus::Connection, ()> {
        if self.connection.is_none() {
            self.connection = Some(
                tokio::time::timeout(COMMAND_TIMEOUT, zbus::Connection::session())
                    .await
                    .map_err(|_| ())?
                    .map_err(|_| ())?,
            );
        }
        self.connection.as_ref().ok_or(())
    }

    async fn proxy(
        &mut self,
        service: &str,
        path: &str,
        interface: &str,
    ) -> Result<zbus::Proxy<'_>, ()> {
        zbus::Proxy::new(
            self.connection().await?,
            service.to_owned(),
            path.to_owned(),
            interface.to_owned(),
        )
        .await
        .map_err(|_| ())
    }
}

impl FocusCommands for QdbusCommands {
    async fn qdbus(&mut self, arguments: &[&str]) -> Result<String, CommandError> {
        qdbus(arguments).await
    }

    async fn bridge_version(&mut self, service: &str, path: &str) -> Result<u32, ()> {
        let proxy = self.proxy(service, path, BRIDGE_INTERFACE).await?;
        tokio::time::timeout(COMMAND_TIMEOUT, proxy.call("protocolVersion", &()))
            .await
            .map_err(|_| ())?
            .map_err(|_| ())
    }

    async fn bridge_capabilities(&mut self, service: &str, path: &str) -> Result<Vec<String>, ()> {
        let proxy = self.proxy(service, path, BRIDGE_INTERFACE).await?;
        tokio::time::timeout(COMMAND_TIMEOUT, proxy.call("capabilities", &()))
            .await
            .map_err(|_| ())?
            .map_err(|_| ())
    }

    async fn bridge_activate(
        &mut self,
        service: &str,
        path: &str,
        session_id: i32,
        token: &SecretString,
    ) -> Result<bool, ()> {
        let proxy = self.proxy(service, path, BRIDGE_INTERFACE).await?;
        tokio::time::timeout(
            COMMAND_TIMEOUT,
            proxy.call("activateSession", &(session_id, token.expose_secret())),
        )
        .await
        .map_err(|_| ())?
        .map_err(|_| ())
    }
}

#[allow(clippy::too_many_lines)]
async fn focus_konsole_with<C: FocusCommands, B: ActivationTokenSource>(
    target: &FocusTarget,
    proc_root: &Path,
    commands: &mut C,
    broker: &mut B,
) -> FocusResult {
    let ClientFocusTarget::Konsole(konsole) = &target.client else {
        return FocusResult::Error("invalid Konsole focus target".to_owned());
    };
    if !focus_process_matches(proc_root, target) {
        return FocusResult::NoOp("TUI process identity is stale".to_owned());
    }

    let Some(session_id) = session_id(&konsole.session_path) else {
        return FocusResult::Error("invalid Konsole session identifier".to_owned());
    };
    if !valid_service(&konsole.service) {
        return FocusResult::Error("invalid Konsole D-Bus service identifier".to_owned());
    }
    if !valid_window_path(&konsole.window_path) {
        return FocusResult::Error("invalid Konsole window identifier".to_owned());
    }

    let owner_pid = match dbus_owner_pid(commands, &konsole.service).await {
        Ok(pid) => pid,
        Err(CommandError::Unavailable) => {
            return FocusResult::Error(
                "Konsole focus is unsupported: qdbus6 is unavailable".to_owned(),
            );
        }
        Err(CommandError::Failed(_)) => {
            return FocusResult::NoOp("Konsole target is no longer available".to_owned());
        }
        Err(CommandError::Other(message)) => return FocusResult::Error(message),
    };

    if let Err(result) = validate_window_object(commands, konsole).await {
        return result;
    }
    if let Err(result) = validate_window_session(commands, konsole, session_id).await {
        return result;
    }

    if !focus_process_matches(proc_root, target) {
        return FocusResult::NoOp("TUI process identity changed before focus".to_owned());
    }
    match dbus_owner_pid(commands, &konsole.service).await {
        Ok(current) if current == owner_pid => {}
        Ok(_) | Err(CommandError::Failed(_)) => {
            return FocusResult::NoOp("Konsole owner identity changed before focus".to_owned());
        }
        Err(error) => return command_error(error),
    }
    if let Err(result) = validate_window_object(commands, konsole).await {
        return result;
    }
    if let Err(result) = validate_window_session(commands, konsole, session_id).await {
        return result;
    }
    if let Some(result) = try_bridge_activation(
        target, konsole, proc_root, commands, broker, owner_pid, session_id,
    )
    .await
    {
        return result;
    }

    if !focus_process_matches(proc_root, target) {
        return FocusResult::NoOp("TUI process identity changed before fallback focus".to_owned());
    }
    match dbus_owner_pid(commands, &konsole.service).await {
        Ok(current) if current == owner_pid => {}
        Ok(_) | Err(CommandError::Failed(_)) => {
            return FocusResult::NoOp(
                "Konsole owner identity changed before fallback focus".to_owned(),
            );
        }
        Err(error) => return command_error(error),
    }
    let window_count = match validate_window_object(commands, konsole).await {
        Ok(count) => count,
        Err(result) => return result,
    };
    if let Err(result) = validate_window_session(commands, konsole, session_id).await {
        return result;
    }
    if let Err(error) = commands
        .qdbus(&[
            &konsole.service,
            &konsole.window_path,
            "org.kde.konsole.Window.setCurrentSession",
            session_id,
        ])
        .await
    {
        return command_error(error);
    }
    if let Err(result) = validate_current_session(commands, konsole, session_id).await {
        return result;
    }
    if window_count != 1 {
        return FocusResult::TabSelected;
    }

    match dbus_owner_pid(commands, &konsole.service).await {
        Ok(current) if current == owner_pid => {}
        Ok(_) | Err(CommandError::Failed(_)) => {
            return FocusResult::NoOp("Konsole owner identity changed before focus".to_owned());
        }
        Err(error) => return command_error(error),
    }
    if !focus_process_matches(proc_root, target) {
        return FocusResult::NoOp("TUI process identity changed before activation".to_owned());
    }

    let script = match OneShotScript::create(owner_pid) {
        Ok(script) => script,
        Err(error) => {
            return FocusResult::Error(format!("could not create KWin focus script: {error}"));
        }
    };
    let script_id = match commands
        .qdbus(&[
            "org.kde.KWin",
            "/Scripting",
            "org.kde.kwin.Scripting.loadScript",
            script.path.to_string_lossy().as_ref(),
            &script.plugin,
        ])
        .await
    {
        Ok(output) => match output.trim().parse::<i32>() {
            Ok(id) if id >= 0 => id,
            _ => return FocusResult::Error("KWin rejected the focus script".to_owned()),
        },
        Err(CommandError::Failed(_)) => {
            return FocusResult::Error(
                "Konsole focus is unsupported: KWin scripting is unavailable".to_owned(),
            );
        }
        Err(error) => return command_error(error),
    };
    let script_path = format!("/Scripting/Script{script_id}");
    let run_result = commands
        .qdbus(&["org.kde.KWin", &script_path, "org.kde.kwin.Script.run"])
        .await;
    let unload_result = commands
        .qdbus(&[
            "org.kde.KWin",
            "/Scripting",
            "org.kde.kwin.Scripting.unloadScript",
            &script.plugin,
        ])
        .await;
    match run_result {
        Ok(_) => match unload_result {
            Ok(_) => FocusResult::Requested,
            Err(error) => FocusResult::Error(format!(
                "focus was requested but KWin script cleanup failed: {}",
                command_error_message(error)
            )),
        },
        Err(error) => command_error(error),
    }
}

async fn try_bridge_activation<C: FocusCommands, B: ActivationTokenSource>(
    target: &FocusTarget,
    konsole: &KonsoleTarget,
    proc_root: &Path,
    commands: &mut C,
    broker: &mut B,
    owner_pid: u32,
    session_id: &str,
) -> Option<FocusResult> {
    let bridge_path = bridge_object_path(&konsole.window_path)?;
    if commands
        .bridge_version(&konsole.service, &bridge_path)
        .await
        .ok()
        != Some(1)
    {
        return None;
    }
    let capabilities = commands
        .bridge_capabilities(&konsole.service, &bridge_path)
        .await
        .ok()?;
    if !capabilities.iter().any(|value| value == BRIDGE_CAPABILITY) {
        return None;
    }
    let token = broker.activation_token().await?;

    if !focus_process_matches(proc_root, target) {
        return Some(FocusResult::NoOp(
            "TUI process identity changed while acquiring activation token".to_owned(),
        ));
    }
    match dbus_owner_pid(commands, &konsole.service).await {
        Ok(current) if current == owner_pid => {}
        Ok(_) | Err(CommandError::Failed(_)) => {
            return Some(FocusResult::NoOp(
                "Konsole owner identity changed while acquiring activation token".to_owned(),
            ));
        }
        Err(error) => return Some(command_error(error)),
    }
    if let Err(result) = validate_window_object(commands, konsole).await {
        return Some(result);
    }
    if let Err(result) = validate_window_session(commands, konsole, session_id).await {
        return Some(result);
    }

    let session_id = session_id.parse::<i32>().ok()?;
    match commands
        .bridge_activate(&konsole.service, &bridge_path, session_id, &token)
        .await
    {
        Ok(true) => Some(FocusResult::Requested),
        Ok(false) | Err(()) => None,
    }
}

async fn validate_window_object<C: FocusCommands>(
    commands: &mut C,
    konsole: &KonsoleTarget,
) -> Result<usize, FocusResult> {
    let objects = match commands.qdbus(&[&konsole.service]).await {
        Ok(output) => output,
        Err(CommandError::Failed(_)) => {
            return Err(FocusResult::NoOp(
                "Konsole target is no longer available".to_owned(),
            ));
        }
        Err(error) => return Err(command_error(error)),
    };
    let (window_count, target_window_count) = window_object_counts(&objects, &konsole.window_path);
    match target_window_count {
        1 => Ok(window_count),
        0 => Err(FocusResult::NoOp(
            "Konsole window is no longer available".to_owned(),
        )),
        _ => Err(FocusResult::NoOp(
            "Konsole returned the target window more than once".to_owned(),
        )),
    }
}

async fn validate_window_session<C: FocusCommands>(
    commands: &mut C,
    konsole: &KonsoleTarget,
    session_id: &str,
) -> Result<(), FocusResult> {
    match commands
        .qdbus(&[
            &konsole.service,
            &konsole.window_path,
            "org.kde.konsole.Window.sessionList",
        ])
        .await
    {
        Ok(sessions) if session_list_contains(&sessions, session_id) => Ok(()),
        Ok(_) | Err(CommandError::Failed(_)) => Err(FocusResult::NoOp(
            "Konsole tab is no longer in the target window".to_owned(),
        )),
        Err(error) => Err(command_error(error)),
    }
}

async fn validate_current_session<C: FocusCommands>(
    commands: &mut C,
    konsole: &KonsoleTarget,
    session_id: &str,
) -> Result<(), FocusResult> {
    let verification = async {
        for attempt in 0..CURRENT_SESSION_VERIFY_ATTEMPTS {
            match commands
                .qdbus(&[
                    &konsole.service,
                    &konsole.window_path,
                    "org.kde.konsole.Window.currentSession",
                ])
                .await
            {
                Ok(current) if current.trim() == session_id => return Ok(true),
                Ok(_) if attempt + 1 < CURRENT_SESSION_VERIFY_ATTEMPTS => {
                    tokio::time::sleep(CURRENT_SESSION_VERIFY_INTERVAL).await;
                }
                Ok(_) | Err(CommandError::Failed(_)) => break,
                Err(error) => return Err(command_error(error)),
            }
        }

        Ok(false)
    };

    match tokio::time::timeout(CURRENT_SESSION_VERIFY_TIMEOUT, verification).await {
        Ok(Ok(true)) => Ok(()),
        Ok(Ok(false)) | Err(_) => Err(FocusResult::NoOp(
            "Konsole did not select the target tab".to_owned(),
        )),
        Ok(Err(result)) => Err(result),
    }
}

async fn dbus_owner_pid<C: FocusCommands>(
    commands: &mut C,
    service: &str,
) -> Result<u32, CommandError> {
    let output = commands
        .qdbus(&[
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus.GetConnectionUnixProcessID",
            service,
        ])
        .await?;
    output
        .trim()
        .parse::<u32>()
        .ok()
        .filter(|pid| *pid > 0)
        .ok_or_else(|| CommandError::Other("Konsole returned an invalid owner PID".to_owned()))
}

fn valid_service(service: &str) -> bool {
    service.len() <= 128
        && service.starts_with(':')
        && service[1..].split('.').count() == 2
        && service[1..]
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

fn session_id(session_path: &str) -> Option<&str> {
    (session_path.len() <= 128)
        .then(|| session_path.strip_prefix("/Sessions/"))
        .flatten()
        .filter(|id| !id.is_empty() && id.bytes().all(|byte| byte.is_ascii_digit()))
}

fn valid_window_path(window_path: &str) -> bool {
    window_path.len() <= 128
        && window_path
            .strip_prefix("/Windows/")
            .is_some_and(|id| !id.is_empty() && id.bytes().all(|byte| byte.is_ascii_digit()))
}

fn bridge_object_path(window_path: &str) -> Option<String> {
    valid_window_path(window_path)
        .then(|| format!("/org/altendky/OpenCodeBeacon/KonsoleActivationBridge/v1{window_path}"))
}

fn valid_cookie(cookie: &str) -> bool {
    let bytes = cookie.as_bytes();
    let encoded = match bytes.len() {
        43 => bytes,
        44 if bytes[43] == b'=' => &bytes[..43],
        _ => return false,
    };

    encoded[..42].iter().copied().all(is_base64_character)
        && matches!(
            encoded[42],
            b'A' | b'E'
                | b'I'
                | b'M'
                | b'Q'
                | b'U'
                | b'Y'
                | b'c'
                | b'g'
                | b'k'
                | b'o'
                | b's'
                | b'w'
                | b'0'
                | b'4'
                | b'8'
        )
}

const fn is_base64_character(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/')
}

fn valid_activation_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= MAX_ACTIVATION_TOKEN_SIZE
        && token.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

fn window_object_counts(objects: &str, target: &str) -> (usize, usize) {
    objects
        .lines()
        .filter(|line| valid_window_path(line))
        .fold((0_usize, 0_usize), |(windows, targets), window| {
            (windows + 1, targets + usize::from(window == target))
        })
}

fn session_list_contains(sessions: &str, target: &str) -> bool {
    sessions.lines().any(|id| id.trim() == target)
}

trait KittyCommands {
    async fn bridge_supported(&mut self, target: &KittyTarget) -> bool;
    async fn bridge_activate(&mut self, target: &KittyTarget, token: &SecretString) -> bool;
    async fn focus(&mut self, target: &KittyTarget) -> Result<(), CommandError>;
}

struct SystemKittyCommands;

impl KittyCommands for SystemKittyCommands {
    async fn bridge_supported(&mut self, target: &KittyTarget) -> bool {
        kitty_bridge_request(target, KittyBridgeRequest::Probe)
            .await
            .as_deref()
            == Some(KITTY_BRIDGE_PROBE_OK)
    }

    async fn bridge_activate(&mut self, target: &KittyTarget, token: &SecretString) -> bool {
        kitty_bridge_request(target, KittyBridgeRequest::Activate(token))
            .await
            .as_deref()
            == Some(KITTY_BRIDGE_ACTIVATE_OK)
    }

    async fn focus(&mut self, target: &KittyTarget) -> Result<(), CommandError> {
        kitten_focus(target).await
    }
}

async fn focus_kitty_with<C: KittyCommands, B: ActivationTokenSource>(
    focus: &FocusTarget,
    target: &KittyTarget,
    proc_root: &Path,
    commands: &mut C,
    broker: &mut B,
) -> FocusResult {
    if !focus_process_matches(proc_root, focus) {
        return FocusResult::NoOp("TUI process identity is stale".to_owned());
    }
    focus_kitty_target_with(target, commands, broker, || {
        focus_process_matches(proc_root, focus)
            && kitty_target_matches(proc_root, focus.process, target)
    })
    .await
}

async fn focus_kitty_target_with<C: KittyCommands, B: ActivationTokenSource, V: FnMut() -> bool>(
    target: &KittyTarget,
    commands: &mut C,
    broker: &mut B,
    mut target_matches: V,
) -> FocusResult {
    if !target_matches() {
        return FocusResult::NoOp("Kitty target is no longer available".to_owned());
    }
    if commands.bridge_supported(target).await
        && let Some(token) = broker.activation_token().await
    {
        if !target_matches() {
            return FocusResult::NoOp(
                "Kitty target changed while acquiring activation token".to_owned(),
            );
        }
        if commands.bridge_activate(target, &token).await {
            return FocusResult::Requested;
        }
    }
    if !target_matches() {
        return FocusResult::NoOp("Kitty target changed before fallback focus".to_owned());
    }
    focus_kitty_command_with(target, commands).await
}

async fn focus_kitty_command_with<C: KittyCommands>(
    target: &KittyTarget,
    commands: &mut C,
) -> FocusResult {
    match commands.focus(target).await {
        Ok(()) => FocusResult::KittySelected,
        Err(CommandError::Unavailable) => {
            FocusResult::Error("Kitty focus is unsupported: kitten is unavailable".to_owned())
        }
        Err(CommandError::Failed(message)) if message.contains("No matching windows") => {
            FocusResult::NoOp("Kitty window is no longer available".to_owned())
        }
        Err(CommandError::Failed(message) | CommandError::Other(message)) => {
            FocusResult::Error(message)
        }
    }
}

#[derive(Clone, Copy)]
enum KittyBridgeRequest<'a> {
    Probe,
    Activate(&'a SecretString),
    SourceProbe,
    SourceToken {
        callback_path: &'a Path,
        nonce: &'a str,
    },
}

async fn kitty_source_activation_token(proc_root: &Path) -> Option<SecretString> {
    let source_process = process_key(proc_root, std::process::id())?;
    let source = kitty_target_for_process(proc_root, source_process)?;
    request_kitty_source_activation_token(proc_root, source_process, &source).await
}

async fn request_kitty_source_activation_token(
    proc_root: &Path,
    source_process: crate::attachment::TuiKey,
    source: &KittyTarget,
) -> Option<SecretString> {
    let source_matches = || {
        process_key(proc_root, source_process.pid) == Some(source_process)
            && kitty_target_matches(proc_root, source_process, source)
    };
    if !source_matches()
        || kitty_bridge_request(source, KittyBridgeRequest::SourceProbe)
            .await
            .as_deref()
            != Some(KITTY_BRIDGE_SOURCE_OK)
    {
        return None;
    }
    let receiver = KittySourceTokenReceiver::bind(proc_root)?;
    if !source_matches()
        || kitty_bridge_request(
            source,
            KittyBridgeRequest::SourceToken {
                callback_path: &receiver.path,
                nonce: &receiver.nonce,
            },
        )
        .await
        .as_deref()
            != Some(KITTY_BRIDGE_SOURCE_REQUESTED)
    {
        return None;
    }
    let token = receiver.receive().await?;
    source_matches().then_some(token)
}

struct KittySourceTokenReceiver {
    socket: UnixDatagram,
    path: PathBuf,
    nonce: String,
}

impl KittySourceTokenReceiver {
    fn bind(proc_root: &Path) -> Option<Self> {
        let runtime = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from)?;
        let uid = fs::metadata(proc_root.join("self")).ok()?.uid();
        Self::bind_in(&runtime, uid, std::process::id())
    }

    fn bind_in(runtime: &Path, uid: u32, pid: u32) -> Option<Self> {
        let metadata = fs::symlink_metadata(runtime).ok()?;
        if !runtime.is_absolute()
            || !metadata.file_type().is_dir()
            || metadata.uid() != uid
            || metadata.mode().trailing_zeros() < 6
            || fs::canonicalize(runtime).ok().as_deref() != Some(runtime)
        {
            return None;
        }
        let mut random = [0_u8; 32];
        getrandom::fill(&mut random).ok()?;
        let nonce = hex(&random);
        let path = runtime.join(format!(
            "{KITTY_SOURCE_CALLBACK_PREFIX}{}-{}",
            pid,
            hex(&random[..12])
        ));
        if path.as_os_str().as_encoded_bytes().len() > 107 || path.exists() {
            return None;
        }
        let socket = UnixDatagram::bind(&path).ok()?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).ok()?;
        let socket_metadata = fs::symlink_metadata(&path).ok()?;
        if !socket_metadata.file_type().is_socket()
            || socket_metadata.uid() != uid
            || socket_metadata.mode() & 0o077 != 0
            || fs::canonicalize(&path).ok().as_deref() != Some(path.as_path())
        {
            let _ = fs::remove_file(&path);
            return None;
        }
        Some(Self {
            socket,
            path,
            nonce,
        })
    }

    async fn receive(&self) -> Option<SecretString> {
        tokio::time::timeout(COMMAND_TIMEOUT, async {
            let mut buffer = [0_u8; MAX_KITTY_SOURCE_DATAGRAM_SIZE];
            for _ in 0..MAX_KITTY_SOURCE_DATAGRAMS {
                let read = self.socket.recv(&mut buffer).await.ok()?;
                if read == buffer.len() {
                    continue;
                }
                let Ok(response) = serde_json::from_slice::<serde_json::Value>(&buffer[..read])
                else {
                    continue;
                };
                let Some(object) = response.as_object() else {
                    continue;
                };
                if object.len() != 3
                    || object.get("version").and_then(serde_json::Value::as_u64) != Some(2)
                    || object.get("nonce").and_then(serde_json::Value::as_str)
                        != Some(self.nonce.as_str())
                {
                    continue;
                }
                let Some(token) = object.get("token").and_then(serde_json::Value::as_str) else {
                    continue;
                };
                if valid_activation_token(token) {
                    return Some(SecretString::from(token.to_owned()));
                }
            }
            None
        })
        .await
        .ok()?
    }
}

impl Drop for KittySourceTokenReceiver {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(char::from(DIGITS[usize::from(byte >> 4)]));
        result.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    result
}

async fn kitty_bridge_request(
    target: &KittyTarget,
    request: KittyBridgeRequest<'_>,
) -> Option<String> {
    let framed = encode_kitty_bridge_request(target, request)?;
    let response = tokio::time::timeout(COMMAND_TIMEOUT, async {
        let mut stream = UnixStream::connect(&target.socket_path).await.ok()?;
        stream.write_all(&framed).await.ok()?;
        stream.shutdown().await.ok()?;
        let mut response = Vec::new();
        let mut chunk = [0_u8; 4096];
        loop {
            let read = stream.read(&mut chunk).await.ok()?;
            if read == 0 {
                break;
            }
            if response.len().saturating_add(read) > MAX_COMMAND_OUTPUT {
                return None;
            }
            response.extend_from_slice(&chunk[..read]);
            if response.ends_with(KITTY_COMMAND_SUFFIX) {
                break;
            }
        }
        Some(response)
    })
    .await
    .ok()??;
    parse_kitty_bridge_response(&response)
}

fn encode_kitty_bridge_request(
    target: &KittyTarget,
    request: KittyBridgeRequest<'_>,
) -> Option<Vec<u8>> {
    let window_id = target.window_id.to_string();
    let args = match request {
        KittyBridgeRequest::Probe => {
            vec![
                "probe-target",
                KITTY_BRIDGE_PROTOCOL_VERSION,
                window_id.as_str(),
            ]
        }
        KittyBridgeRequest::Activate(token) => vec![
            "activate",
            KITTY_BRIDGE_PROTOCOL_VERSION,
            window_id.as_str(),
            token.expose_secret(),
        ],
        KittyBridgeRequest::SourceProbe => vec![
            "probe-source",
            KITTY_BRIDGE_PROTOCOL_VERSION,
            window_id.as_str(),
        ],
        KittyBridgeRequest::SourceToken {
            callback_path,
            nonce,
        } => vec![
            "source-token",
            KITTY_BRIDGE_PROTOCOL_VERSION,
            window_id.as_str(),
            callback_path.to_str()?,
            nonce,
        ],
    };
    let command = serde_json::json!({
        "cmd": "kitten",
        "version": [0, 45, 0],
        "no_response": false,
        "payload": {
            "kitten": KITTY_BRIDGE_KITTEN,
            "args": args,
            "match": format!("id:{window_id}"),
        },
    });
    let encoded = serde_json::to_vec(&command).ok()?;
    if encoded.len() > MAX_COMMAND_OUTPUT {
        return None;
    }
    let mut framed =
        Vec::with_capacity(KITTY_COMMAND_PREFIX.len() + encoded.len() + KITTY_COMMAND_SUFFIX.len());
    framed.extend_from_slice(KITTY_COMMAND_PREFIX);
    framed.extend_from_slice(&encoded);
    framed.extend_from_slice(KITTY_COMMAND_SUFFIX);
    Some(framed)
}

fn parse_kitty_bridge_response(response: &[u8]) -> Option<String> {
    let payload = response
        .strip_prefix(KITTY_COMMAND_PREFIX)?
        .strip_suffix(KITTY_COMMAND_SUFFIX)?;
    let response = serde_json::from_slice::<serde_json::Value>(payload).ok()?;
    response.get("ok")?.as_bool()?.then_some(())?;
    response.get("data")?.as_str().map(ToOwned::to_owned)
}

fn kitty_arguments(target: &KittyTarget) -> Option<Vec<OsString>> {
    let socket = target.socket_path.to_str()?;
    Some(vec![
        OsString::from("@"),
        OsString::from("--to"),
        OsString::from(format!("unix:{socket}")),
        OsString::from("--use-password=never"),
        OsString::from("focus-window"),
        OsString::from("--match"),
        OsString::from(format!("id:{}", target.window_id)),
    ])
}

async fn kitten_focus(target: &KittyTarget) -> Result<(), CommandError> {
    let arguments = kitty_arguments(target)
        .ok_or_else(|| CommandError::Other("Kitty socket path is not UTF-8".to_owned()))?;
    let mut command = Command::new("kitten");
    command
        .args(arguments)
        .env_remove("KITTY_LISTEN_ON")
        .env_remove("KITTY_PUBLIC_KEY")
        .env_remove("KITTY_RC_PASSWORD")
        .env_remove("KITTY_WINDOW_ID")
        .stdin(Stdio::null())
        .kill_on_drop(true);
    let output = match tokio::time::timeout(COMMAND_TIMEOUT, command.output()).await {
        Ok(Ok(output)) => output,
        Ok(Err(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(CommandError::Unavailable);
        }
        Ok(Err(error)) => {
            return Err(CommandError::Other(format!(
                "could not run kitten focus command: {error}"
            )));
        }
        Err(_) => {
            return Err(CommandError::Other(
                "kitten focus command timed out".to_owned(),
            ));
        }
    };
    if output.stdout.len() > MAX_COMMAND_OUTPUT || output.stderr.len() > MAX_COMMAND_OUTPUT {
        return Err(CommandError::Other(
            "kitten output exceeded the safety limit".to_owned(),
        ));
    }
    if !output.status.success() {
        let message = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Err(CommandError::Failed(if message.is_empty() {
            format!("kitten focus command exited with {}", output.status)
        } else {
            format!("kitten focus command failed: {message}")
        }));
    }
    Ok(())
}

enum CommandError {
    Unavailable,
    Failed(String),
    Other(String),
}

fn command_error(error: CommandError) -> FocusResult {
    FocusResult::Error(command_error_message(error))
}

fn command_error_message(error: CommandError) -> String {
    match error {
        CommandError::Unavailable => {
            "Konsole focus is unsupported: qdbus6 is unavailable".to_owned()
        }
        CommandError::Failed(message) | CommandError::Other(message) => message,
    }
}

async fn qdbus(arguments: &[&str]) -> Result<String, CommandError> {
    let mut command = Command::new("qdbus6");
    command
        .args(arguments)
        .stdin(Stdio::null())
        .kill_on_drop(true);
    let output = match tokio::time::timeout(COMMAND_TIMEOUT, command.output()).await {
        Ok(Ok(output)) => output,
        Ok(Err(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(CommandError::Unavailable);
        }
        Ok(Err(error)) => return Err(CommandError::Other(format!("qdbus6 failed: {error}"))),
        Err(_) => return Err(CommandError::Other("qdbus6 timed out".to_owned())),
    };
    if output.stdout.len() > MAX_COMMAND_OUTPUT || output.stderr.len() > MAX_COMMAND_OUTPUT {
        return Err(CommandError::Other(
            "qdbus6 output exceeded the safety limit".to_owned(),
        ));
    }
    if !output.status.success() {
        let message = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Err(CommandError::Failed(if message.is_empty() {
            format!("qdbus6 exited with {}", output.status)
        } else {
            format!("qdbus6 failed: {message}")
        }));
    }
    String::from_utf8(output.stdout)
        .map_err(|_| CommandError::Other("qdbus6 returned non-UTF-8 output".to_owned()))
}

struct OneShotScript {
    path: PathBuf,
    plugin: String,
}

impl OneShotScript {
    fn create(pid: u32) -> std::io::Result<Self> {
        let plugin = format!(
            "opencode-beacon-focus-{}-{}",
            std::process::id(),
            fastrand::u64(..)
        );
        let path = std::env::temp_dir().join(format!("{plugin}.js"));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        let script = Self { path, plugin };
        let source = KWIN_SCRIPT_TEMPLATE.replace(KWIN_PID_TOKEN, &pid.to_string());
        file.write_all(source.as_bytes())?;
        Ok(script)
    }
}

impl Drop for OneShotScript {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::os::unix::fs::MetadataExt;

    use super::*;
    use crate::attachment::{FocusProcessSource, KonsoleTarget, TuiKey};

    #[derive(Default)]
    struct MockCommands {
        calls: Vec<Vec<String>>,
        responses: VecDeque<Result<String, CommandError>>,
        operations: Vec<&'static str>,
        bridge_version: Option<Result<u32, ()>>,
        bridge_capabilities: Option<Result<Vec<String>, ()>>,
        activation: Option<Result<bool, ()>>,
        hang_qdbus: bool,
    }

    impl FocusCommands for MockCommands {
        async fn qdbus(&mut self, arguments: &[&str]) -> Result<String, CommandError> {
            self.operations.push(match arguments {
                [_, _, "org.freedesktop.DBus.GetConnectionUnixProcessID", _] => "owner",
                [_] => "windows",
                [_, _, "org.kde.konsole.Window.sessionList"] => "membership",
                [_, _, "org.kde.konsole.Window.setCurrentSession", _] => "fallback-select",
                [_, _, "org.kde.konsole.Window.currentSession"] => "fallback-verify",
                _ => "qdbus",
            });
            self.calls
                .push(arguments.iter().map(|value| (*value).to_owned()).collect());
            if self.hang_qdbus {
                return std::future::pending().await;
            }
            self.responses
                .pop_front()
                .unwrap_or_else(|| unreachable!("unexpected qdbus call: {arguments:?}"))
        }

        async fn bridge_version(&mut self, _service: &str, _path: &str) -> Result<u32, ()> {
            self.operations.push("version");
            self.bridge_version.take().unwrap_or(Err(()))
        }

        async fn bridge_capabilities(
            &mut self,
            _service: &str,
            _path: &str,
        ) -> Result<Vec<String>, ()> {
            self.operations.push("capabilities");
            self.bridge_capabilities.take().unwrap_or(Err(()))
        }

        async fn bridge_activate(
            &mut self,
            _service: &str,
            _path: &str,
            _session_id: i32,
            _token: &SecretString,
        ) -> Result<bool, ()> {
            self.operations.push("activate");
            self.activation.take().unwrap_or(Err(()))
        }
    }

    #[derive(Default)]
    struct MockKittyCommands {
        calls: Vec<KittyTarget>,
        result: Option<Result<(), CommandError>>,
        bridge_supported: bool,
        activation: bool,
        operations: Vec<&'static str>,
    }

    impl KittyCommands for MockKittyCommands {
        async fn bridge_supported(&mut self, _target: &KittyTarget) -> bool {
            self.operations.push("probe");
            self.bridge_supported
        }

        async fn bridge_activate(&mut self, _target: &KittyTarget, _token: &SecretString) -> bool {
            self.operations.push("activate");
            self.activation
        }

        async fn focus(&mut self, target: &KittyTarget) -> Result<(), CommandError> {
            self.operations.push("fallback");
            self.calls.push(target.clone());
            self.result
                .take()
                .unwrap_or_else(|| unreachable!("unexpected Kitty focus call"))
        }
    }

    #[derive(Default)]
    struct MockBroker {
        token: Option<SecretString>,
        requests: usize,
    }

    impl ActivationTokenSource for MockBroker {
        async fn activation_token(&mut self) -> Option<SecretString> {
            self.requests += 1;
            self.token.take()
        }
    }

    fn kitty_target() -> KittyTarget {
        KittyTarget {
            process: TuiKey {
                pid: 500,
                start_time: 80,
            },
            window_id: 77,
            socket_path: PathBuf::from("/run/user/1000/kitty beacon.sock"),
            socket_device: 1,
            socket_inode: 2,
        }
    }

    #[test]
    fn dbus_service_validation_accepts_only_unique_names() {
        assert!(valid_service(":1.108"));
        for value in ["org.kde.konsole", ":1", ":1.two", ":1.2.extra", ":1.2;bad"] {
            assert!(!valid_service(value));
        }
    }

    #[test]
    fn window_validation_accepts_only_bounded_numeric_paths() {
        assert!(valid_window_path("/Windows/11"));
        for value in ["Windows/1", "/Windows/", "/Windows/one", "/Windows/1/2"] {
            assert!(!valid_window_path(value));
        }
        assert!(!valid_window_path(&format!("/Windows/{}", "1".repeat(129))));
    }

    #[test]
    fn session_validation_accepts_only_bounded_numeric_paths() {
        assert_eq!(session_id("/Sessions/4"), Some("4"));
        for value in ["Sessions/1", "/Sessions/", "/Sessions/one", "/Sessions/1/2"] {
            assert!(session_id(value).is_none());
        }
        assert!(session_id(&format!("/Sessions/{}", "1".repeat(129))).is_none());
    }

    #[test]
    fn exact_window_and_session_matching_do_not_depend_on_uniqueness_or_substrings() {
        let objects = "/\n/Windows/1\n/Sessions/4\n/Windows/11\n";
        assert_eq!(window_object_counts(objects, "/Windows/11"), (2, 1));
        assert_eq!(window_object_counts(objects, "/Windows/2"), (2, 0));
        assert!(session_list_contains("1\n4\n14\n", "4"));
        assert!(!session_list_contains("1\n14\n", "4"));
    }

    #[test]
    fn kitty_focus_arguments_are_fixed_and_disable_ambient_passwords() {
        assert_eq!(
            kitty_arguments(&kitty_target()),
            Some(vec![
                OsString::from("@"),
                OsString::from("--to"),
                OsString::from("unix:/run/user/1000/kitty beacon.sock"),
                OsString::from("--use-password=never"),
                OsString::from("focus-window"),
                OsString::from("--match"),
                OsString::from("id:77"),
            ])
        );
    }

    #[test]
    fn kitty_bridge_protocol_is_fixed_bounded_and_token_safe_for_debug() {
        let target = kitty_target();
        let token = SecretString::from("fresh-token".to_owned());
        let encoded = encode_kitty_bridge_request(&target, KittyBridgeRequest::Activate(&token))
            .unwrap_or_else(|| unreachable!("valid bridge request"));
        let payload = encoded
            .strip_prefix(KITTY_COMMAND_PREFIX)
            .and_then(|value| value.strip_suffix(KITTY_COMMAND_SUFFIX))
            .unwrap_or_else(|| unreachable!("fixed Kitty framing"));
        let command = serde_json::from_slice::<serde_json::Value>(payload)
            .unwrap_or_else(|error| unreachable!("valid bridge JSON: {error}"));
        assert_eq!(command["cmd"], "kitten");
        assert_eq!(command["version"], serde_json::json!([0, 45, 0]));
        assert_eq!(command["payload"]["kitten"], KITTY_BRIDGE_KITTEN);
        assert_eq!(
            command["payload"]["args"],
            serde_json::json!(["activate", "2", "77", "fresh-token"])
        );
        assert_eq!(command["payload"]["match"], "id:77");
        assert!(!format!("{token:?}").contains("fresh-token"));

        let response = format!(
            "{}{{\"ok\":true,\"data\":\"{KITTY_BRIDGE_ACTIVATE_OK}\"}}{}",
            String::from_utf8_lossy(KITTY_COMMAND_PREFIX),
            String::from_utf8_lossy(KITTY_COMMAND_SUFFIX)
        );
        assert_eq!(
            parse_kitty_bridge_response(response.as_bytes()).as_deref(),
            Some(KITTY_BRIDGE_ACTIVATE_OK)
        );
        assert!(parse_kitty_bridge_response(b"{\"ok\":true}").is_none());
        assert!(
            parse_kitty_bridge_response(
                b"\x1bP@kitty-cmd{\"ok\":false,\"data\":\"ignored\"}\x1b\\"
            )
            .is_none()
        );

        let callback = Path::new("/run/user/1000/beacon-callback.sock");
        let source = encode_kitty_bridge_request(
            &target,
            KittyBridgeRequest::SourceToken {
                callback_path: callback,
                nonce: &"a".repeat(64),
            },
        )
        .unwrap_or_else(|| unreachable!("valid source request"));
        let payload = source
            .strip_prefix(KITTY_COMMAND_PREFIX)
            .and_then(|value| value.strip_suffix(KITTY_COMMAND_SUFFIX))
            .unwrap_or_else(|| unreachable!("fixed source framing"));
        let command = serde_json::from_slice::<serde_json::Value>(payload)
            .unwrap_or_else(|error| unreachable!("valid source JSON: {error}"));
        assert_eq!(
            command["payload"]["args"],
            serde_json::json!([
                "source-token",
                "2",
                "77",
                "/run/user/1000/beacon-callback.sock",
                "a".repeat(64)
            ])
        );
    }

    #[tokio::test]
    async fn kitty_source_callback_is_private_nonce_bound_bounded_and_one_shot() {
        let directory = tempfile::tempdir()
            .unwrap_or_else(|error| unreachable!("temporary directory: {error}"));
        assert!(fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).is_ok());
        let uid = fs::metadata(directory.path())
            .unwrap_or_else(|error| unreachable!("runtime metadata: {error}"))
            .uid();
        let receiver = KittySourceTokenReceiver::bind_in(directory.path(), uid, 123)
            .unwrap_or_else(|| unreachable!("private callback receiver"));
        let callback_path = receiver.path.clone();
        let sender = UnixDatagram::unbound()
            .unwrap_or_else(|error| unreachable!("unbound callback sender: {error}"));
        sender
            .send_to(b"not-json", &callback_path)
            .await
            .unwrap_or_else(|error| unreachable!("send malformed callback: {error}"));
        sender
            .send_to(
                serde_json::json!({
                    "version": 2,
                    "nonce": "b".repeat(64),
                    "token": "spoofed-token",
                })
                .to_string()
                .as_bytes(),
                &callback_path,
            )
            .await
            .unwrap_or_else(|error| unreachable!("send spoofed callback: {error}"));
        let oversized = [b'x'; MAX_KITTY_SOURCE_DATAGRAM_SIZE];
        sender
            .send_to(&oversized, &callback_path)
            .await
            .unwrap_or_else(|error| unreachable!("send oversized callback: {error}"));
        sender
            .send_to(
                serde_json::json!({
                    "version": 2,
                    "nonce": receiver.nonce.as_str(),
                    "token": "fresh-token",
                })
                .to_string()
                .as_bytes(),
                &callback_path,
            )
            .await
            .unwrap_or_else(|error| unreachable!("send valid callback: {error}"));

        let token = receiver
            .receive()
            .await
            .unwrap_or_else(|| unreachable!("valid nonce-bound token"));
        assert_eq!(token.expose_secret(), "fresh-token");
        assert!(!format!("{token:?}").contains("fresh-token"));
        drop(receiver);
        assert!(!callback_path.exists());

        assert!(fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755)).is_ok());
        assert!(KittySourceTokenReceiver::bind_in(directory.path(), uid, 123).is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn kitty_source_callback_timeout_is_bounded_and_cleanup_is_owned() {
        let directory = tempfile::tempdir()
            .unwrap_or_else(|error| unreachable!("temporary directory: {error}"));
        assert!(fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).is_ok());
        let uid = fs::metadata(directory.path())
            .unwrap_or_else(|error| unreachable!("runtime metadata: {error}"))
            .uid();
        let receiver = KittySourceTokenReceiver::bind_in(directory.path(), uid, 123)
            .unwrap_or_else(|| unreachable!("private callback receiver"));
        let callback_path = receiver.path.clone();
        let started = tokio::time::Instant::now();

        assert!(receiver.receive().await.is_none());
        assert_eq!(started.elapsed(), COMMAND_TIMEOUT);
        assert!(callback_path.exists());
        drop(receiver);
        assert!(!callback_path.exists());
    }

    #[tokio::test]
    async fn activation_broker_prefers_active_kitty_then_falls_back_to_konsole() {
        let mut broker = ActivationTokenBroker {
            kitty: MockBroker {
                token: Some(SecretString::from("kitty-token".to_owned())),
                ..MockBroker::default()
            },
            konsole: MockBroker {
                token: Some(SecretString::from("konsole-token".to_owned())),
                ..MockBroker::default()
            },
        };
        let token = broker
            .activation_token()
            .await
            .unwrap_or_else(|| unreachable!("Kitty source token"));
        assert_eq!(token.expose_secret(), "kitty-token");
        assert_eq!(broker.kitty.requests, 1);
        assert_eq!(broker.konsole.requests, 0);

        let mut broker = ActivationTokenBroker {
            kitty: MockBroker::default(),
            konsole: MockBroker {
                token: Some(SecretString::from("konsole-token".to_owned())),
                ..MockBroker::default()
            },
        };
        let token = broker
            .activation_token()
            .await
            .unwrap_or_else(|| unreachable!("Konsole fallback token"));
        assert_eq!(token.expose_secret(), "konsole-token");
        assert_eq!(broker.kitty.requests, 1);
        assert_eq!(broker.konsole.requests, 1);
    }

    #[tokio::test]
    async fn kitty_bridge_uses_direct_socket_payload_and_bounded_response() {
        let directory = tempfile::tempdir()
            .unwrap_or_else(|error| unreachable!("temporary directory: {error}"));
        let socket_path = directory.path().join("kitty.sock");
        let listener = tokio::net::UnixListener::bind(&socket_path)
            .unwrap_or_else(|error| unreachable!("bind Kitty test socket: {error}"));
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener
                .accept()
                .await
                .unwrap_or_else(|error| unreachable!("accept bridge request: {error}"));
            let mut request = Vec::new();
            stream
                .read_to_end(&mut request)
                .await
                .unwrap_or_else(|error| unreachable!("read bridge request: {error}"));
            let payload = request
                .strip_prefix(KITTY_COMMAND_PREFIX)
                .and_then(|value| value.strip_suffix(KITTY_COMMAND_SUFFIX))
                .unwrap_or_else(|| unreachable!("fixed request framing"));
            let command = serde_json::from_slice::<serde_json::Value>(payload)
                .unwrap_or_else(|error| unreachable!("valid request JSON: {error}"));
            assert_eq!(command["payload"]["match"], "id:77");
            assert_eq!(
                command["payload"]["args"],
                serde_json::json!(["probe-target", "2", "77"])
            );
            let response = format!(
                "{}{{\"ok\":true,\"data\":\"{KITTY_BRIDGE_PROBE_OK}\"}}{}",
                String::from_utf8_lossy(KITTY_COMMAND_PREFIX),
                String::from_utf8_lossy(KITTY_COMMAND_SUFFIX)
            );
            stream
                .write_all(response.as_bytes())
                .await
                .unwrap_or_else(|error| unreachable!("write bridge response: {error}"));
        });
        let mut target = kitty_target();
        target.socket_path = socket_path;

        assert_eq!(
            kitty_bridge_request(&target, KittyBridgeRequest::Probe)
                .await
                .as_deref(),
            Some(KITTY_BRIDGE_PROBE_OK)
        );
        server
            .await
            .unwrap_or_else(|error| unreachable!("bridge server task: {error}"));
    }

    #[tokio::test]
    async fn kitty_bridge_negotiates_before_token_revalidates_and_activates() {
        let target = kitty_target();
        let mut commands = MockKittyCommands {
            bridge_supported: true,
            activation: true,
            ..MockKittyCommands::default()
        };
        let mut broker = MockBroker {
            token: Some(SecretString::from("fresh-token".to_owned())),
            ..MockBroker::default()
        };
        let mut validations = [true, true].into_iter();

        assert_eq!(
            focus_kitty_target_with(&target, &mut commands, &mut broker, || {
                validations.next().unwrap_or(false)
            })
            .await,
            FocusResult::Requested
        );
        assert_eq!(commands.operations, ["probe", "activate"]);
        assert_eq!(broker.requests, 1);
        assert!(commands.calls.is_empty());
    }

    #[tokio::test]
    async fn kitty_bridge_unavailable_or_failed_preserves_partial_fallback() {
        let target = kitty_target();
        let mut unavailable = MockKittyCommands {
            result: Some(Ok(())),
            ..MockKittyCommands::default()
        };
        let mut broker = MockBroker::default();
        assert_eq!(
            focus_kitty_target_with(&target, &mut unavailable, &mut broker, || true).await,
            FocusResult::KittySelected
        );
        assert_eq!(unavailable.operations, ["probe", "fallback"]);
        assert_eq!(broker.requests, 0);

        let mut failed = MockKittyCommands {
            result: Some(Ok(())),
            bridge_supported: true,
            ..MockKittyCommands::default()
        };
        let mut broker = MockBroker {
            token: Some(SecretString::from("fresh-token".to_owned())),
            ..MockBroker::default()
        };
        assert_eq!(
            focus_kitty_target_with(&target, &mut failed, &mut broker, || true).await,
            FocusResult::KittySelected
        );
        assert_eq!(failed.operations, ["probe", "activate", "fallback"]);
        assert_eq!(broker.requests, 1);
    }

    #[tokio::test]
    async fn kitty_bridge_rejects_target_change_after_token_without_fallback() {
        let target = kitty_target();
        let mut commands = MockKittyCommands {
            bridge_supported: true,
            activation: true,
            ..MockKittyCommands::default()
        };
        let mut broker = MockBroker {
            token: Some(SecretString::from("fresh-token".to_owned())),
            ..MockBroker::default()
        };
        let mut validations = [true, false].into_iter();

        assert_eq!(
            focus_kitty_target_with(&target, &mut commands, &mut broker, || {
                validations.next().unwrap_or(false)
            })
            .await,
            FocusResult::NoOp("Kitty target changed while acquiring activation token".to_owned())
        );
        assert_eq!(commands.operations, ["probe"]);
        assert_eq!(broker.requests, 1);
        assert!(commands.calls.is_empty());
    }

    #[tokio::test]
    async fn kitty_focus_maps_success_unavailable_no_match_and_other_failures() {
        let target = kitty_target();
        for (response, expected) in [
            (Ok(()), FocusResult::KittySelected),
            (
                Err(CommandError::Unavailable),
                FocusResult::Error("Kitty focus is unsupported: kitten is unavailable".to_owned()),
            ),
            (
                Err(CommandError::Failed(
                    "No matching windows for expression: id:77".to_owned(),
                )),
                FocusResult::NoOp("Kitty window is no longer available".to_owned()),
            ),
            (
                Err(CommandError::Failed(
                    "remote control is disabled".to_owned(),
                )),
                FocusResult::Error("remote control is disabled".to_owned()),
            ),
        ] {
            let mut commands = MockKittyCommands {
                calls: Vec::new(),
                result: Some(response),
                ..MockKittyCommands::default()
            };
            assert_eq!(
                focus_kitty_command_with(&target, &mut commands).await,
                expected
            );
            assert_eq!(commands.calls.as_slice(), std::slice::from_ref(&target));
        }
    }

    #[tokio::test]
    async fn kitty_focus_rejects_stale_tui_before_running_client() {
        let directory = tempfile::tempdir()
            .unwrap_or_else(|error| unreachable!("temporary directory: {error}"));
        let mut commands = MockKittyCommands {
            calls: Vec::new(),
            result: Some(Ok(())),
            ..MockKittyCommands::default()
        };
        let focus = FocusTarget {
            process: TuiKey {
                pid: 123,
                start_time: 100,
            },
            source: FocusProcessSource::OpenCode,
            client: ClientFocusTarget::Kitty(kitty_target()),
        };
        let ClientFocusTarget::Kitty(kitty) = &focus.client else {
            unreachable!("test target is Kitty");
        };
        let mut broker = MockBroker::default();
        assert_eq!(
            focus_kitty_with(&focus, kitty, directory.path(), &mut commands, &mut broker,).await,
            FocusResult::NoOp("TUI process identity is stale".to_owned())
        );
        assert!(commands.calls.is_empty());
    }

    #[tokio::test]
    async fn claude_focus_revalidates_pid_starttime_and_identifiers_before_commands() {
        let directory = tempfile::tempdir()
            .unwrap_or_else(|error| unreachable!("temporary directory: {error}"));
        let proc_root = directory.path().join("proc");
        let self_process = proc_root.join("self");
        let process = proc_root.join("123");
        assert!(fs::create_dir_all(&self_process).is_ok());
        assert!(fs::create_dir_all(&process).is_ok());
        let uid = fs::metadata(directory.path())
            .unwrap_or_else(|error| unreachable!("metadata: {error}"))
            .uid();
        let status = format!("Uid:\t{uid}\t{uid}\t{uid}\t{uid}\n");
        assert!(fs::write(self_process.join("status"), &status).is_ok());
        assert!(fs::write(process.join("status"), status).is_ok());
        assert!(fs::write(process.join("cmdline"), b"claude\0").is_ok());
        assert!(fs::write(
            process.join("environ"),
            b"KONSOLE_DBUS_SERVICE=:1.108\0KONSOLE_DBUS_SESSION=/Sessions/7\0KONSOLE_DBUS_WINDOW=/Windows/11\0"
        ).is_ok());
        let stat = |start_time| {
            format!(
                "123 (claude) S 1 0 0 7 {} {start_time}\n",
                vec!["0"; 14].join(" ")
            )
        };
        assert!(fs::write(process.join("stat"), stat(100)).is_ok());
        let konsole = FocusTarget {
            process: TuiKey {
                pid: 123,
                start_time: 100,
            },
            source: FocusProcessSource::Claude,
            client: ClientFocusTarget::Konsole(KonsoleTarget {
                service: ":1.108".to_owned(),
                session_path: "/Sessions/7".to_owned(),
                window_path: "/Windows/11".to_owned(),
            }),
        };
        assert!(focus_process_matches(&proc_root, &konsole));

        assert!(fs::write(process.join("stat"), stat(101)).is_ok());
        let mut commands = MockCommands::default();
        let mut broker = MockBroker::default();
        assert_eq!(
            focus_konsole_with(&konsole, &proc_root, &mut commands, &mut broker).await,
            FocusResult::NoOp("TUI process identity is stale".to_owned())
        );
        assert!(commands.operations.is_empty());

        assert!(fs::write(process.join("stat"), stat(100)).is_ok());
        assert!(fs::write(
            process.join("environ"),
            b"KONSOLE_DBUS_SERVICE=:1.108\0KONSOLE_DBUS_SESSION=/Sessions/8\0KONSOLE_DBUS_WINDOW=/Windows/11\0"
        ).is_ok());
        let mut commands = MockCommands::default();
        let mut broker = MockBroker::default();
        assert_eq!(
            focus_konsole_with(&konsole, &proc_root, &mut commands, &mut broker).await,
            FocusResult::NoOp("TUI process identity is stale".to_owned())
        );
        assert!(commands.operations.is_empty());

        let kitty = kitty_target();
        let kitty_focus = FocusTarget {
            process: konsole.process,
            source: FocusProcessSource::Claude,
            client: ClientFocusTarget::Kitty(kitty.clone()),
        };
        let mut kitty_commands = MockKittyCommands {
            result: Some(Ok(())),
            ..MockKittyCommands::default()
        };
        let mut broker = MockBroker::default();
        assert_eq!(
            focus_kitty_with(
                &kitty_focus,
                &kitty,
                &proc_root,
                &mut kitty_commands,
                &mut broker,
            )
            .await,
            FocusResult::NoOp("TUI process identity is stale".to_owned())
        );
        assert!(kitty_commands.calls.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn current_session_verification_waits_for_delayed_selection() {
        let target = KonsoleTarget {
            service: ":1.108".to_owned(),
            session_path: "/Sessions/7".to_owned(),
            window_path: "/Windows/11".to_owned(),
        };
        let mut commands = MockCommands {
            responses: VecDeque::from([
                Ok("4\n".to_owned()),
                Ok("4\n".to_owned()),
                Ok("7\n".to_owned()),
            ]),
            ..MockCommands::default()
        };

        assert_eq!(
            validate_current_session(&mut commands, &target, "7").await,
            Ok(())
        );
        assert_eq!(
            commands.operations,
            ["fallback-verify", "fallback-verify", "fallback-verify"]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn current_session_verification_is_bounded_when_selection_never_converges() {
        let target = KonsoleTarget {
            service: ":1.108".to_owned(),
            session_path: "/Sessions/7".to_owned(),
            window_path: "/Windows/11".to_owned(),
        };
        let mut commands = MockCommands {
            responses: VecDeque::from([
                Ok("4\n".to_owned()),
                Ok("4\n".to_owned()),
                Ok("4\n".to_owned()),
                Ok("4\n".to_owned()),
                Ok("4\n".to_owned()),
                Ok("4\n".to_owned()),
            ]),
            ..MockCommands::default()
        };

        assert_eq!(
            validate_current_session(&mut commands, &target, "7").await,
            Err(FocusResult::NoOp(
                "Konsole did not select the target tab".to_owned()
            ))
        );
        assert_eq!(commands.operations.len(), CURRENT_SESSION_VERIFY_ATTEMPTS);
    }

    #[tokio::test(start_paused = true)]
    async fn current_session_verification_times_out_a_hanging_qdbus_call() {
        let target = KonsoleTarget {
            service: ":1.108".to_owned(),
            session_path: "/Sessions/7".to_owned(),
            window_path: "/Windows/11".to_owned(),
        };
        let mut commands = MockCommands {
            hang_qdbus: true,
            ..MockCommands::default()
        };
        let started = tokio::time::Instant::now();

        assert_eq!(
            validate_current_session(&mut commands, &target, "7").await,
            Err(FocusResult::NoOp(
                "Konsole did not select the target tab".to_owned()
            ))
        );
        assert_eq!(started.elapsed(), CURRENT_SESSION_VERIFY_TIMEOUT);
        assert_eq!(commands.operations, ["fallback-verify"]);
        assert_eq!(commands.calls.len(), 1);
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn multi_window_selects_exact_tab_without_invoking_kwin() {
        let directory = tempfile::tempdir()
            .unwrap_or_else(|error| unreachable!("temporary directory: {error}"));
        let process = directory.path().join("123");
        assert!(fs::create_dir(&process).is_ok());
        assert!(
            fs::write(
                process.join("stat"),
                format!("123 (opencode) S 1 0 0 7 {} 100\n", vec!["0"; 14].join(" "))
            )
            .is_ok()
        );
        let target = FocusTarget {
            process: TuiKey {
                pid: 123,
                start_time: 100,
            },
            source: FocusProcessSource::OpenCode,
            client: ClientFocusTarget::Konsole(KonsoleTarget {
                service: ":1.108".to_owned(),
                session_path: "/Sessions/7".to_owned(),
                window_path: "/Windows/11".to_owned(),
            }),
        };
        let mut commands = MockCommands {
            calls: Vec::new(),
            responses: VecDeque::from([
                Ok("500\n".to_owned()),
                Ok("/\n/Windows/1\n/Windows/11\n".to_owned()),
                Ok("4\n5\n7\n".to_owned()),
                Ok("500\n".to_owned()),
                Ok("/\n/Windows/1\n/Windows/11\n".to_owned()),
                Ok("4\n5\n7\n".to_owned()),
                Ok("500\n".to_owned()),
                Ok("/\n/Windows/1\n/Windows/11\n".to_owned()),
                Ok("4\n5\n7\n".to_owned()),
                Ok(String::new()),
                Ok("7\n".to_owned()),
            ]),
            ..MockCommands::default()
        };
        let mut broker = MockBroker::default();

        assert_eq!(
            focus_konsole_with(&target, directory.path(), &mut commands, &mut broker).await,
            FocusResult::TabSelected
        );
        assert_eq!(
            commands.calls,
            vec![
                vec![
                    "org.freedesktop.DBus",
                    "/org/freedesktop/DBus",
                    "org.freedesktop.DBus.GetConnectionUnixProcessID",
                    ":1.108",
                ],
                vec![":1.108"],
                vec![
                    ":1.108",
                    "/Windows/11",
                    "org.kde.konsole.Window.sessionList",
                ],
                vec![
                    "org.freedesktop.DBus",
                    "/org/freedesktop/DBus",
                    "org.freedesktop.DBus.GetConnectionUnixProcessID",
                    ":1.108",
                ],
                vec![":1.108"],
                vec![
                    ":1.108",
                    "/Windows/11",
                    "org.kde.konsole.Window.sessionList",
                ],
                vec![
                    "org.freedesktop.DBus",
                    "/org/freedesktop/DBus",
                    "org.freedesktop.DBus.GetConnectionUnixProcessID",
                    ":1.108",
                ],
                vec![":1.108"],
                vec![
                    ":1.108",
                    "/Windows/11",
                    "org.kde.konsole.Window.sessionList",
                ],
                vec![
                    ":1.108",
                    "/Windows/11",
                    "org.kde.konsole.Window.setCurrentSession",
                    "7",
                ],
                vec![
                    ":1.108",
                    "/Windows/11",
                    "org.kde.konsole.Window.currentSession",
                ],
            ]
        );
        assert!(commands.calls.iter().all(|arguments| {
            arguments
                .first()
                .is_none_or(|value| value != "org.kde.KWin")
        }));
        assert_eq!(
            commands.operations,
            [
                "owner",
                "windows",
                "membership",
                "owner",
                "windows",
                "membership",
                "version",
                "owner",
                "windows",
                "membership",
                "fallback-select",
                "fallback-verify",
            ]
        );
    }

    #[tokio::test]
    async fn bridge_negotiates_before_token_then_revalidates_and_activates() {
        let directory = tempfile::tempdir()
            .unwrap_or_else(|error| unreachable!("temporary directory: {error}"));
        let process = directory.path().join("123");
        assert!(fs::create_dir(&process).is_ok());
        assert!(
            fs::write(
                process.join("stat"),
                format!("123 (opencode) S 1 0 0 7 {} 100\n", vec!["0"; 14].join(" "))
            )
            .is_ok()
        );
        let target = FocusTarget {
            process: TuiKey {
                pid: 123,
                start_time: 100,
            },
            source: FocusProcessSource::OpenCode,
            client: ClientFocusTarget::Konsole(KonsoleTarget {
                service: ":1.108".to_owned(),
                session_path: "/Sessions/7".to_owned(),
                window_path: "/Windows/11".to_owned(),
            }),
        };
        let mut commands = MockCommands {
            responses: VecDeque::from([
                Ok("500\n".to_owned()),
                Ok("/\n/Windows/1\n/Windows/11\n".to_owned()),
                Ok("4\n5\n7\n".to_owned()),
                Ok("500\n".to_owned()),
                Ok("/\n/Windows/1\n/Windows/11\n".to_owned()),
                Ok("4\n5\n7\n".to_owned()),
                Ok("500\n".to_owned()),
                Ok("/\n/Windows/1\n/Windows/11\n".to_owned()),
                Ok("4\n5\n7\n".to_owned()),
            ]),
            bridge_version: Some(Ok(1)),
            bridge_capabilities: Some(Ok(vec![BRIDGE_CAPABILITY.to_owned()])),
            activation: Some(Ok(true)),
            ..MockCommands::default()
        };
        let mut broker = MockBroker {
            token: Some(SecretString::from("fresh-token".to_owned())),
            ..MockBroker::default()
        };

        assert_eq!(
            focus_konsole_with(&target, directory.path(), &mut commands, &mut broker).await,
            FocusResult::Requested
        );
        assert_eq!(
            commands.operations,
            [
                "owner",
                "windows",
                "membership",
                "owner",
                "windows",
                "membership",
                "version",
                "capabilities",
                "owner",
                "windows",
                "membership",
                "activate",
            ]
        );
        assert_eq!(broker.requests, 1);
        assert!(
            commands
                .calls
                .iter()
                .flatten()
                .all(|argument| { !argument.contains("fresh-token") })
        );
        assert!(commands.calls.iter().all(|arguments| {
            !arguments
                .iter()
                .any(|argument| argument == "org.kde.konsole.Window.setCurrentSession")
        }));
    }

    #[tokio::test]
    async fn unavailable_token_preserves_exact_tab_fallback() {
        let directory = tempfile::tempdir()
            .unwrap_or_else(|error| unreachable!("temporary directory: {error}"));
        let process = directory.path().join("123");
        assert!(fs::create_dir(&process).is_ok());
        assert!(
            fs::write(
                process.join("stat"),
                format!("123 (opencode) S 1 0 0 7 {} 100\n", vec!["0"; 14].join(" "))
            )
            .is_ok()
        );
        let target = FocusTarget {
            process: TuiKey {
                pid: 123,
                start_time: 100,
            },
            source: FocusProcessSource::OpenCode,
            client: ClientFocusTarget::Konsole(KonsoleTarget {
                service: ":1.108".to_owned(),
                session_path: "/Sessions/7".to_owned(),
                window_path: "/Windows/11".to_owned(),
            }),
        };
        let mut commands = MockCommands {
            responses: VecDeque::from([
                Ok("500\n".to_owned()),
                Ok("/\n/Windows/1\n/Windows/11\n".to_owned()),
                Ok("4\n5\n7\n".to_owned()),
                Ok("500\n".to_owned()),
                Ok("/\n/Windows/1\n/Windows/11\n".to_owned()),
                Ok("4\n5\n7\n".to_owned()),
                Ok("500\n".to_owned()),
                Ok("/\n/Windows/1\n/Windows/11\n".to_owned()),
                Ok("4\n5\n7\n".to_owned()),
                Ok(String::new()),
                Ok("7\n".to_owned()),
            ]),
            bridge_version: Some(Ok(1)),
            bridge_capabilities: Some(Ok(vec![BRIDGE_CAPABILITY.to_owned()])),
            ..MockCommands::default()
        };
        let mut broker = MockBroker::default();

        assert_eq!(
            focus_konsole_with(&target, directory.path(), &mut commands, &mut broker).await,
            FocusResult::TabSelected
        );
        assert_eq!(
            commands.operations,
            [
                "owner",
                "windows",
                "membership",
                "owner",
                "windows",
                "membership",
                "version",
                "capabilities",
                "owner",
                "windows",
                "membership",
                "fallback-select",
                "fallback-verify",
            ]
        );
        assert_eq!(broker.requests, 1);
        assert!(commands.calls.iter().any(|arguments| {
            arguments
                .iter()
                .any(|argument| argument == "org.kde.konsole.Window.setCurrentSession")
        }));
    }

    #[tokio::test]
    async fn changed_owner_blocks_single_and_multi_window_fallback_selection() {
        for windows in ["/\n/Windows/11\n", "/\n/Windows/1\n/Windows/11\n"] {
            let directory = tempfile::tempdir()
                .unwrap_or_else(|error| unreachable!("temporary directory: {error}"));
            let process = directory.path().join("123");
            assert!(fs::create_dir(&process).is_ok());
            assert!(
                fs::write(
                    process.join("stat"),
                    format!("123 (opencode) S 1 0 0 7 {} 100\n", vec!["0"; 14].join(" "))
                )
                .is_ok()
            );
            let target = FocusTarget {
                process: TuiKey {
                    pid: 123,
                    start_time: 100,
                },
                source: FocusProcessSource::OpenCode,
                client: ClientFocusTarget::Konsole(KonsoleTarget {
                    service: ":1.108".to_owned(),
                    session_path: "/Sessions/7".to_owned(),
                    window_path: "/Windows/11".to_owned(),
                }),
            };
            let mut commands = MockCommands {
                responses: VecDeque::from([
                    Ok("500\n".to_owned()),
                    Ok(windows.to_owned()),
                    Ok("4\n5\n7\n".to_owned()),
                    Ok("500\n".to_owned()),
                    Ok(windows.to_owned()),
                    Ok("4\n5\n7\n".to_owned()),
                    Ok("501\n".to_owned()),
                ]),
                ..MockCommands::default()
            };
            let mut broker = MockBroker::default();

            assert_eq!(
                focus_konsole_with(&target, directory.path(), &mut commands, &mut broker).await,
                FocusResult::NoOp(
                    "Konsole owner identity changed before fallback focus".to_owned()
                )
            );
            assert_eq!(
                commands.operations,
                [
                    "owner",
                    "windows",
                    "membership",
                    "owner",
                    "windows",
                    "membership",
                    "version",
                    "owner",
                ]
            );
            assert!(commands.calls.iter().all(|arguments| {
                !arguments
                    .iter()
                    .any(|argument| argument == "org.kde.konsole.Window.setCurrentSession")
            }));
        }
    }

    #[tokio::test]
    async fn old_bridge_is_rejected_before_source_cookie_access() {
        let target = FocusTarget {
            process: TuiKey {
                pid: 123,
                start_time: 100,
            },
            source: FocusProcessSource::OpenCode,
            client: ClientFocusTarget::Konsole(KonsoleTarget {
                service: ":1.108".to_owned(),
                session_path: "/Sessions/7".to_owned(),
                window_path: "/Windows/11".to_owned(),
            }),
        };
        let ClientFocusTarget::Konsole(konsole) = &target.client else {
            unreachable!("test target is Konsole")
        };
        let mut commands = MockCommands {
            bridge_version: Some(Ok(0)),
            ..MockCommands::default()
        };
        let mut broker = MockBroker {
            token: Some(SecretString::from("fresh-token".to_owned())),
            ..MockBroker::default()
        };

        assert_eq!(
            try_bridge_activation(
                &target,
                konsole,
                Path::new("/unused"),
                &mut commands,
                &mut broker,
                500,
                "7",
            )
            .await,
            None
        );
        assert_eq!(commands.operations, ["version"]);
        assert_eq!(broker.requests, 0);
    }

    #[test]
    fn activation_cookie_accepts_canonical_padded_and_unpadded_base64() {
        let unpadded = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU";
        assert_eq!(unpadded.len(), 43);
        assert!(valid_cookie(unpadded));
        assert!(valid_cookie(&format!("{unpadded}=")));

        for final_character in b"AEIMQUYcgkosw048" {
            let cookie = format!("{}{}", &unpadded[..42], char::from(*final_character));
            assert!(valid_cookie(&cookie));
            assert!(valid_cookie(&format!("{cookie}=")));
        }

        for malformed in [
            "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuF",
            "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU==",
            "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFUx",
            "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuF_",
            "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFB",
            "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFB=",
            "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hS=FU",
        ] {
            assert!(!valid_cookie(malformed), "accepted {malformed:?}");
        }
    }

    #[test]
    fn activation_source_debug_does_not_expose_cookie() {
        let cookie = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU";
        assert!(valid_activation_token("fresh-token"));
        assert!(!valid_activation_token("token\nnext"));
        let source = ActivationSource {
            service: ":1.2".to_owned(),
            session_path: "/Sessions/1".to_owned(),
            cookie: SecretString::from(cookie.to_owned()),
        };
        assert!(!format!("{source:?}").contains(cookie));
    }

    #[test]
    fn repository_kwin_script_has_one_numeric_pid_substitution() {
        assert_eq!(KWIN_SCRIPT_TEMPLATE.matches(KWIN_PID_TOKEN).count(), 1);
        let source = KWIN_SCRIPT_TEMPLATE.replace(KWIN_PID_TOKEN, "1234");
        assert!(!source.contains(KWIN_PID_TOKEN));
        assert!(source.contains("window.pid === 1234"));
        assert!(source.contains("matches.length === 1"));
        assert!(source.contains("window.normalWindow"));
        assert!(source.contains("workspace.stackingOrder"));
    }

    #[tokio::test]
    #[ignore = "requires an explicitly selected live Konsole TUI"]
    async fn live_konsole_focus_acceptance() {
        let pid = std::env::var("OPENCODE_BEACON_TEST_TUI_PID")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or_else(|| unreachable!("set OPENCODE_BEACON_TEST_TUI_PID"));
        let start_time = std::env::var("OPENCODE_BEACON_TEST_TUI_START_TIME")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or_else(|| unreachable!("set OPENCODE_BEACON_TEST_TUI_START_TIME"));
        let service = std::env::var("OPENCODE_BEACON_TEST_KONSOLE_SERVICE")
            .unwrap_or_else(|_| unreachable!("set OPENCODE_BEACON_TEST_KONSOLE_SERVICE"));
        let session_path = std::env::var("OPENCODE_BEACON_TEST_KONSOLE_SESSION")
            .unwrap_or_else(|_| unreachable!("set OPENCODE_BEACON_TEST_KONSOLE_SESSION"));
        let window_path = std::env::var("OPENCODE_BEACON_TEST_KONSOLE_WINDOW")
            .unwrap_or_else(|_| unreachable!("set OPENCODE_BEACON_TEST_KONSOLE_WINDOW"));
        let result = focus_client(&FocusTarget {
            process: TuiKey { pid, start_time },
            source: FocusProcessSource::OpenCode,
            client: ClientFocusTarget::Konsole(KonsoleTarget {
                service,
                session_path,
                window_path,
            }),
        })
        .await;
        assert!(
            matches!(result, FocusResult::Requested),
            "unexpected focus result: {result:?}"
        );
    }
}
