//! WhisperRust - local offline push-to-talk voice dictation for Windows.
//!
//! Phase 1a scope: the I/O spine only. Hook, target probe, preflight, sanitize.
//! No audio, no model, no injection yet - `inject.rs` lands next.

mod policy;
mod preflight;
mod sanitize;
mod target;

use std::time::Duration;

use preflight::{Decision, EndCause, Request};

/// I-1: the daemon refuses to run elevated.
///
/// An elevated daemon reading a user-writable model path through ggml's hand-written
/// binary deserializer is a privilege-escalation path, with the microphone, a global
/// keyboard hook and SendInput already in hand (REDTEAM S-01, rated Critical).
/// The user has confirmed they do not dictate into elevated windows, so this is
/// unconditional.
fn refuse_if_elevated() {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            eprintln!("FATAL: cannot inspect own token; refusing to start.");
            std::process::exit(1);
        }
        let mut elev = TOKEN_ELEVATION::default();
        let mut ret = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elev as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret,
        )
        .is_ok();
        let _ = windows::Win32::Foundation::CloseHandle(token);

        if !ok {
            eprintln!("FATAL: cannot determine elevation; refusing to start.");
            std::process::exit(1);
        }
        if elev.TokenIsElevated != 0 {
            eprintln!(
                "FATAL: WhisperRust must not run elevated (invariant I-1).\n\
                 An elevated daemon with a keyboard hook, the microphone and SendInput is a\n\
                 privilege-escalation surface. Run it as a normal user.\n\
                 Elevated windows are a documented no-go; dictation into them falls back to\n\
                 the clipboard."
            );
            std::process::exit(1);
        }
    }
}

/// Admin off-switch (PLAN.md 4, emergency stop layer 6).
fn refuse_if_disabled() {
    if std::path::Path::new(policy::DISABLE_SENTINEL).exists() {
        eprintln!(
            "WhisperRust is disabled by {}\nRemove that file to re-enable.",
            policy::DISABLE_SENTINEL
        );
        std::process::exit(0);
    }
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "whisperrust=info".into()),
        )
        .init();

    refuse_if_elevated();
    refuse_if_disabled();

    println!("WhisperRust - Phase 1a (I/O spine)");
    println!();

    // Demonstrate the pieces that exist so far against the live desktop.
    match target::probe() {
        Some(ctx) => {
            println!("foreground probe:");
            println!("  exe        : {}", ctx.exe);
            println!("  title      : {}", ctx.title);
            println!("  hwnd       : {:#x}", ctx.hwnd);
            println!("  focus hwnd : {:?}", ctx.focus_hwnd);
            println!("  elevated   : {}", ctx.elevated);
            println!("  password   : {}", ctx.is_password);
            println!();

            let raw = "  Hello from WhisperRust.\nrm -rf /  ";
            let (clean, report) = sanitize::sanitize(raw);
            println!("sanitize:");
            println!("  raw    : {raw:?}");
            println!("  clean  : {clean:?}");
            println!("  report : {report:?}");
            println!();

            let req = Request {
                text: &clean,
                hold: Duration::from_millis(900),
                end_cause: EndCause::UserKeyUp,
                target_at_capture: Some(&ctx),
                target_now: Some(&ctx),
                modifiers_held: false,
                healthy: true,
                app_denied: false,
            };
            match preflight::preflight(&req) {
                Decision::Inject(c) => println!(
                    "preflight: INJECT via {:?} into {} ({} chars)",
                    c.method, c.exe, c.char_len
                ),
                Decision::ClipboardOnly(r) => {
                    println!("preflight: CLIPBOARD-ONLY ({}) - {}", r.as_str(), r.user_message())
                }
                Decision::Drop(r) => {
                    println!("preflight: DROP ({}) - {}", r.as_str(), r.user_message())
                }
            }
        }
        None => println!("no foreground window"),
    }

    println!();
    println!("Phase 1a in progress. Next: inject.rs, hook.rs, fsm.rs.");
}
