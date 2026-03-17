use std::{
    io::{self, Write},
    thread,
    time::Duration,
};

use anyhow::{bail, Context, Result};

/// Wait briefly after a YubiKey interaction so the HID device can finish
/// emitting any stray keystrokes before we read the next prompt.
pub fn post_yubikey_interaction_cleanup() -> Result<()> {
    thread::sleep(Duration::from_millis(250));
    flush_stdin_buffer()?;
    Ok(())
}

/// Read a line prompt and trim trailing whitespace.
pub fn read_line_prompt(prompt: &str) -> Result<String> {
    print!("{prompt}");
    io::stdout().flush().context("failed to flush stdout")?;

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .context("failed to read user input")?;

    Ok(input.trim().to_string())
}

/// Read a strict yes/no answer.
/// Empty input selects the provided default.
/// Any other value is rejected and the user is asked again.
pub fn read_yes_no_prompt(prompt: &str, default_yes: bool) -> Result<bool> {
    loop {
        let answer = read_line_prompt(prompt)?;

        if answer.is_empty() {
            return Ok(default_yes);
        }

        match answer.to_ascii_lowercase().as_str() {
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => {
                println!("Please answer with Y or n.");
            }
        }
    }
}

/// Read a strict numeric choice from a fixed set of allowed values.
/// Empty input selects the provided default.
pub fn read_numeric_choice_prompt(
    prompt: &str,
    allowed: &[u8],
    default_choice: u8,
) -> Result<u8> {
    if !allowed.contains(&default_choice) {
        bail!("default numeric choice is not in allowed set");
    }

    loop {
        let answer = read_line_prompt(prompt)?;

        if answer.is_empty() {
            return Ok(default_choice);
        }

        let parsed: u8 = match answer.parse() {
            Ok(v) => v,
            Err(_) => {
                println!("Please enter one of: {}.", format_allowed_choices(allowed));
                continue;
            }
        };

        if allowed.contains(&parsed) {
            return Ok(parsed);
        }

        println!("Please enter one of: {}.", format_allowed_choices(allowed));
    }
}

fn format_allowed_choices(values: &[u8]) -> String {
    values
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(unix)]
fn flush_stdin_buffer() -> Result<()> {
    let rc = unsafe { libc::tcflush(libc::STDIN_FILENO, libc::TCIFLUSH) };
    if rc != 0 {
        return Err(io::Error::last_os_error()).context("failed to flush stdin buffer");
    }
    Ok(())
}

#[cfg(not(unix))]
fn flush_stdin_buffer() -> Result<()> {
    Ok(())
}