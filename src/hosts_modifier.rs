use std::io;
use tokio::fs;
use tokio::io::{AsyncBufReadExt, BufReader}; 
use log::{info, warn, error};

// --- Configuration ---
// Define the hosts file path based on the target OS
#[cfg(target_os = "windows")]
const HOSTS_FILE_PATH: &str = "C:\\Windows\\System32\\drivers\\etc\\hosts";

const REDIRECT_DOMAIN: &str = "auth.gog.com";
const REDIRECT_IP: &str = "127.0.0.1";
const COMMENT_TAG: &str = "# Added by CometOffline";

fn get_redirect_entry_line() -> String {
    format!("{} {} {}", REDIRECT_IP, REDIRECT_DOMAIN, COMMENT_TAG)
}

async fn entry_exists_in_reader(mut reader: impl AsyncBufReadExt + Unpin) -> io::Result<bool> {
    let mut lines = reader.lines();
    let full_entry_line_trim = get_redirect_entry_line().trim().to_lowercase();
    while let Some(line_result) = lines.next_line().await? {
        let line_trim_lower = line_result.trim().to_lowercase();
        // Check for the exact line or a line starting with the IP and domain and containing the tag
        if line_trim_lower == full_entry_line_trim ||
           (line_trim_lower.starts_with(&format!("{} {}", REDIRECT_IP, REDIRECT_DOMAIN).to_lowercase()) && line_trim_lower.contains(&COMMENT_TAG.to_lowercase())) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Adds the redirect entry to the system's hosts file.
/// Requires administrator/root privileges.
pub async fn add_redirect_entry() -> io::Result<()> {
    info!("[HOSTS_MODIFIER] Attempting to add redirect for {} to {} in {}", REDIRECT_DOMAIN, REDIRECT_IP, HOSTS_FILE_PATH);
    warn!("[HOSTS_MODIFIER] This operation requires Administrator/root privileges.");

    match fs::File::open(HOSTS_FILE_PATH).await {
        Ok(file_for_check) => {
            let reader_for_check = BufReader::new(file_for_check);
            if entry_exists_in_reader(reader_for_check).await? {
                info!("[HOSTS_MODIFIER] Redirect entry for {} already exists. No action taken.", REDIRECT_DOMAIN);
                return Ok(());
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            warn!("[HOSTS_MODIFIER] Hosts file not found at {}. Cannot add entry.", HOSTS_FILE_PATH);
            return Err(e);
        }
        Err(e) => { 
            error!("[HOSTS_MODIFIER] Error opening hosts file for check: {}", e);
            return Err(e);
        }
    }


    let mut current_content = match fs::read_to_string(HOSTS_FILE_PATH).await {
        Ok(content) => content,
        Err(e) => {
            error!("[HOSTS_MODIFIER] Failed to read hosts file before adding entry: {}", e);
            return Err(e);
        }
    };
    let entry_to_add = get_redirect_entry_line();

    if !current_content.is_empty() && !current_content.ends_with('\n') {
        current_content.push('\n'); 
    }
    current_content.push_str(&entry_to_add);
    current_content.push('\n');

    if let Err(e) = fs::write(HOSTS_FILE_PATH, current_content).await {
        error!("[HOSTS_MODIFIER] FAILED to write redirect entry to hosts file: {}. Check permissions.", e);
        return Err(e);
    }

    info!("[HOSTS_MODIFIER] Successfully added redirect: {}", entry_to_add.trim());
    Ok(())
}

pub async fn remove_redirect_entry() -> io::Result<()> {
    info!("[HOSTS_MODIFIER] Attempting to remove redirect for {} from {}", REDIRECT_DOMAIN, HOSTS_FILE_PATH);
    warn!("[HOSTS_MODIFIER] This operation requires Administrator/root privileges.");

    let current_content = match fs::read_to_string(HOSTS_FILE_PATH).await {
        Ok(content) => content,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            info!("[HOSTS_MODIFIER] Hosts file not found at {}. Nothing to remove.", HOSTS_FILE_PATH);
            return Ok(());
        }
        Err(e) => {
            error!("[HOSTS_MODIFIER] Failed to read hosts file before removing entry: {}", e);
            return Err(e);
        }
    };

    let mut new_lines: Vec<String> = Vec::new();
    let mut removed_count = 0;
    let entry_to_check_lower = get_redirect_entry_line().trim().to_lowercase();

    for line in current_content.lines() {
        let line_trim_lower = line.trim().to_lowercase();

        if line_trim_lower == entry_to_check_lower ||
           (line_trim_lower.starts_with(&format!("{} {}", REDIRECT_IP, REDIRECT_DOMAIN).to_lowercase()) && line_trim_lower.contains(&COMMENT_TAG.to_lowercase())) {
            removed_count += 1;
        } else {
            new_lines.push(line.to_string());
        }
    }

    if removed_count > 0 {
        let new_content = new_lines.join("\n");
        let final_content = if !new_content.is_empty() && !new_content.ends_with('\n') {
            format!("{}\n", new_content)
        } else {
            new_content
        };

        if let Err(e) = fs::write(HOSTS_FILE_PATH, final_content).await {
            error!("[HOSTS_MODIFIER] FAILED to write updated hosts file after removing entry: {}. Check permissions.", e);
            return Err(e);
        }
        info!("[HOSTS_MODIFIER] Successfully removed {} redirect entr(y/ies) for {}.", removed_count, REDIRECT_DOMAIN);
    } else {
        info!("[HOSTS_MODIFIER] No redirect entry found for {} with the specific tag. No action taken.", REDIRECT_DOMAIN);
    }
    Ok(())
}