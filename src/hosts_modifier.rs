use std::io;
use tokio::fs;
use tokio::io::{AsyncBufReadExt, BufReader}; 
use log::{info, warn, error, debug};

#[cfg(target_os = "windows")]
const HOSTS_FILE_PATH: &str = "C:\\Windows\\System32\\drivers\\etc\\hosts";

const REDIRECT_DOMAINS: &[&str] = &["auth.gog.com", "users.gog.com", "presence.gog.com"]; // Changed to an array
const REDIRECT_IP: &str = "127.0.0.1";
const COMMENT_TAG: &str = "# Added by CometOffline";

fn get_redirect_entry_line(domain: &str) -> String { // Added domain parameter
    format!("{} {} {}", REDIRECT_IP, domain, COMMENT_TAG)
}

async fn domain_entry_exists_in_reader(mut reader: impl AsyncBufReadExt + Unpin, domain: &str) -> io::Result<bool> { // Renamed and added domain parameter
    let mut lines = reader.lines();
    let specific_redirect_entry = get_redirect_entry_line(domain);
    let full_entry_line_trim = specific_redirect_entry.trim().to_lowercase();

    while let Some(line_result) = lines.next_line().await? {
        let line_trim_lower = line_result.trim().to_lowercase();
        if line_trim_lower == full_entry_line_trim ||
           (line_trim_lower.starts_with(&format!("{} {}", REDIRECT_IP, domain).to_lowercase()) && line_trim_lower.contains(&COMMENT_TAG.to_lowercase())) {
            return Ok(true);
        }
    }
    Ok(false)
}


pub async fn add_redirect_entry() -> io::Result<()> {
    debug!("[HOSTS_MODIFIER] Attempting to add redirects for {:?} to {} in {}", REDIRECT_DOMAINS, REDIRECT_IP, HOSTS_FILE_PATH);
    warn!("[HOSTS_MODIFIER] This operation requires Administrator/root privileges.");

    let mut entries_added_count = 0;
    let mut entries_already_exist_count = 0;

    for &domain in REDIRECT_DOMAINS {
        match fs::File::open(HOSTS_FILE_PATH).await {
            Ok(file_for_check) => {
                let reader_for_check = BufReader::new(file_for_check);
                if domain_entry_exists_in_reader(reader_for_check, domain).await? {
                    debug!("[HOSTS_MODIFIER] Redirect entry for {} already exists. No action taken.", domain);
                    entries_already_exist_count += 1;
                    continue; // Move to the next domain
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                warn!("[HOSTS_MODIFIER] Hosts file not found at {}. Cannot add entry for {}.", HOSTS_FILE_PATH, domain);
                return Err(e); // If hosts file not found, can't proceed
            }
            Err(e) => {
                error!("[HOSTS_MODIFIER] Error opening hosts file for check for domain {}: {}", domain, e);
                return Err(e); // Propagate other errors
            }
        }

        // Read current content for each domain to ensure it's up-to-date if multiple entries are added
        let mut current_content = match fs::read_to_string(HOSTS_FILE_PATH).await {
            Ok(content) => content,
            Err(e) => {
                error!("[HOSTS_MODIFIER] Failed to read hosts file before adding entry for {}: {}", domain, e);
                return Err(e);
            }
        };

        let entry_to_add = get_redirect_entry_line(domain);

        if !current_content.is_empty() && !current_content.ends_with('\n') {
            current_content.push('\n');
        }
        current_content.push_str(&entry_to_add);
        current_content.push('\n');

        if let Err(e) = fs::write(HOSTS_FILE_PATH, current_content).await {
            error!("[HOSTS_MODIFIER] FAILED to write redirect entry for {} to hosts file: {}. Check permissions.", domain, e);
            return Err(e);
        }
        debug!("[HOSTS_MODIFIER] Successfully added redirect: {}", entry_to_add.trim());
        entries_added_count += 1;
    }

    if entries_added_count > 0 {
        debug!("[HOSTS_MODIFIER] Finished adding {} new redirect entries.", entries_added_count);
    }
    if entries_already_exist_count > 0 {
        debug!("[HOSTS_MODIFIER] {} redirect entries already existed.", entries_already_exist_count);
    }
    if entries_added_count == 0 && entries_already_exist_count == REDIRECT_DOMAINS.len() {
        debug!("[HOSTS_MODIFIER] All redirect entries already existed. No changes made.");
    }

    Ok(())
}

pub async fn remove_redirect_entry() -> io::Result<()> {
    debug!("[HOSTS_MODIFIER] Attempting to remove redirects for {:?} from {}", REDIRECT_DOMAINS, HOSTS_FILE_PATH);
    warn!("[HOSTS_MODIFIER] This operation requires Administrator/root privileges.");

    let current_content = match fs::read_to_string(HOSTS_FILE_PATH).await {
        Ok(content) => content,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            debug!("[HOSTS_MODIFIER] Hosts file not found at {}. Nothing to remove.", HOSTS_FILE_PATH);
            return Ok(());
        }
        Err(e) => {
            error!("[HOSTS_MODIFIER] Failed to read hosts file before removing entries: {}", e);
            return Err(e);
        }
    };

    let mut new_lines: Vec<String> = Vec::new();
    let mut total_removed_count = 0;
    let original_lines: Vec<&str> = current_content.lines().collect();
    let mut lines_to_keep: Vec<String> = Vec::new();

    for line in original_lines {
        let mut keep_line = true;
        for &domain in REDIRECT_DOMAINS {
            let entry_to_check_lower = get_redirect_entry_line(domain).trim().to_lowercase();
            let line_trim_lower = line.trim().to_lowercase();

            if line_trim_lower == entry_to_check_lower ||
               (line_trim_lower.starts_with(&format!("{} {}", REDIRECT_IP, domain).to_lowercase()) && line_trim_lower.contains(&COMMENT_TAG.to_lowercase())) {
                total_removed_count += 1;
                keep_line = false;
                debug!("[HOSTS_MODIFIER] Marking line for removal: {}", line);
                break; // Found a match for this line, no need to check other domains for the same line
            }
        }
        if keep_line {
            lines_to_keep.push(line.to_string());
        }
    }


    if total_removed_count > 0 {
        let new_content = lines_to_keep.join("\n");
        // Ensure a trailing newline if content is not empty
        let final_content = if !new_content.is_empty() && !new_content.ends_with('\n') {
            format!("{}\n", new_content)
        } else if new_content.is_empty() {
            String::new() // Handle case where file becomes empty
        }
         else {
            new_content
        };


        if let Err(e) = fs::write(HOSTS_FILE_PATH, final_content).await {
            error!("[HOSTS_MODIFIER] FAILED to write updated hosts file after removing entries: {}. Check permissions.", e);
            return Err(e);
        }
        debug!("[HOSTS_MODIFIER] Successfully removed {} redirect entr(y/ies) for {:?}.", total_removed_count, REDIRECT_DOMAINS);
    } else {
        debug!("[HOSTS_MODIFIER] No redirect entries found for {:?} with the specific tag. No action taken.", REDIRECT_DOMAINS);
    }
    Ok(())
}