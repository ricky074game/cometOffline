use std::env;
use std::path::PathBuf;

#[cfg(target_os = "windows")]
lazy_static! {
    static ref DATA_PATH: PathBuf = PathBuf::from(env::var("LOCALAPPDATA").unwrap()).join("comet");
    static ref CONFIG_PATH: PathBuf = PathBuf::from(env::var("APPDATA").unwrap()).join("comet");
}

lazy_static! {
    pub static ref GAMEPLAY_STORAGE: PathBuf = DATA_PATH.join("gameplay");
    pub static ref REDISTS_STORAGE: PathBuf = DATA_PATH.join("redist");
    pub static ref CONFIG_FILE: PathBuf = CONFIG_PATH.join("config.toml");
}
