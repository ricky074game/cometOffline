use derive_getters::Getters;
use serde::{Deserialize, Serialize};
use std::fmt::Display;


#[allow(dead_code)]
pub enum Platform {
    Windows,
    Mac,
}

impl Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Windows => f.write_str("windows"),
            Self::Mac => f.write_str("osx"),
        }
    }
}

#[derive(Serialize, Deserialize, Getters, Debug)]
#[serde(rename_all = "camelCase")]
struct ComponentManifest {
    application_type: String,
    #[serde(rename = "baseURI")]
    base_uri: String,
    files: Vec<ComponentFile>,
    force_update: bool,
    project_name: String,
    symlinks: Vec<ComponentSymlink>,
    timestamp: String,
    version: String,
}

#[derive(Serialize, Deserialize, Getters, Debug)]
struct ComponentFile {
    hash: String,
    path: String,
    resource: String,
    sha256: String,
    size: u32,
}

#[derive(Serialize, Deserialize, Getters, Debug)]
struct ComponentSymlink {
    path: String,
    target: String,
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum Component {
    Peer,
    Overlay,
    Web,
}

#[derive(Serialize, Deserialize, Debug, Default)]
struct ComponentManifestLocal {
    pub time: i64,
    pub version: String,
}

impl Display for Component {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Peer => f.write_str("desktop-galaxy-peer"),
            Self::Overlay => f.write_str("desktop-galaxy-overlay"),
            Self::Web => f.write_str("desktop-galaxy-client"),
        }
    }
}
