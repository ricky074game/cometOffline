#[derive(Debug)]
pub enum MessageHandlingErrorKind {
    NotImplemented,
    Ignored,
    Unauthorized,
    DB(sqlx::Error),
    Network(reqwest::Error),
    Proto(protobuf::Error),
    Json(serde_json::Error),
    InternalError(String),
    FatalError(String),
}

#[derive(Debug)]
pub struct MessageHandlingError {
    pub kind: MessageHandlingErrorKind,
}

impl std::error::Error for MessageHandlingError {}

impl MessageHandlingError {
    pub fn new(kind: MessageHandlingErrorKind) -> MessageHandlingError {
        MessageHandlingError { kind }
    }
}

impl std::fmt::Display for MessageHandlingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.kind {
            MessageHandlingErrorKind::NotImplemented => write!(f, "Not implemented"),
            MessageHandlingErrorKind::Ignored => write!(f, "Ignored"),
            MessageHandlingErrorKind::Unauthorized => write!(f, "Unauthorized"),
            MessageHandlingErrorKind::DB(e) => write!(f, "Database error: {}", e),
            MessageHandlingErrorKind::Network(e) => write!(f, "Network error: {}", e),
            MessageHandlingErrorKind::Proto(e) => write!(f, "Protobuf error: {}", e),
            MessageHandlingErrorKind::Json(e) => write!(f, "JSON error: {}", e),
            MessageHandlingErrorKind::InternalError(msg) => write!(f, "Internal error: {}", msg),
            MessageHandlingErrorKind::FatalError(msg) => write!(f, "Fatal error: {}", msg),
        }
    }
}
