use std::{io, sync::Arc};

use parking_lot::Mutex;

use super::{handshake::HandshakeKeys, HandshakeKeysListener};

pub struct KeyLogFile {
    stream: Mutex<Box<dyn io::Write + Send>>,
}

impl KeyLogFile {
    pub fn new(stream: Box<dyn io::Write + Send>) -> Self {
        Self {
            stream: Mutex::new(stream),
        }
    }
}

impl KeyLogger for KeyLogFile {
    fn log_key(&self, name: &str, keymaterial: &str) {
        let mut locked_stream = self.stream.lock();

        // Errors are intentionally ignored.
        let _ = writeln!(&mut *locked_stream, "{} = {}", name, keymaterial);
    }
}

impl KeyLogger for Arc<KeyLogFile> {
    fn log_key(&self, name: &str, keymaterial: &str) {
        self.as_ref().log_key(name, keymaterial)
    }
}

pub trait KeyLogger: Send + Sync {
    fn log_key(&self, name: &str, keymaterial: &str);
}

pub struct KeysLogger<T> {
    output: T,
}

impl<T: KeyLogger> KeysLogger<T> {
    pub fn new(output: T) -> Self {
        Self { output }
    }

    fn log_handshake_keys(&self, keys: HandshakeKeys<'_>) {
        self.log_key("LOCAL_STATIC_PRIVATE_KEY", keys.static_private);
        self.log_key("REMOTE_STATIC_PUBLIC_KEY", keys.peer_static_public);
        self.log_key("LOCAL_EPHEMERAL_PRIVATE_KEY", keys.ephemeral_private);

        if let Some(preshared_key) = keys.preshared_key.as_ref() {
            self.log_key("PRESHARED_KEY", preshared_key);
        }
    }

    fn log_key(&self, name: &str, content: &[u8]) {
        let encoded = base64::encode(content);
        self.output.log_key(name, &encoded);
    }
}

impl<T: KeyLogger> HandshakeKeysListener for KeysLogger<T> {
    fn publish_handshake_keys(&self, keys: HandshakeKeys<'_>) {
        self.log_handshake_keys(keys);
    }
}
