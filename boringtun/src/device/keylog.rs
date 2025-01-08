use std::{
    io,
    sync::{Arc, OnceLock},
};

use crate::noise::keys_logger::KeyLogFile;

static KEYLOG: OnceLock<Arc<KeyLogFile>> = OnceLock::new();

pub fn set_keylog_file(stream: Box<dyn io::Write + Send>) -> Result<(), ()> {
    KEYLOG
        .set(Arc::new(KeyLogFile::new(stream)))
        .map_err(|_| ())
}

pub fn get_keylog_file() -> Option<Arc<KeyLogFile>> {
    KEYLOG.get().cloned()
}
