#![allow(dead_code)]

use std::{
    fmt::{self, Display},
    iter::Peekable,
    net::SocketAddr,
    str::FromStr,
};

use eyre::{bail, ensure, eyre};
use typed_builder::TypedBuilder;

use crate::{device::peer::AllowedIP, serialization::KeyBytes};

#[derive(Debug)]
pub enum Request {
    Get(Get),
    Set(Set),
}

#[derive(Debug)]
pub enum Response {
    Get(GetResponse),
    Set(SetResponse),
}

#[derive(Default, Debug)]
#[non_exhaustive]
pub struct Get;

#[derive(Debug)]
#[derive(TypedBuilder)]
#[non_exhaustive]
pub struct GetPeer {
    pub peer: Peer,

    /// This and [Self::last_handshake_time_nsec] indicate in the number of seconds and
    /// nano-seconds of the most recent handshake for the previously added peer entry, expressed
    /// relative to the Unix epoch.
    #[builder(default, setter(strip_option, into))]
    pub last_handshake_time_sec: Option<u64>,

    /// See [Self::last_handshake_time_sec].
    #[builder(default, setter(strip_option, into))]
    pub last_handshake_time_nsec: Option<u32>,

    /// Indicates the number of received bytes for the previously added peer entry.
    #[builder(default, setter(strip_option, into))]
    pub rx_bytes: Option<u64>,

    /// Indicates the number of transmitted bytes for the previously added peer entry.
    #[builder(default, setter(strip_option, into))]
    pub tx_bytes: Option<u64>,
}

#[derive(TypedBuilder, Default, Debug)]
#[non_exhaustive]
pub struct GetResponse {
    /// The private key of the interface
    #[builder(default, setter(strip_option, into))]
    pub private_key: Option<KeyBytes>,

    /// The listening port of the interface.
    #[builder(default, setter(strip_option, into))]
    pub listen_port: Option<u16>,

    /// The fwmark of the interface.
    #[builder(default, setter(strip_option, into))]
    pub fwmark: Option<u32>,

    #[builder(default, setter(skip))]
    pub peers: Vec<GetPeer>,

    pub errno: i32,
}

#[derive(TypedBuilder, Default, Debug)]
#[non_exhaustive]
pub struct Set {
    /// The private key of the interface. If this key is all zero, it indicates that the private key
    /// should be removed.
    #[builder(default, setter(strip_option, into))]
    pub private_key: Option<KeyBytes>,

    /// The listening port of the interface.
    #[builder(default, setter(strip_option, into))]
    pub listen_port: Option<u16>,

    /// The fwmark of the interface. The value may 0, in which case it indicates that the fwmark
    /// should be removed.
    #[builder(default, setter(strip_option, into))]
    pub fwmark: Option<u32>,

    /// This indicates that the subsequent peers (perhaps an empty list) should replace any
    /// existing peers, rather than append to the existing peer list.
    #[builder(setter(strip_bool))]
    pub replace_peers: bool,

    /// This value should not be used or set by most users of this API. If unset, the corresponding
    /// peer will use the latest available protocol version. Otherwise this value must be "1".
    #[builder(default, setter(strip_option, into))]
    pub protocol_version: Option<String>,

    #[builder(default, setter(skip))]
    pub peers: Vec<SetPeer>,
}

#[derive(TypedBuilder, Debug)]
#[non_exhaustive]
pub struct SetPeer {
    pub peer: Peer,

    /// Remove the peer instead of adding it.
    #[builder(setter(strip_bool))]
    pub remove: bool,

    /// Only perform the operation if the peer already exists as part of the interface.
    #[builder(setter(strip_bool))]
    pub update_only: bool,
}

#[derive(Debug)]
#[non_exhaustive]
pub struct SetResponse {
    pub errno: i32,
}

#[derive(Debug)]
/// A config value which may be either set to something, or to nothing.
pub enum SetUnset<T> {
    /// Set the value to `T`
    Set(T),

    /// Set the value to nothing.
    Unset,
}

#[derive(TypedBuilder, Debug)]
#[non_exhaustive]
pub struct Peer {
    /// The public key of a peer entry.
    #[builder(setter(into))]
    pub public_key: KeyBytes,

    /// The preshared-key of the previously added peer entry. The value may be all zero in the case
    /// of a set operation, in which case it indicates that the preshared-key should be removed.
    #[builder(default, setter(strip_option, into))]
    pub preshared_key: Option<SetUnset<KeyBytes>>,

    /// The value for this key is either IP:port for IPv4 or [IP]:port for IPv6, indicating the
    /// endpoint of the previously added peer entry.
    #[builder(default, setter(strip_option, into))]
    pub endpoint: Option<SocketAddr>,

    /// The persistent keepalive interval of the previously added peer entry. The value 0 disables it.
    #[builder(default, setter(strip_option, into))]
    pub persistent_keepalive_interval: Option<u16>,

    /// The value for this is IP/cidr, indicating a new added allowed IP entry for the previously
    /// added peer entry. If an identical value already exists as part of a prior peer, the allowed
    /// IP entry will be removed from that peer and added to this peer.
    #[builder(default)]
    pub allowed_ip: Vec<AllowedIP>,
}

impl From<Set> for Request {
    fn from(set: Set) -> Self {
        Self::Set(set)
    }
}

impl From<Get> for Request {
    fn from(get: Get) -> Self {
        Self::Get(get)
    }
}

impl Set {
    pub fn peer(mut self, peer: SetPeer) -> Self {
        self.peers.push(peer);
        self
    }
}

impl Peer {
    /// Create a new [Peer] with only `public_key` set.
    pub fn new(public_key: impl Into<KeyBytes>) -> Self {
        Self {
            public_key: public_key.into(),
            preshared_key: None,
            endpoint: None,
            persistent_keepalive_interval: None,
            allowed_ip: vec![],
        }
    }
}

impl SetPeer {
    /// Create a new [SetPeer] with only `public_key` set.
    pub fn new(public_key: impl Into<KeyBytes>) -> Self {
        Self {
            peer: Peer::new(public_key),
            remove: false,
            update_only: false,
        }
    }
}

impl GetPeer {
    /// Create a new [GetPeer] with only `public_key` set.
    pub fn new(public_key: impl Into<KeyBytes>) -> Self {
        Self {
            peer: Peer::new(public_key),
            last_handshake_time_sec: None,
            last_handshake_time_nsec: None,
            rx_bytes: None,
            tx_bytes: None,
        }
    }
}

impl GetResponse {
    pub fn peer(mut self, peer: GetPeer) -> Self {
        self.peers.push(peer);
        self
    }
}

impl Display for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Response::Get(get) => get.fmt(f),
            Response::Set(set) => set.fmt(f),
        }
    }
}

/// Convert an &Option<T> to Option<(&str, &dyn Display)>, turning the variable name into the str.
macro_rules! opt_to_key_and_display {
    ($i:ident) => {
        $i.as_ref().map(|r| (stringify!($i), r as &dyn Display))
    };
}

impl Display for GetResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let GetResponse {
            private_key,
            listen_port,
            fwmark,
            peers,
            errno,
        } = self;

        let fields = [
            opt_to_key_and_display!(private_key),
            opt_to_key_and_display!(listen_port),
            opt_to_key_and_display!(fwmark),
        ]
        .into_iter()
        .flatten();

        for (key, value) in fields {
            writeln!(f, "{key}={value}")?;
        }

        for peer in peers {
            // TODO: make sure number of newlines is correct.
            write!(f, "{peer}")?;
        }

        writeln!(f, "errno={errno}")?;

        Ok(())
    }
}

impl Display for GetPeer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let GetPeer {
            peer:
                Peer {
                    public_key,
                    preshared_key,
                    endpoint,
                    persistent_keepalive_interval,
                    allowed_ip,
                },
            last_handshake_time_sec,
            last_handshake_time_nsec,
            rx_bytes,
            tx_bytes,
        } = self;

        let public_key = Some(&public_key);

        let fields = [
            opt_to_key_and_display!(public_key),
            opt_to_key_and_display!(preshared_key),
            opt_to_key_and_display!(endpoint),
            opt_to_key_and_display!(persistent_keepalive_interval),
            opt_to_key_and_display!(last_handshake_time_sec),
            opt_to_key_and_display!(last_handshake_time_nsec),
            opt_to_key_and_display!(rx_bytes),
            opt_to_key_and_display!(tx_bytes),
        ]
        .into_iter()
        .flatten();

        for (key, value) in fields {
            writeln!(f, "{key}={value}")?;
        }

        for AllowedIP { addr, cidr } in allowed_ip {
            writeln!(f, "allowed_ip={addr}/{cidr}")?;
        }

        Ok(())
    }
}

impl Display for SetResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "errno={}", self.errno)
    }
}

impl<T: Display> Display for SetUnset<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SetUnset::Set(t) => Display::fmt(t, f),
            SetUnset::Unset => Ok(()),
        }
    }
}

impl Display for KeyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

macro_rules! parse_opt {
    ($key:expr, $value:expr, $field:ident) => {{
        ensure!(
            $field.is_none(),
            "Key {:?} may not be specified twice",
            $key
        );
        *$field = Some($value.parse().unwrap());
    }};
}

macro_rules! parse_bool {
    ($key:expr, $value:expr, $field:ident) => {{
        ensure!(
            $value == "true",
            "The only valid value for key {:?} is \"true\"",
            $key
        );
        *$field = true;
    }};
}

impl FromStr for Get {
    type Err = eyre::Report;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s != "get=1\n" {
            bail!("Not a valid `get` command. Expected `get=1\\n`");
        }

        Ok(Get {})
    }
}

impl FromStr for Set {
    type Err = eyre::Report;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut lines = s.lines().peekable();
        ensure!(
            lines.next() == Some("set=1"),
            "Set commands must start with 'set=1'"
        );

        let mut set = Set::default();
        let Set {
            private_key,
            listen_port,
            fwmark,
            replace_peers,
            protocol_version,
            peers,
        } = &mut set;

        while let Some(line) = lines.next() {
            if line.is_empty() {
                break;
            }

            let (k, v) = to_key_value(line)?;

            match k {
                "private_key" => parse_opt!(k, v, private_key),
                "listen_port" => parse_opt!(k, v, listen_port),
                "fwmark" => parse_opt!(k, v, fwmark),
                "replace_peers" => parse_bool!(k, v, replace_peers),
                "protocol_version" => parse_opt!(k, v, protocol_version),
                "public_key" => {
                    let public_key = KeyBytes::from_str(v).map_err(|err| eyre!("{err}"))?;
                    peers.push(SetPeer::from_lines(public_key, &mut lines)?);
                }

                _ => bail!("Key {k:?} in {line:?} is not allowed in command set"),
            }
        }

        Ok(set)
    }
}

impl<T: FromStr> FromStr for SetUnset<T> {
    type Err = T::Err;

    /// Parse an empty str to [SetUnset::Unset], and a non-empty str `T`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(if s.is_empty() {
            SetUnset::Unset
        } else {
            SetUnset::Set(T::from_str(s)?)
        })
    }
}

impl SetPeer {
    fn from_lines<'a>(
        public_key: impl Into<KeyBytes>,
        lines: &mut Peekable<impl Iterator<Item = &'a str>>,
    ) -> eyre::Result<Self> {
        let mut set_peer = SetPeer::new(public_key);
        let SetPeer {
            peer:
                Peer {
                    public_key: _,
                    preshared_key,
                    endpoint,
                    persistent_keepalive_interval,
                    allowed_ip,
                },
            remove,
            update_only,
        } = &mut set_peer;

        loop {
            // loop until we peek an empty line or end-of-string
            let Some(line) = lines.peek() else {
                break;
            };
            if line.is_empty() {
                break;
            }

            let (k, v) = to_key_value(line)?;

            match k {
                // This key indicates the start of a new peer
                "public_key" => break,

                "preshared_key" => parse_opt!(k, v, preshared_key),
                "endpoint" => parse_opt!(k, v, endpoint),
                "persistent_keepalive_interval" => parse_opt!(k, v, persistent_keepalive_interval),
                "remove" => parse_bool!(k, v, remove),
                "update_only" => parse_bool!(k, v, update_only),
                "allowed_ip" => allowed_ip.push(v.parse().map_err(|err| eyre!("{err}"))?),

                _ => bail!("Key {k:?} in {line:?} is not allowed in command set/peer"),
            }

            // advance the iterator *after* we make sure we want to consume the line
            // i.e. after we check for an empty line, or a public_key
            lines.next();
        }

        Ok(set_peer)
    }
}

impl FromStr for Request {
    type Err = eyre::Report;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        //let s = s.trim();

        let Some((first_line, ..)) = s.split_once('\n') else {
            bail!("Missing newline: {s:?}");
        };

        Ok(match first_line {
            "set=1" => Set::from_str(s)?.into(),
            "get=1" => Get::from_str(s)?.into(),
            _ => bail!("Unknown command: {s:?}"),
        })
    }
}

fn to_key_value(line: &str) -> eyre::Result<(&str, &str)> {
    line.split_once('=')
        .ok_or(eyre!("expected {line:?} to be `<key>=<value>`"))
}

fn testy() {
    let public_key = [0x77u8; 32];
    let get = Peer::builder().public_key(public_key).build();
    let get = GetPeer::builder().peer(get).build();
    let _get = GetResponse::builder()
        .fwmark(123u32)
        .listen_port(18u16)
        .errno(0)
        .build()
        .peer(get);

    let _set = Set::builder()
        .fwmark(1234u32)
        .private_key(public_key)
        .build()
        .peer(
            SetPeer::builder()
                .peer(Peer::builder().public_key(public_key).build())
                .remove()
                .update_only()
                .build(),
        )
        .peer(
            SetPeer::builder()
                .peer(
                    Peer::builder()
                        .public_key(public_key)
                        .endpoint(([127, 0, 0, 1], 1234u16))
                        .build(),
                )
                .build(),
        );
}
