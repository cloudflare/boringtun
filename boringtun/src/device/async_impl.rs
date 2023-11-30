use std::{io::{self, BufRead}, sync::Arc, collections::HashMap, ops::{Deref, DerefMut}, os::fd::FromRawFd};
use libc::*;
use parking_lot::RwLock;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use crate::{x25519, noise::rate_limiter::RateLimiter, serialization::KeyBytes};

use super::{DeviceConfig, tun::IfrIfru, Error, peer::Peer, allowed_ips::AllowedIps, IndexLfsr};

const TUNSETIFF: u64 = 0x4004_54ca;

#[repr(C)]
pub struct ifreq {
    ifr_name: [c_uchar; IFNAMSIZ],
    ifr_ifru: IfrIfru,
}


pub struct AsyncDeviceHandle {
    device: Arc<RwLock<AsyncDevice>>,
}
pub struct AsyncDevice {
    key_pair: Option<(x25519::StaticSecret, x25519::PublicKey)>,
    // queue: Arc<EventPoll<Handler>>,

    listen_port: u16,
    fwmark: Option<u32>,

    iface: AsyncTunSocket,
    udp4: Option<tokio::net::UdpSocket>,
    udp6: Option<tokio::net::UdpSocket>,

    // yield_notice: Option<EventRef>,
    // exit_notice: Option<EventRef>,

    peers: HashMap<x25519::PublicKey, Peer>,
    peers_by_ip: AllowedIps<Peer>,
    peers_by_idx: HashMap<u32, Peer>,
    next_index: IndexLfsr,

    config: DeviceConfig,

    cleanup_paths: Vec<String>,

    mtu: usize,

    rate_limiter: Option<RateLimiter>,



    #[cfg(target_os = "linux")]
    uapi_fd: i32,
}

impl AsyncDevice {

    pub  async fn new(name: &str, config: DeviceConfig) -> Result<AsyncDevice, Error> {
        // let poll = EventPoll::<Handler>::new()?;

        // Create a tunnel device
        let iface = AsyncTunSocket::new(name)?;
        let mtu = 1500;

        #[cfg(not(target_os = "linux"))]
        let uapi_fd = -1;
        #[cfg(target_os = "linux")]
        let uapi_fd = config.uapi_fd;

        let mut device = AsyncDevice {

            iface,
            config,
            fwmark: Default::default(),
            key_pair: Default::default(),
            listen_port: Default::default(),
            next_index: Default::default(),
            peers: Default::default(),
            peers_by_idx: Default::default(),
            peers_by_ip: AllowedIps::new(),
            udp4: Default::default(),
            udp6: Default::default(),
            cleanup_paths: Default::default(),
            mtu: mtu,
            rate_limiter: None,
            #[cfg(target_os = "linux")]
            uapi_fd,
        };


        let (mut rx, tx) = device.create_fs_sock().await?;


        loop {
            let frame = rx.recv().await.unwrap();

            println!("{:?}", frame);
    
            let out = tx.send(vec![WireGuardProtocol::Errno(0)]);
    
        }


        // if uapi_fd >= 0 {
        //     device.register_api_fd(uapi_fd)?;
        // } else {
        //     device.register_api_handler()?;
        // }
        // device.register_iface_handler(&device.iface)?;
        // device.register_notifiers()?;
        // device.register_timers()?;

        #[cfg(target_os = "macos")]
        {
            // Only for macOS write the actual socket name into WG_TUN_NAME_FILE
            if let Ok(name_file) = std::env::var("WG_TUN_NAME_FILE") {
                if name == "utun" {
                    std::fs::write(&name_file, device.iface.name().unwrap().as_bytes()).unwrap();
                    device.cleanup_paths.push(name_file);
                }
            }
        }

        Ok(device)
    }
    

    pub async fn create_fs_sock(&mut self) -> Result<(UnboundedReceiver<Vec<WireGuardProtocol>>, UnboundedSender<Vec<WireGuardProtocol>>), Error> {
        let path = format!("{}/{}.sock", "/var/run/wireguard/", self.iface.name);

        tokio::fs::create_dir_all("/var/run/wireguard/").await?;

        let _ = tokio::fs::remove_file(path.clone()).await;

        self.cleanup_paths.push(path.clone());

        let p = path.clone();

        let (frame_in_tx, frame_in_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<WireGuardProtocol>>();

        let (mut frame_out_tx, mut frame_out_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<WireGuardProtocol>>();

        let rdr = tokio::spawn(async move {
            let api_listener = tokio::net::UnixListener::bind(p).map_err(Error::ApiSocket).unwrap(); // Bind a new socket to the path
           
            loop {
                let (mut conn,addr) = api_listener.accept().await.unwrap();
                let (rx, tx) = conn.split();
                println!("New connection: {:?}", addr);
                let mut buf = [0; 1024*1024];
                
                
                loop {
                    tokio::select! {
                        f = frame_out_rx.recv() => {
                            
                            if let Some(frame) = f {
                                println!("Got frame from tx {:?}", frame);
                                let buf = WireGuardProtocol::convert_vec_to_buf(frame);
                                let mut l = 0;
                                loop {
                                    // conn.writable().await.unwrap();
                                    match tx.try_write(&buf[l..]) {
                                        Ok(n) => {

                                            println!("Wrote {:?} bytes", n);
                                            if n != buf.len() {
                                                l += n;
                                                println!("Wrote {:?} bytes", n);
                                                continue;
                                            } else {
                                                break;
                                            }
                                        },
                                        Err(e) => {
                                            println!("Error writing to socket: {:?}", e);
                                            break;
                                        }
                                    }
                                }

                            }
                        },
                        _ = rx.readable() => {
                            let mut protos = vec![];
                            match rx.try_read(&mut buf) {
                                Ok(0) => break,
                                Ok(n) => {
        
                                    println!("Read {:?} bytes", n);
        
                                    let mut read_buf = &buf[..n];
                                    loop {
                                        match WireGuardProtocol::read_frame(read_buf) {
                                            Ok(ReadResponse::Complete(p)) => {
                                                protos.extend(p);
        
                                                frame_in_tx.send(protos).unwrap();

                                                break;
                                            },
                                            Ok(ReadResponse::More(p, buf)) => {
                                                protos.extend(p);
                                                read_buf = buf;
                                                continue;
                                                
                                            },
                                            Ok(ReadResponse::InvalidFrame(buf)) => {
                                                println!("Invalid frame: {:?}", buf);
                                                break;
                                            },
                                            Err(e) => {
                                                return panic!("err={:?}", e);
                                            }
                                        }
                                    }
                                }
                                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                                    continue;
                                }
                                Err(e) => {
                                    return panic!("err={:?}", e);
                                }
                            };
                        }

                    }
                }
     
            }        
        });
        
        Ok((frame_in_rx, frame_out_tx))

        
    }

    async fn open_listen_socket(&mut self, arg: i32) -> Result<(), io::Error>{

        let socket4 = tokio::net::UdpSocket::bind(format!("0.0.0.0:{}", arg)).await?;
        
        let socket6 = tokio::net::UdpSocket::bind(format!("[::]:{}", arg)).await?;


        self.udp4 = Some(socket4);
        self.udp6 = Some(socket6);

        
        Ok(())
    }


    async fn api_set(&mut self, op: WireGuardProtocol) -> Result<(), io::Error> {

        match op {
            WireGuardProtocol::Get(_) => panic!("Shouldn't pass that to set"),
            WireGuardProtocol::Set(_) => panic!("Shouldn't pass that to set"),
            WireGuardProtocol::PrivateKey(key) => {
                match key.parse::<KeyBytes>() {
                    Ok(key_bytes) => {
                        self.key(x25519::StaticSecret::from(key_bytes.0))
                    }
                    Err(_) => return EINVAL,
                },
            },
            WireGuardProtocol::ListenPort(_) => todo!(),
            WireGuardProtocol::Fwmark(_) => todo!(),
            WireGuardProtocol::ReplacePeers(_) => todo!(),
            WireGuardProtocol::PublicKey(_) => todo!(),
            WireGuardProtocol::Remove(_) => todo!(),
            WireGuardProtocol::UpdateOnly(_) => todo!(),
            WireGuardProtocol::PresharedKey(_) => todo!(),
            WireGuardProtocol::Endpoint(_) => todo!(),
            WireGuardProtocol::PersistentKeepaliveInterval(_) => todo!(),
            WireGuardProtocol::AllowedIP(_) => todo!(),
            WireGuardProtocol::RxBytes(_) => todo!(),
            WireGuardProtocol::TxBytes(_) => todo!(),
            WireGuardProtocol::LastHandshakeTimeSec(_) => todo!(),
            WireGuardProtocol::LastHandshakeTimeNsec(_) => todo!(),
            WireGuardProtocol::ProtocolVersion(_) => todo!(),
            WireGuardProtocol::Errno(_) => todo!(),
        }

    }

}

type MioHandler = Box<dyn FnMut(&mut AsyncDevice) -> Result<(), io::Error>>;

impl AsyncDeviceHandle {
    pub async fn new(name: &str, config: DeviceConfig) -> Result<AsyncDeviceHandle, Error> {
        let mut wg_interface =  AsyncDevice::new(name, config).await?;
        wg_interface.open_listen_socket(0).await?; // Start listening on a random port

        
        let sock = wg_interface.udp4.as_ref().unwrap();

        // let mut buf = [0; 1024];
        // loop {
        //     let (len, addr) = sock.recv_from(&mut buf).await?;
        //     println!("{:?} bytes received from {:?}", len, addr);
    
        //     let len = sock.send_to(&buf[..len], addr).await?;
        //     println!("{:?} bytes sent", len);
        // }

        let interface_lock = Arc::new(parking_lot::RwLock::new(wg_interface));

        

        Ok(AsyncDeviceHandle {
            device: interface_lock,
        })
    }

}


pub struct AsyncTunSocket {
    file: tokio::fs::File,
    name: String,
}

impl Drop for AsyncTunSocket {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(format!("/var/run/{}.sock", self.name));
    }
}

impl AsyncTunSocket {
    pub fn new(name: &str) -> Result<AsyncTunSocket, Error> {
        let provided_fd = name.parse::<i32>();
        if let Ok(fd) = provided_fd {


            let tun_file = unsafe { tokio::fs::File::from_raw_fd(fd) };

            return Ok(AsyncTunSocket {
                file: tun_file,
                name: name.to_string(),
            });
        }

        let fd = match unsafe { open(b"/dev/net/tun\0".as_ptr() as _, O_RDWR) } {
            -1 => return Err(Error::Socket(io::Error::last_os_error())),
            fd => fd,
        };
        let iface_name = name.as_bytes();
        let mut ifr = ifreq {
            ifr_name: [0; IFNAMSIZ],
            ifr_ifru: IfrIfru {
                ifru_flags: (IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE) as _,
            },
        };

        if iface_name.len() >= ifr.ifr_name.len() {
            return Err(Error::InvalidTunnelName);
        }

        ifr.ifr_name[..iface_name.len()].copy_from_slice(iface_name);

        if unsafe { ioctl(fd, TUNSETIFF as _, &ifr) } < 0 {
            return Err(Error::IOCtl(io::Error::last_os_error()));
        }

        match unsafe { fcntl(fd, F_GETFL) } {
            -1 => return Err(Error::FCntl(io::Error::last_os_error())),
            flags => match unsafe { fcntl(fd, F_SETFL, flags | O_NONBLOCK) } {
                -1 => return Err(Error::FCntl(io::Error::last_os_error())),
                _ => {},
            },
        };

        let name = name.to_string();
        let tun_file = unsafe { tokio::fs::File::from_raw_fd(fd) };

        Ok(
            AsyncTunSocket {
                file: tun_file,
                name,
            }
        )
    }
}

impl Deref for AsyncTunSocket {
    type Target = tokio::fs::File;

    fn deref(&self) -> &Self::Target {
        &self.file
    }
}

impl DerefMut for AsyncTunSocket {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.file
    }
}

#[derive(Debug,Clone)]
pub enum WireGuardProtocol {
    Get(u8),
    Set(u8),
    PrivateKey(String),
    ListenPort(u16),
    Fwmark(u32),
    ReplacePeers(bool),
    PublicKey(String),
    Remove(bool),
    UpdateOnly(bool),
    PresharedKey(String),
    Endpoint(String),
    PersistentKeepaliveInterval(u16),
    AllowedIP(String),
    RxBytes(u64),
    TxBytes(u64),
    LastHandshakeTimeSec(u64),
    LastHandshakeTimeNsec(u64),
    ProtocolVersion(u8),
    Errno(u8)
}



impl WireGuardProtocol {


    pub fn convert_to_string(&self) -> String {
        match self {
            WireGuardProtocol::Get(s) => format!("get={}", s),
            WireGuardProtocol::Set(s) => format!("set={}", s),
            WireGuardProtocol::PrivateKey(s) => format!("private_key={}", s),
            WireGuardProtocol::ListenPort(s) => format!("listen_port={}", s),
            WireGuardProtocol::Fwmark(s) => format!("fwmark={}", s),
            WireGuardProtocol::ReplacePeers(s) => format!("replace_peers={}", s),
            WireGuardProtocol::PublicKey(s) => format!("public_key={}", s),
            WireGuardProtocol::Remove(s) => format!("remove={}", s),
            WireGuardProtocol::UpdateOnly(s) => format!("update_only={}", s),
            WireGuardProtocol::PresharedKey(s) => format!("preshared_key={}", s),
            WireGuardProtocol::Endpoint(s) => format!("endpoint={}", s),
            WireGuardProtocol::PersistentKeepaliveInterval(s) => format!("persistent_keepalive_interval={}", s),
            WireGuardProtocol::AllowedIP(s) => format!("allowed_ip={}", s),
            WireGuardProtocol::RxBytes(s) => format!("rx_bytes={}", s),
            WireGuardProtocol::TxBytes(s) => format!("tx_bytes={}", s),
            WireGuardProtocol::LastHandshakeTimeSec(s) => format!("last_handshake_time_sec={}", s),
            WireGuardProtocol::LastHandshakeTimeNsec(s) => format!("last_handshake_time_nsec={}", s),
            WireGuardProtocol::ProtocolVersion(s) => format!("protocol_version={}", s),
            WireGuardProtocol::Errno(s) => format!("errno={}", s),
        }
    }

    pub fn convert_line_to_wg_proto(line: &str) -> Result<WireGuardProtocol, io::Error> {
        let mut split = line.split("=");

        let key = split.next().ok_or(io::Error::new(io::ErrorKind::InvalidData, "Could not split"))?;
        let value = split.next().ok_or(io::Error::new(io::ErrorKind::InvalidData, "Could not split"))?;

        match key {
            "get" => Ok(WireGuardProtocol::Get(value.parse::<u8>().map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid line"))?)),
            "set" => Ok(WireGuardProtocol::Set(value.parse::<u8>().map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid line"))?)),
            "private_key" => Ok(WireGuardProtocol::PrivateKey(value.to_string())),
            "listen_port" => Ok(WireGuardProtocol::ListenPort(value.parse::<u16>().map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid line"))?)),
            "fwmark" => Ok(WireGuardProtocol::Fwmark(value.parse::<u32>().map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid line"))?)),
            "replace_peers" => Ok(WireGuardProtocol::ReplacePeers(value.parse::<bool>().map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid line"))?)),
            "public_key" => Ok(WireGuardProtocol::PublicKey(value.to_string())),
            "remove" => Ok(WireGuardProtocol::Remove(value.parse::<bool>().map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid line"))?)),
            "update_only" => Ok(WireGuardProtocol::UpdateOnly(value.parse::<bool>().map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid line"))?)),
            "preshared_key" => Ok(WireGuardProtocol::PresharedKey(value.to_string())),
            "endpoint" => Ok(WireGuardProtocol::Endpoint(value.to_string())),
            "persistent_keepalive_interval" => Ok(WireGuardProtocol::PersistentKeepaliveInterval(value.parse::<u16>().map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid line"))?)),
            "allowed_ip" => Ok(WireGuardProtocol::AllowedIP(value.to_string())),
            "rx_bytes" => Ok(WireGuardProtocol::RxBytes(value.parse::<u64>().map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid line"))?)),
            "tx_bytes" => Ok(WireGuardProtocol::TxBytes(value.parse::<u64>().map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid line"))?)),
            "last_handshake_time_sec" => Ok(WireGuardProtocol::LastHandshakeTimeSec(value.parse::<u64>().map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid line"))?)),
            "last_handshake_time_nsec" => Ok(WireGuardProtocol::LastHandshakeTimeNsec(value.parse::<u64>().map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid line"))?)),
            "protocol_version" => Ok(WireGuardProtocol::ProtocolVersion(value.parse::<u8>().map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid line"))?)),
            "errno" => Ok(WireGuardProtocol::Errno(value.parse::<u8>().map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid line"))?)),
            _ => Err(io::Error::new(io::ErrorKind::InvalidData, "Unknown key")),
        }
    }


    fn convert_vec_to_buf(protos: Vec<WireGuardProtocol>) -> Vec<u8> {
        let mut buf = Vec::new();

        for proto in protos {
            buf.extend(proto.convert_to_string().as_bytes());
            buf.push(b'\n');
        }
        buf.push(b'\n');

        buf
    }

    fn read_frame(buf: &[u8]) -> Result<ReadResponse, io::Error> {
        let mut protos = Vec::new();

        let mut last_idx = 0;

        
            let frame_end = buf[last_idx..].windows(2).position(|x| x == b"\n\n");
            match frame_end {
                Some(l) => {

                    if l == 0 {
                        return Ok(ReadResponse::Complete(protos));
                    }

                    let frame = &buf[last_idx..l];
                    last_idx = l + 2;
                    

                    for line in frame.lines() {
                        let proto = WireGuardProtocol::convert_line_to_wg_proto(&line?)?;
                        protos.push(proto);
                    }

                    if buf[last_idx..].is_empty() {
                        return Ok(ReadResponse::Complete(protos));
                    } else  {
                        return Ok(ReadResponse::More(protos, &buf[last_idx..]));
                    }

                },
                None => {
                    return Ok(ReadResponse::InvalidFrame(buf));
                }
        }
    }

}
#[derive(Debug)]
enum ReadResponse<'a> {
    Complete(Vec<WireGuardProtocol>),
    More(Vec<WireGuardProtocol>, &'a [u8]),
    InvalidFrame(&'a [u8]),
}