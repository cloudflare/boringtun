use std::fmt::Debug;

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Immutable, Unaligned, FromBytes, IntoBytes, KnownLayout)]
pub struct IpNextProtocol(u8);

impl IpNextProtocol {
    #![allow(non_upper_case_globals)]

    /// IPv6 Hop-by-Hop Option \[RFC2460\]
    pub const Hopopt: IpNextProtocol = IpNextProtocol(0);

    /// Internet Control Message \[RFC792\]
    pub const Icmp: IpNextProtocol = IpNextProtocol(1);

    /// Internet Group Management \[RFC1112\]
    pub const Igmp: IpNextProtocol = IpNextProtocol(2);

    /// Gateway-to-Gateway \[RFC823\]
    pub const Ggp: IpNextProtocol = IpNextProtocol(3);

    /// IPv4 encapsulation \[RFC2003\]
    pub const Ipv4: IpNextProtocol = IpNextProtocol(4);

    /// Stream \[RFC1190\]\[RFC1819\]
    pub const St: IpNextProtocol = IpNextProtocol(5);

    /// Transmission Control \[RFC793\]
    pub const Tcp: IpNextProtocol = IpNextProtocol(6);

    /// CBT
    pub const Cbt: IpNextProtocol = IpNextProtocol(7);

    /// Exterior Gateway Protocol \[RFC888\]
    pub const Egp: IpNextProtocol = IpNextProtocol(8);

    /// any private interior gateway (used by Cisco for their IGRP)
    pub const Igp: IpNextProtocol = IpNextProtocol(9);

    /// BBN RCC Monitoring
    pub const BbnRccMon: IpNextProtocol = IpNextProtocol(10);

    /// Network Voice Protocol \[RFC741\]
    pub const NvpII: IpNextProtocol = IpNextProtocol(11);

    /// PUP
    pub const Pup: IpNextProtocol = IpNextProtocol(12);

    /// ARGUS
    pub const Argus: IpNextProtocol = IpNextProtocol(13);

    /// EMCON
    pub const Emcon: IpNextProtocol = IpNextProtocol(14);

    /// Cross Net Debugger
    pub const Xnet: IpNextProtocol = IpNextProtocol(15);

    /// Chaos
    pub const Chaos: IpNextProtocol = IpNextProtocol(16);

    /// User Datagram \[RFC768\]
    pub const Udp: IpNextProtocol = IpNextProtocol(17);

    /// Multiplexing
    pub const Mux: IpNextProtocol = IpNextProtocol(18);

    /// DCN Measurement Subsystems
    pub const DcnMeas: IpNextProtocol = IpNextProtocol(19);

    /// Host Monitoring \[RFC869\]
    pub const Hmp: IpNextProtocol = IpNextProtocol(20);

    /// Packet Radio Measurement
    pub const Prm: IpNextProtocol = IpNextProtocol(21);

    /// XEROX NS IDP
    pub const XnsIdp: IpNextProtocol = IpNextProtocol(22);

    /// Trunk-1
    pub const Trunk1: IpNextProtocol = IpNextProtocol(23);

    /// Trunk-2
    pub const Trunk2: IpNextProtocol = IpNextProtocol(24);

    /// Leaf-1
    pub const Leaf1: IpNextProtocol = IpNextProtocol(25);

    /// Leaf-2
    pub const Leaf2: IpNextProtocol = IpNextProtocol(26);

    /// Reliable Data Protocol \[RFC908\]
    pub const Rdp: IpNextProtocol = IpNextProtocol(27);

    /// Internet Reliable Transaction \[RFC938\]
    pub const Irtp: IpNextProtocol = IpNextProtocol(28);

    /// ISO Transport Protocol Class 4 \[RFC905\]
    pub const IsoTp4: IpNextProtocol = IpNextProtocol(29);

    /// Bulk Data Transfer Protocol \[RFC969\]
    pub const Netblt: IpNextProtocol = IpNextProtocol(30);

    /// MFE Network Services Protocol
    pub const MfeNsp: IpNextProtocol = IpNextProtocol(31);

    /// MERIT Internodal Protocol
    pub const MeritInp: IpNextProtocol = IpNextProtocol(32);

    /// Datagram Congestion Control Protocol \[RFC4340\]
    pub const Dccp: IpNextProtocol = IpNextProtocol(33);

    /// Third Party Connect Protocol
    pub const ThreePc: IpNextProtocol = IpNextProtocol(34);

    /// Inter-Domain Policy Routing Protocol
    pub const Idpr: IpNextProtocol = IpNextProtocol(35);

    /// XTP
    pub const Xtp: IpNextProtocol = IpNextProtocol(36);

    /// Datagram Delivery Protocol
    pub const Ddp: IpNextProtocol = IpNextProtocol(37);

    /// IDPR Control Message Transport Proto
    pub const IdprCmtp: IpNextProtocol = IpNextProtocol(38);

    /// TP++ Transport Protocol
    pub const TpPlusPlus: IpNextProtocol = IpNextProtocol(39);

    /// IL Transport Protocol
    pub const Il: IpNextProtocol = IpNextProtocol(40);

    /// IPv6 encapsulation \[RFC2473\]
    pub const Ipv6: IpNextProtocol = IpNextProtocol(41);

    /// Source Demand Routing Protocol
    pub const Sdrp: IpNextProtocol = IpNextProtocol(42);

    /// Routing Header for IPv6
    pub const Ipv6Route: IpNextProtocol = IpNextProtocol(43);

    /// Fragment Header for IPv6
    pub const Ipv6Frag: IpNextProtocol = IpNextProtocol(44);

    /// Inter-Domain Routing Protocol
    pub const Idrp: IpNextProtocol = IpNextProtocol(45);

    /// Reservation Protocol \[RFC2205\]\[RFC3209\]
    pub const Rsvp: IpNextProtocol = IpNextProtocol(46);

    /// Generic Routing Encapsulation \[RFC1701\]
    pub const Gre: IpNextProtocol = IpNextProtocol(47);

    /// Dynamic Source Routing Protocol \[RFC4728\]
    pub const Dsr: IpNextProtocol = IpNextProtocol(48);

    /// BNA
    pub const Bna: IpNextProtocol = IpNextProtocol(49);

    /// Encap Security Payload \[RFC4303\]
    pub const Esp: IpNextProtocol = IpNextProtocol(50);

    /// Authentication Header \[RFC4302\]
    pub const Ah: IpNextProtocol = IpNextProtocol(51);

    /// Integrated Net Layer Security TUBA
    pub const INlsp: IpNextProtocol = IpNextProtocol(52);

    /// IP with Encryption
    pub const Swipe: IpNextProtocol = IpNextProtocol(53);

    /// NBMA Address Resolution Protocol \[RFC1735\]
    pub const Narp: IpNextProtocol = IpNextProtocol(54);

    /// IP Mobility
    pub const Mobile: IpNextProtocol = IpNextProtocol(55);

    /// Transport Layer Security Protocol using Kryptonet key management
    pub const Tlsp: IpNextProtocol = IpNextProtocol(56);

    /// SKIP
    pub const Skip: IpNextProtocol = IpNextProtocol(57);

    /// ICMPv6 \[RFC4443\]
    pub const Icmpv6: IpNextProtocol = IpNextProtocol(58);

    /// No Next Header for IPv6 \[RFC2460\]
    pub const Ipv6NoNxt: IpNextProtocol = IpNextProtocol(59);

    /// Destination Options for IPv6 \[RFC2460\]
    pub const Ipv6Opts: IpNextProtocol = IpNextProtocol(60);

    /// any host internal protocol
    pub const HostInternal: IpNextProtocol = IpNextProtocol(61);

    /// CFTP
    pub const Cftp: IpNextProtocol = IpNextProtocol(62);

    /// any local network
    pub const LocalNetwork: IpNextProtocol = IpNextProtocol(63);

    /// SATNET and Backroom EXPAK
    pub const SatExpak: IpNextProtocol = IpNextProtocol(64);

    /// Kryptolan
    pub const Kryptolan: IpNextProtocol = IpNextProtocol(65);

    /// MIT Remote Virtual Disk Protocol
    pub const Rvd: IpNextProtocol = IpNextProtocol(66);

    /// Internet Pluribus Packet Core
    pub const Ippc: IpNextProtocol = IpNextProtocol(67);

    /// any distributed file system
    pub const DistributedFs: IpNextProtocol = IpNextProtocol(68);

    /// SATNET Monitoring
    pub const SatMon: IpNextProtocol = IpNextProtocol(69);

    /// VISA Protocol
    pub const Visa: IpNextProtocol = IpNextProtocol(70);

    /// Internet Packet Core Utility
    pub const Ipcv: IpNextProtocol = IpNextProtocol(71);

    /// Computer Protocol Network Executive
    pub const Cpnx: IpNextProtocol = IpNextProtocol(72);

    /// Computer Protocol Heart Beat
    pub const Cphb: IpNextProtocol = IpNextProtocol(73);

    /// Wang Span Network
    pub const Wsn: IpNextProtocol = IpNextProtocol(74);

    /// Packet Video Protocol
    pub const Pvp: IpNextProtocol = IpNextProtocol(75);

    /// Backroom SATNET Monitoring
    pub const BrSatMon: IpNextProtocol = IpNextProtocol(76);

    /// SUN ND PROTOCOL-Temporary
    pub const SunNd: IpNextProtocol = IpNextProtocol(77);

    /// WIDEBAND Monitoring
    pub const WbMon: IpNextProtocol = IpNextProtocol(78);

    /// WIDEBAND EXPAK
    pub const WbExpak: IpNextProtocol = IpNextProtocol(79);

    /// ISO Internet Protocol
    pub const IsoIp: IpNextProtocol = IpNextProtocol(80);

    /// VMTP
    pub const Vmtp: IpNextProtocol = IpNextProtocol(81);

    /// SECURE-VMTP
    pub const SecureVmtp: IpNextProtocol = IpNextProtocol(82);

    /// VINES
    pub const Vines: IpNextProtocol = IpNextProtocol(83);

    /// Transaction Transport Protocol/IP Traffic Manager
    pub const TtpOrIptm: IpNextProtocol = IpNextProtocol(84);

    /// NSFNET-IGP
    pub const NsfnetIgp: IpNextProtocol = IpNextProtocol(85);

    /// Dissimilar Gateway Protocol
    pub const Dgp: IpNextProtocol = IpNextProtocol(86);

    /// TCF
    pub const Tcf: IpNextProtocol = IpNextProtocol(87);

    /// EIGRP
    pub const Eigrp: IpNextProtocol = IpNextProtocol(88);

    /// OSPFIGP \[RFC1583\]\[RFC2328\]\[RFC5340\]
    pub const OspfigP: IpNextProtocol = IpNextProtocol(89);

    /// Sprite RPC Protocol
    pub const SpriteRpc: IpNextProtocol = IpNextProtocol(90);

    /// Locus Address Resolution Protocol
    pub const Larp: IpNextProtocol = IpNextProtocol(91);

    /// Multicast Transport Protocol
    pub const Mtp: IpNextProtocol = IpNextProtocol(92);

    /// AX.25 Frames
    pub const Ax25: IpNextProtocol = IpNextProtocol(93);

    /// IP-within-IP Encapsulation Protocol
    pub const IpIp: IpNextProtocol = IpNextProtocol(94);

    /// Mobile Internetworking Control Pro.
    pub const Micp: IpNextProtocol = IpNextProtocol(95);

    /// Semaphore Communications Sec. Pro.
    pub const SccSp: IpNextProtocol = IpNextProtocol(96);

    /// Ethernet-within-IP Encapsulation \[RFC3378\]
    pub const Etherip: IpNextProtocol = IpNextProtocol(97);

    /// Encapsulation Header \[RFC1241\]
    pub const Encap: IpNextProtocol = IpNextProtocol(98);

    /// any private encryption scheme
    pub const PrivEncryption: IpNextProtocol = IpNextProtocol(99);

    /// GMTP
    pub const Gmtp: IpNextProtocol = IpNextProtocol(100);

    /// Ipsilon Flow Management Protocol
    pub const Ifmp: IpNextProtocol = IpNextProtocol(101);

    /// PNNI over IP
    pub const Pnni: IpNextProtocol = IpNextProtocol(102);

    /// Protocol Independent Multicast \[RFC4601\]
    pub const Pim: IpNextProtocol = IpNextProtocol(103);

    /// ARIS
    pub const Aris: IpNextProtocol = IpNextProtocol(104);

    /// SCPS
    pub const Scps: IpNextProtocol = IpNextProtocol(105);

    /// QNX
    pub const Qnx: IpNextProtocol = IpNextProtocol(106);

    /// Active Networks
    pub const AN: IpNextProtocol = IpNextProtocol(107);

    /// IP Payload Compression Protocol \[RFC2393\]
    pub const IpComp: IpNextProtocol = IpNextProtocol(108);

    /// Sitara Networks Protocol
    pub const Snp: IpNextProtocol = IpNextProtocol(109);

    /// Compaq Peer Protocol
    pub const CompaqPeer: IpNextProtocol = IpNextProtocol(110);

    /// IPX in IP
    pub const IpxInIp: IpNextProtocol = IpNextProtocol(111);

    /// Virtual Router Redundancy Protocol \[RFC5798\]
    pub const Vrrp: IpNextProtocol = IpNextProtocol(112);

    /// PGM Reliable Transport Protocol
    pub const Pgm: IpNextProtocol = IpNextProtocol(113);

    /// any 0-hop protocol
    pub const ZeroHop: IpNextProtocol = IpNextProtocol(114);

    /// Layer Two Tunneling Protocol \[RFC3931\]
    pub const L2tp: IpNextProtocol = IpNextProtocol(115);

    /// D-II Data Exchange (DDX)
    pub const Ddx: IpNextProtocol = IpNextProtocol(116);

    /// Interactive Agent Transfer Protocol
    pub const Iatp: IpNextProtocol = IpNextProtocol(117);

    /// Schedule Transfer Protocol
    pub const Stp: IpNextProtocol = IpNextProtocol(118);

    /// SpectraLink Radio Protocol
    pub const Srp: IpNextProtocol = IpNextProtocol(119);

    /// UTI
    pub const Uti: IpNextProtocol = IpNextProtocol(120);

    /// Simple Message Protocol
    pub const Smp: IpNextProtocol = IpNextProtocol(121);

    /// Simple Multicast Protocol
    pub const Sm: IpNextProtocol = IpNextProtocol(122);

    /// Performance Transparency Protocol
    pub const Ptp: IpNextProtocol = IpNextProtocol(123);

    ///
    pub const IsisOverIpv4: IpNextProtocol = IpNextProtocol(124);

    ///
    pub const Fire: IpNextProtocol = IpNextProtocol(125);

    /// Combat Radio Transport Protocol
    pub const Crtp: IpNextProtocol = IpNextProtocol(126);

    /// Combat Radio User Datagram
    pub const Crudp: IpNextProtocol = IpNextProtocol(127);

    ///
    pub const Sscopmce: IpNextProtocol = IpNextProtocol(128);

    ///
    pub const Iplt: IpNextProtocol = IpNextProtocol(129);

    /// Secure Packet Shield
    pub const Sps: IpNextProtocol = IpNextProtocol(130);

    /// Private IP Encapsulation within IP
    pub const Pipe: IpNextProtocol = IpNextProtocol(131);

    /// Stream Control Transmission Protocol
    pub const Sctp: IpNextProtocol = IpNextProtocol(132);

    /// Fibre Channel \[RFC6172\]
    pub const Fc: IpNextProtocol = IpNextProtocol(133);

    /// \[RFC3175\]
    pub const RsvpE2eIgnore: IpNextProtocol = IpNextProtocol(134);

    /// \[RFC6275\]
    pub const MobilityHeader: IpNextProtocol = IpNextProtocol(135);

    /// \[RFC3828\]
    pub const UdpLite: IpNextProtocol = IpNextProtocol(136);

    /// \[RFC4023\]
    pub const MplsInIp: IpNextProtocol = IpNextProtocol(137);

    /// MANET Protocols \[RFC5498\]
    pub const Manet: IpNextProtocol = IpNextProtocol(138);

    /// Host Identity Protocol \[RFC5201\]
    pub const Hip: IpNextProtocol = IpNextProtocol(139);

    /// Shim6 Protocol \[RFC5533\]
    pub const Shim6: IpNextProtocol = IpNextProtocol(140);

    /// Wrapped Encapsulating Security Payload \[RFC5840\]
    pub const Wesp: IpNextProtocol = IpNextProtocol(141);

    /// Robust Header Compression \[RFC5858\]
    pub const Rohc: IpNextProtocol = IpNextProtocol(142);
}

impl Debug for IpNextProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match *self {
            IpNextProtocol::Hopopt => "Hopopt",
            IpNextProtocol::Icmp => "Icmp",
            IpNextProtocol::Igmp => "Igmp",
            IpNextProtocol::Ggp => "Ggp",
            IpNextProtocol::Ipv4 => "Ipv4",
            IpNextProtocol::St => "St",
            IpNextProtocol::Tcp => "Tcp",
            IpNextProtocol::Cbt => "Cbt",
            IpNextProtocol::Egp => "Egp",
            IpNextProtocol::Igp => "Igp",
            IpNextProtocol::BbnRccMon => "BbnRccMon",
            IpNextProtocol::NvpII => "NvpII",
            IpNextProtocol::Pup => "Pup",
            IpNextProtocol::Argus => "Argus",
            IpNextProtocol::Emcon => "Emcon",
            IpNextProtocol::Xnet => "Xnet",
            IpNextProtocol::Chaos => "Chaos",
            IpNextProtocol::Udp => "Udp",
            IpNextProtocol::Mux => "Mux",
            IpNextProtocol::DcnMeas => "DcnMeas",
            IpNextProtocol::Hmp => "Hmp",
            IpNextProtocol::Prm => "Prm",
            IpNextProtocol::XnsIdp => "XnsIdp",
            IpNextProtocol::Trunk1 => "Trunk1",
            IpNextProtocol::Trunk2 => "Trunk2",
            IpNextProtocol::Leaf1 => "Leaf1",
            IpNextProtocol::Leaf2 => "Leaf2",
            IpNextProtocol::Rdp => "Rdp",
            IpNextProtocol::Irtp => "Irtp",
            IpNextProtocol::IsoTp4 => "IsoTp4",
            IpNextProtocol::Netblt => "Netblt",
            IpNextProtocol::MfeNsp => "MfeNsp",
            IpNextProtocol::MeritInp => "MeritInp",
            IpNextProtocol::Dccp => "Dccp",
            IpNextProtocol::ThreePc => "ThreePc",
            IpNextProtocol::Idpr => "Idpr",
            IpNextProtocol::Xtp => "Xtp",
            IpNextProtocol::Ddp => "Ddp",
            IpNextProtocol::IdprCmtp => "IdprCmtp",
            IpNextProtocol::TpPlusPlus => "TpPlusPlus",
            IpNextProtocol::Il => "Il",
            IpNextProtocol::Ipv6 => "Ipv6",
            IpNextProtocol::Sdrp => "Sdrp",
            IpNextProtocol::Ipv6Route => "Ipv6Route",
            IpNextProtocol::Ipv6Frag => "Ipv6Frag",
            IpNextProtocol::Idrp => "Idrp",
            IpNextProtocol::Rsvp => "Rsvp",
            IpNextProtocol::Gre => "Gre",
            IpNextProtocol::Dsr => "Dsr",
            IpNextProtocol::Bna => "Bna",
            IpNextProtocol::Esp => "Esp",
            IpNextProtocol::Ah => "Ah",
            IpNextProtocol::INlsp => "INlsp",
            IpNextProtocol::Swipe => "Swipe",
            IpNextProtocol::Narp => "Narp",
            IpNextProtocol::Mobile => "Mobile",
            IpNextProtocol::Tlsp => "Tlsp",
            IpNextProtocol::Skip => "Skip",
            IpNextProtocol::Icmpv6 => "Icmpv6",
            IpNextProtocol::Ipv6NoNxt => "Ipv6NoNxt",
            IpNextProtocol::Ipv6Opts => "Ipv6Opts",
            IpNextProtocol::HostInternal => "HostInternal",
            IpNextProtocol::Cftp => "Cftp",
            IpNextProtocol::LocalNetwork => "LocalNetwork",
            IpNextProtocol::SatExpak => "SatExpak",
            IpNextProtocol::Kryptolan => "Kryptolan",
            IpNextProtocol::Rvd => "Rvd",
            IpNextProtocol::Ippc => "Ippc",
            IpNextProtocol::DistributedFs => "DistributedFs",
            IpNextProtocol::SatMon => "SatMon",
            IpNextProtocol::Visa => "Visa",
            IpNextProtocol::Ipcv => "Ipcv",
            IpNextProtocol::Cpnx => "Cpnx",
            IpNextProtocol::Cphb => "Cphb",
            IpNextProtocol::Wsn => "Wsn",
            IpNextProtocol::Pvp => "Pvp",
            IpNextProtocol::BrSatMon => "BrSatMon",
            IpNextProtocol::SunNd => "SunNd",
            IpNextProtocol::WbMon => "WbMon",
            IpNextProtocol::WbExpak => "WbExpak",
            IpNextProtocol::IsoIp => "IsoIp",
            IpNextProtocol::Vmtp => "Vmtp",
            IpNextProtocol::SecureVmtp => "SecureVmtp",
            IpNextProtocol::Vines => "Vines",
            IpNextProtocol::TtpOrIptm => "TtpOrIptm",
            IpNextProtocol::NsfnetIgp => "NsfnetIgp",
            IpNextProtocol::Dgp => "Dgp",
            IpNextProtocol::Tcf => "Tcf",
            IpNextProtocol::Eigrp => "Eigrp",
            IpNextProtocol::OspfigP => "OspfigP",
            IpNextProtocol::SpriteRpc => "SpriteRpc",
            IpNextProtocol::Larp => "Larp",
            IpNextProtocol::Mtp => "Mtp",
            IpNextProtocol::Ax25 => "Ax25",
            IpNextProtocol::IpIp => "IpIp",
            IpNextProtocol::Micp => "Micp",
            IpNextProtocol::SccSp => "SccSp",
            IpNextProtocol::Etherip => "Etherip",
            IpNextProtocol::Encap => "Encap",
            IpNextProtocol::PrivEncryption => "PrivEncryption",
            IpNextProtocol::Gmtp => "Gmtp",
            IpNextProtocol::Ifmp => "Ifmp",
            IpNextProtocol::Pnni => "Pnni",
            IpNextProtocol::Pim => "Pim",
            IpNextProtocol::Aris => "Aris",
            IpNextProtocol::Scps => "Scps",
            IpNextProtocol::Qnx => "Qnx",
            IpNextProtocol::AN => "AN",
            IpNextProtocol::IpComp => "IpComp",
            IpNextProtocol::Snp => "Snp",
            IpNextProtocol::CompaqPeer => "CompaqPeer",
            IpNextProtocol::IpxInIp => "IpxInIp",
            IpNextProtocol::Vrrp => "Vrrp",
            IpNextProtocol::Pgm => "Pgm",
            IpNextProtocol::ZeroHop => "ZeroHop",
            IpNextProtocol::L2tp => "L2tp",
            IpNextProtocol::Ddx => "Ddx",
            IpNextProtocol::Iatp => "Iatp",
            IpNextProtocol::Stp => "Stp",
            IpNextProtocol::Srp => "Srp",
            IpNextProtocol::Uti => "Uti",
            IpNextProtocol::Smp => "Smp",
            IpNextProtocol::Sm => "Sm",
            IpNextProtocol::Ptp => "Ptp",
            IpNextProtocol::IsisOverIpv4 => "IsisOverIpv4",
            IpNextProtocol::Fire => "Fire",
            IpNextProtocol::Crtp => "Crtp",
            IpNextProtocol::Crudp => "Crudp",
            IpNextProtocol::Sscopmce => "Sscopmce",
            IpNextProtocol::Iplt => "Iplt",
            IpNextProtocol::Sps => "Sps",
            IpNextProtocol::Pipe => "Pipe",
            IpNextProtocol::Sctp => "Sctp",
            IpNextProtocol::Fc => "Fc",
            IpNextProtocol::RsvpE2eIgnore => "RsvpE2eIgnore",
            IpNextProtocol::MobilityHeader => "MobilityHeader",
            IpNextProtocol::UdpLite => "UdpLite",
            IpNextProtocol::MplsInIp => "MplsInIp",
            IpNextProtocol::Manet => "Manet",
            IpNextProtocol::Hip => "Hip",
            IpNextProtocol::Shim6 => "Shim6",
            IpNextProtocol::Wesp => "Wesp",
            IpNextProtocol::Rohc => "Rohc",
            _ => "Unknown",
        };

        f.debug_tuple(name).finish()
    }
}
