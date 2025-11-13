use aya::Pod;

/// Equivalent to `struct ipv4_flow_key`
/// Represents a unique IPv4 network flow identified by source/destination IP and ports
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct Ipv4FlowKey {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
}

unsafe impl Pod for Ipv4FlowKey {}

// Compile-time check: size == 12 bytes
const _: () = assert!(std::mem::size_of::<Ipv4FlowKey>() == 12);

/// Statistics structure that matches the eBPF map structure
/// This tracks various packet drop metrics for monitoring DDoS protection effectiveness
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct Statistics {
    /// Total number of packets dropped by the filter
    pub packets_dropped: u64,
    
    /// Total bytes of dropped packets
    pub bytes_dropped: u64,
    
    /// Number of SYN packets dropped (initial connection attempts)
    pub syn_packets_dropped: u64,
    
    /// Number of TCP bypass packets dropped (SYN-ACK or URG flag packets)
    /// These are often used in sophisticated DDoS attacks
    pub tcp_bypass_dropped: u64,
    
    /// Number of invalid packets dropped (malformed or suspicious packets)
    pub invalid_packets_dropped: u64,
    
    /// Number of packets dropped due to connection throttling
    pub throttled_packets_dropped: u64,
    
    /// Number of packets dropped from blocked IPs
    pub blocked_ip_packets_dropped: u64,
}

unsafe impl Pod for Statistics {}

// Compile-time check: ensure proper size alignment
const _: () = assert!(std::mem::size_of::<Statistics>() == 56);

/// Converts a network byte order IPv4 address to a human-readable string
/// Network byte order is big-endian, so we swap bytes for host representation
pub fn network_address_to_string(ip: u32) -> String {
    std::net::Ipv4Addr::from(ip.swap_bytes()).to_string()
}

/// Converts a network byte order port number to host byte order
pub fn network_port_to_normal(port: u16) -> u16 {
    port.swap_bytes()
}

/// Formats a flow key into a readable string representation
/// Format: [src_ip:src_port -> dst_ip:dst_port]
pub fn flow_key_to_string(key: &Ipv4FlowKey) -> String {
    format!(
        "[{}:{} -> {}:{}]",
        network_address_to_string(key.src_ip),
        network_port_to_normal(key.src_port),
        network_address_to_string(key.dst_ip),
        network_port_to_normal(key.dst_port)
    )
}

/// Formats bytes into human-readable format (B, KB, MB, GB)
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    
    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Formats a rate value (per second) into human-readable format with K, M suffixes
pub fn format_rate(rate: u64) -> String {
    const K: u64 = 1000;
    const M: u64 = K * 1000;
    
    if rate >= M {
        format!("{:.2}M", rate as f64 / M as f64)
    } else if rate >= K {
        format!("{:.2}K", rate as f64 / K as f64)
    } else {
        format!("{}", rate)
    }
}
