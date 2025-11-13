use anyhow::Result;
use aya::{
    Ebpf, include_bytes_aligned,
    maps::{Array, HashMap, MapData},
    programs::{Xdp, XdpFlags},
};
use common::{Ipv4FlowKey, Statistics};
use env_logger::{Builder, Env};
use libc::{CLOCK_BOOTTIME, clock_gettime, timespec};
use log::{debug, error, info, warn};
use signal_hook::consts::TERM_SIGNALS;
use signal_hook::iterator::Signals;
use std::{
    env,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

mod common;

const SECOND_TO_NANOS: u64 = 1_000_000_000;

// Heart beat interval: 100 milliseconds
const OLD_CONNECTION_TIMEOUT: u64 = 60; // Clear old connections every 60 seconds
const BLOCKED_IP_TIMEOUT: u64 = 60; // Unblock IPs after 60 seconds
const THROTTLE_CLEAR_CYCLE: u64 = 3; // Clear throttle counters every 3 seconds
const STATS_DISPLAY_INTERVAL: u64 = 1; // Display statistics every 1 second

/// Initiates graceful shutdown of all background threads
fn shutdown(running: Arc<AtomicBool>, condvar: Arc<Condvar>) {
    if running.load(Ordering::SeqCst) {
        info!("Shutting down...");
        running.store(false, Ordering::SeqCst);
        condvar.notify_all();
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <interface> or '--license'", args[0]);
        return;
    }
    
    // Set default log level if not specified
    if std::env::var("RUST_LOG").is_err() {
        unsafe {
            #[cfg(debug_assertions)]
            std::env::set_var("RUST_LOG", "debug");
            #[cfg(not(debug_assertions))]
            std::env::set_var("RUST_LOG", "info");
        }
    }
    
    if args[1] == "--license" {
        println!(include_str!("../LICENSE"));
        return;
    }
    
    Builder::from_env(Env::default())
        .format_timestamp_secs()
        .init();

    info!("Loading minecraft xdp filter v1.9 by Outfluencer...");

    let running = Arc::new(AtomicBool::new(true));
    let condvar = Arc::new(Condvar::new());

    start_shutdown_hook(running.clone(), condvar.clone());

    match load(args[1].as_str(), running.clone(), condvar.clone()) {
        Err(e) => {
            error!("Failed to load BPF program: {}", e);
        }
        _ => {}
    }

    shutdown(running, condvar);

    info!("Good bye!");
}

/// Spawns a background thread to handle termination signals (SIGTERM, SIGINT, etc.)
fn start_shutdown_hook(arc: Arc<AtomicBool>, condvar: Arc<Condvar>) {
    let mut signals = Signals::new(TERM_SIGNALS).expect("Couldn't register signals");
    thread::spawn(move || {
        for signal in signals.forever() {
            warn!("Received termination signal: {signal}");
            shutdown(arc, condvar);
            break; // Stop on first termination signal
        }
    });
}

/// Main function to load eBPF program and start all background tasks
fn load(
    interface: &str,
    running: Arc<AtomicBool>,
    condvar: Arc<Condvar>,
) -> Result<(), anyhow::Error> {
    // Load the compiled eBPF bytecode
    let data = include_bytes_aligned!(concat!(env!("CARGO_MANIFEST_DIR"), "/c/minecraft_filter.o"));
    info!("Loaded BPF program (size: {})", data.len());

    let mut ebpf = Ebpf::load(data)?;

    // Load and attach the XDP program to the network interface
    let programm: &mut Xdp = ebpf
        .program_mut("minecraft_filter")
        .ok_or_else(|| anyhow::anyhow!("Program 'minecraft_filter' not found"))?
        .try_into()?;
    programm.load()?;

    let result = programm.attach(interface, XdpFlags::empty())?;
    info!(
        "BPF program attached to interface: {} ({:?})",
        interface, result
    );

    // Get reference to the player connection tracking map
    // This map stores active connections with their last activity timestamp
    let player_connection_map = {
        let map = ebpf
            .take_map("player_connection_map")
            .ok_or_else(|| anyhow::anyhow!("Can't take map 'player_connection_map'"))?;
        HashMap::<MapData, Ipv4FlowKey, u64>::try_from(map)?
    };
    let player_connection_map_ref: Arc<Mutex<HashMap<MapData, Ipv4FlowKey, u64>>> =
        Arc::new(Mutex::new(player_connection_map));

    // Get reference to the connection throttle map
    // This map tracks connection attempts per IP to prevent connection flooding
    let connection_throttle = {
        let map = ebpf
            .take_map("connection_throttle")
            .ok_or_else(|| anyhow::anyhow!("Can't take map 'connection_throttle'"))?;
        HashMap::<MapData, u32, u32>::try_from(map)?
    };
    let connection_throttle_ref: Arc<Mutex<HashMap<MapData, u32, u32>>> =
        Arc::new(Mutex::new(connection_throttle));

    // Get reference to the blocked IPs map
    // This map stores IPs that have been temporarily blocked due to suspicious activity
    let blocked_ips = {
        let map = ebpf
            .take_map("blocked_ips")
            .ok_or_else(|| anyhow::anyhow!("Can't take map 'blocked_ips'"))?;
        HashMap::<MapData, u32, u64>::try_from(map)?
    };
    let blocked_ips_ref: Arc<Mutex<HashMap<MapData, u32, u64>>> = Arc::new(Mutex::new(blocked_ips));

    // Get reference to the statistics array map
    // Index 0 contains the cumulative statistics from the eBPF program
    let statistics = {
        let map = ebpf
            .take_map("statistics")
            .ok_or_else(|| anyhow::anyhow!("Can't take map 'statistics'"))?;
        Array::<MapData, Statistics>::try_from(map)?
    };
    let statistics_ref: Arc<Mutex<Array<MapData, Statistics>>> = Arc::new(Mutex::new(statistics));

    // Spawn background thread to display statistics every second
    let handle_stats = spawn_statistics_display(
        "stats-display",
        running.clone(),
        condvar.clone(),
        statistics_ref,
    )?;

    // Spawn background thread to clean up old connections
    let handle1 = spawn_old_connection_clear(
        "clear-old",
        running.clone(),
        condvar.clone(),
        player_connection_map_ref,
    )?;
    
    // Spawn background thread to reset throttle counters periodically
    let handle2 = spawn_connection_throttle_clear(
        "clear-throttle",
        running.clone(),
        condvar.clone(),
        connection_throttle_ref,
    )?;
    
    // Spawn background thread to unblock IPs after timeout
    let handle3 = spawn_block_clear("clear-blocks", running, condvar, blocked_ips_ref)?;

    // Wait for all background threads to complete
    let _ = handle_stats
        .join()
        .map_err(|e| anyhow::anyhow!("stats-display thread panicked: {:?}", e))?;
    let _ = handle1
        .join()
        .map_err(|e| anyhow::anyhow!("clear-old thread panicked: {:?}", e))?;
    let _ = handle2
        .join()
        .map_err(|e| anyhow::anyhow!("clear-throttle thread panicked: {:?}", e))?;
    let _ = handle3
        .join()
        .map_err(|e| anyhow::anyhow!("clear-blocks thread panicked: {:?}", e))?;

    Ok(())
}

/// Spawns a thread to display real-time statistics every second
fn spawn_statistics_display(
    name: &'static str,
    running: Arc<AtomicBool>,
    condvar: Arc<Condvar>,
    statistics_ref: Arc<Mutex<Array<MapData, Statistics>>>,
) -> Result<thread::JoinHandle<()>, anyhow::Error> {
    thread::Builder::new()
        .name(name.into())
        .spawn(move || {
            if let Err(e) = statistics_display(running.clone(), condvar.clone(), statistics_ref) {
                error!("Failed to display statistics: {:?}", e);
                shutdown(running, condvar);
            }
        })
        .map_err(|e| e.into())
}

/// Main loop for displaying real-time statistics
/// Calculates per-second rates by comparing current values with previous values
fn statistics_display(
    running: Arc<AtomicBool>,
    condvar: Arc<Condvar>,
    statistics_ref: Arc<Mutex<Array<MapData, Statistics>>>,
) -> Result<(), anyhow::Error> {
    let dummy_mutex = Mutex::new(());
    
    // Initialize previous statistics to zero for first iteration
    let mut prev_stats = Statistics::default();
    
    // Print header for statistics table
    info!("╔═══════════════════════════════════════════════════════════════════════════════════════════════╗");
    info!("║                            Real-time DDoS Protection Statistics                               ║");
    info!("╚═══════════════════════════════════════════════════════════════════════════════════════════════╝");
    
    while running.load(Ordering::SeqCst) {
        let map = statistics_ref
            .lock()
            .map_err(|e| anyhow::anyhow!("Statistics mutex poisoned: {}", e))?;
        
        // Read current statistics from eBPF map (index 0)
        let current_stats = match map.get(&0, 0) {
            Ok(stats) => stats,
            Err(e) => {
                warn!("Failed to read statistics: {:?}", e);
                Statistics::default()
            }
        };
        
        // Calculate per-second rates by subtracting previous values
        let packets_per_sec = current_stats.packets_dropped.saturating_sub(prev_stats.packets_dropped);
        let bytes_per_sec = current_stats.bytes_dropped.saturating_sub(prev_stats.bytes_dropped);
        let syn_per_sec = current_stats.syn_packets_dropped.saturating_sub(prev_stats.syn_packets_dropped);
        let tcp_bypass_per_sec = current_stats.tcp_bypass_dropped.saturating_sub(prev_stats.tcp_bypass_dropped);
        let invalid_per_sec = current_stats.invalid_packets_dropped.saturating_sub(prev_stats.invalid_packets_dropped);
        let throttled_per_sec = current_stats.throttled_packets_dropped.saturating_sub(prev_stats.throttled_packets_dropped);
        let blocked_ip_per_sec = current_stats.blocked_ip_packets_dropped.saturating_sub(prev_stats.blocked_ip_packets_dropped);
        
        // Only display if there's activity (at least one packet dropped)
        if packets_per_sec > 0 {
            info!("┌─────────────────────────────────────────────────────────────────────────────────────────┐");
            info!("│ Per-Second Statistics                                                                   │");
            info!("├─────────────────────────────────────────────────────────────────────────────────────────┤");
            info!("│  Total Packets/Bytes Dropped:  {:>10} pkt/s {:>15}             ", common::format_rate(packets_per_sec), common::format_bytes(bytes_per_sec));
            info!("│  SYN Packets Dropped:          {:>10} pkt/s  (Connection attempts)   ", common::format_rate(syn_per_sec));
            info!("│  TCP Bypass Dropped:           {:>10} pkt/s  (SYN-ACK/URG attacks)   ", common::format_rate(tcp_bypass_per_sec));
            info!("│  Invalid Packets Dropped:      {:>10} pkt/s  (Malformed packets)     ", common::format_rate(invalid_per_sec));
            info!("│  Throttled Packets:            {:>10} pkt/s  (Rate limited)          ", common::format_rate(throttled_per_sec));
            info!("│  Blocked IP Packets:           {:>10} pkt/s  (From banned IPs)       ", common::format_rate(blocked_ip_per_sec));
            info!("├─────────────────────────────────────────────────────────────────────────────────────────┤");
            info!("│ Cumulative Totals                                                                       │");
            info!("├─────────────────────────────────────────────────────────────────────────────────────────┤");
            info!("│  Total Packets:                {:>10}   ", common::format_rate(current_stats.packets_dropped));
            info!("│  Total Bytes:                  {:>15}   ", common::format_bytes(current_stats.bytes_dropped));
            info!("│  Total SYN:                    {:>10}   ", common::format_rate(current_stats.syn_packets_dropped));
            info!("│  Total TCP Bypass:             {:>10}   ", common::format_rate(current_stats.tcp_bypass_dropped));
            info!("│  Total Invalid:                {:>10}   ", common::format_rate(current_stats.invalid_packets_dropped));
            info!("│  Total Throttled:              {:>10}   ", common::format_rate(current_stats.throttled_packets_dropped));
            info!("│  Total Blocked IP:             {:>10}   ", common::format_rate(current_stats.blocked_ip_packets_dropped));
            info!("└─────────────────────────────────────────────────────────────────────────────────────────┘");
            
            // Calculate and display percentage breakdown if there are drops
            if current_stats.packets_dropped > 0 {
                let syn_pct = (current_stats.syn_packets_dropped as f64 / current_stats.packets_dropped as f64) * 100.0;
                let bypass_pct = (current_stats.tcp_bypass_dropped as f64 / current_stats.packets_dropped as f64) * 100.0;
                let invalid_pct = (current_stats.invalid_packets_dropped as f64 / current_stats.packets_dropped as f64) * 100.0;
                let throttled_pct = (current_stats.throttled_packets_dropped as f64 / current_stats.packets_dropped as f64) * 100.0;
                let blocked_pct = (current_stats.blocked_ip_packets_dropped as f64 / current_stats.packets_dropped as f64) * 100.0;
                
                info!("┌─────────────────────────────────────────────────────────────────────────────────────────┐");
                info!("│ Drop Reason Distribution                                                                │");
                info!("├─────────────────────────────────────────────────────────────────────────────────────────┤");
                info!("│  SYN Floods:      {:>6.2}%  │  TCP Bypass: {:>6.2}%  │  Invalid: {:>6.2}% ", syn_pct, bypass_pct, invalid_pct);
                info!("│  Throttled:       {:>6.2}%  │  Blocked IP: {:>6.2}%                       ", throttled_pct, blocked_pct);
                info!("└─────────────────────────────────────────────────────────────────────────────────────────┘");
            }
        }
        
        // Store current statistics for next iteration's rate calculation
        prev_stats = current_stats;
        
        // Release the map lock before sleeping
        drop(map);
        
        // Wait for next display interval or shutdown signal
        let guard = dummy_mutex
            .lock()
            .map_err(|e| anyhow::anyhow!("Dummy mutex poisoned: {}", e))?;
        let _ = condvar
            .wait_timeout(guard, Duration::from_secs(STATS_DISPLAY_INTERVAL))
            .map_err(|e| anyhow::anyhow!("condvar wait_timeout poisoned: {}", e))?;
    }
    
    debug!("Statistics display thread shutting down");
    Ok(())
}

/// Spawns a thread to periodically clear connection throttle counters
fn spawn_connection_throttle_clear(
    name: &'static str,
    running: Arc<AtomicBool>,
    condvar: Arc<Condvar>,
    connection_throttle_ref: Arc<Mutex<HashMap<MapData, u32, u32>>>,
) -> Result<thread::JoinHandle<()>, anyhow::Error> {
    thread::Builder::new()
        .name(name.into())
        .spawn(move || {
            if let Err(e) =
                connection_throttle_clear(running.clone(), condvar.clone(), connection_throttle_ref)
            {
                error!("Failed to clear connection throttles: {:?}", e);
                shutdown(running, condvar);
            }
        })
        .map_err(|e| e.into())
}

/// Clears all connection throttle counters every THROTTLE_CLEAR_CYCLE seconds
/// This resets the rate limiting, allowing IPs to attempt connections again
fn connection_throttle_clear(
    running: Arc<AtomicBool>,
    condvar: Arc<Condvar>,
    connection_throttle_ref: Arc<Mutex<HashMap<MapData, u32, u32>>>,
) -> Result<(), anyhow::Error> {
    let dummy_mutex = Mutex::new(());
    while running.load(Ordering::SeqCst) {
        let mut map = connection_throttle_ref
            .lock()
            .map_err(|e| anyhow::anyhow!("Mutex poisoned: {}", e))?;
        
        // Collect all keys to remove
        let all = map
            .iter()
            .filter_map(|res| {
                match res {
                    Ok((key, _)) => Some(key),
                    Err(_) => None, // skip errors
                }
            })
            .collect::<Vec<u32>>();
        
        // Remove all throttle entries to reset counters
        all.iter().for_each(|key| {
            map.remove(key).ok();
        });
        
        debug!("Cleared {} throttle entries", all.len());
        
        let guard = dummy_mutex
            .lock()
            .map_err(|e| anyhow::anyhow!("Dummy Mutex poisoned: {}", e))?;
        let _ = condvar
            .wait_timeout(guard, Duration::from_secs(THROTTLE_CLEAR_CYCLE))
            .map_err(|e| anyhow::anyhow!("condvar wait_timeout poisoned: {}", e))?;
    }
    Ok(())
}

/// Spawns a thread to periodically remove old/inactive connections
fn spawn_old_connection_clear(
    name: &'static str,
    running: Arc<AtomicBool>,
    condvar: Arc<Condvar>,
    player_connection_map_ref: Arc<Mutex<HashMap<MapData, Ipv4FlowKey, u64>>>,
) -> Result<thread::JoinHandle<()>, anyhow::Error> {
    thread::Builder::new()
        .name(name.into())
        .spawn(move || {
            if let Err(e) =
                clear_old_connections(running.clone(), condvar.clone(), player_connection_map_ref)
            {
                error!("Failed to clear old connections: {:?}", e);
                shutdown(running, condvar);
            }
        })
        .map_err(|e| e.into())
}

/// Removes connections that haven't had activity for OLD_CONNECTION_TIMEOUT seconds
/// This prevents the connection map from growing indefinitely
fn clear_old_connections(
    running: Arc<AtomicBool>,
    condvar: Arc<Condvar>,
    player_connection_map_ref: Arc<Mutex<HashMap<MapData, Ipv4FlowKey, u64>>>,
) -> Result<(), anyhow::Error> {
    let dummy_mutex = Mutex::new(());
    while running.load(Ordering::SeqCst) {
        let now = uptime_nanos()?;
        debug!("Checking for old connections... {:?}", now);
        let mut amount = 0;
        let mut map = player_connection_map_ref
            .lock()
            .map_err(|e| anyhow::anyhow!("Mutex poisoned: {}", e))?;

        // Find connections that have timed out
        let to_remove = map
            .iter()
            .filter_map(|res| {
                amount += 1;
                match res {
                    Ok((key, last_update)) => {
                        // Check if connection has been inactive for too long
                        if last_update + (OLD_CONNECTION_TIMEOUT * SECOND_TO_NANOS) < now {
                            Some(key)
                        } else {
                            None
                        }
                    }
                    Err(_) => None, // skip errors
                }
            })
            .collect::<Vec<Ipv4FlowKey>>();

        debug!("Map had {} entries, {} will be removed", amount, to_remove.len());

        // Remove timed out connections
        to_remove.iter().for_each(|key| {
            let result = map.remove(key);
            if result.is_err() {
                error!(
                    "Failed to remove connection for key {}: {:?}",
                    common::flow_key_to_string(key),
                    result.err()
                );
            } else {
                debug!("Removed old connection: {}", common::flow_key_to_string(key));
            }
        });

        let guard = dummy_mutex
            .lock()
            .map_err(|e| anyhow::anyhow!("Dummy Mutex poisoned: {}", e))?;
        let _ = condvar
            .wait_timeout(guard, Duration::from_secs(OLD_CONNECTION_TIMEOUT))
            .map_err(|e| anyhow::anyhow!("condvar wait_timeout poisoned: {}", e))?;
    }
    Ok(())
}

/// Spawns a thread to periodically unblock IPs that have served their ban duration
fn spawn_block_clear(
    name: &'static str,
    running: Arc<AtomicBool>,
    condvar: Arc<Condvar>,
    blocked_ips_ref: Arc<Mutex<HashMap<MapData, u32, u64>>>,
) -> Result<thread::JoinHandle<()>, anyhow::Error> {
    thread::Builder::new()
        .name(name.into())
        .spawn(move || {
            if let Err(e) = block_clear(running.clone(), condvar.clone(), blocked_ips_ref) {
                error!("Failed to clear blocked IPs: {:?}", e);
                shutdown(running, condvar);
            }
        })
        .map_err(|e| e.into())
}

/// Removes IP addresses from the block list after BLOCKED_IP_TIMEOUT seconds
/// This implements temporary bans that automatically expire
fn block_clear(
    running: Arc<AtomicBool>,
    condvar: Arc<Condvar>,
    blocked_ips_ref: Arc<Mutex<HashMap<MapData, u32, u64>>>,
) -> Result<(), anyhow::Error> {
    let dummy_mutex = Mutex::new(());
    while running.load(Ordering::SeqCst) {
        let now = uptime_nanos()?;
        let mut map = blocked_ips_ref
            .lock()
            .map_err(|e| anyhow::anyhow!("Mutex poisoned: {}", e))?;
        
        // Find IPs whose block time has expired
        let to_remove = map
            .iter()
            .filter_map(|res| {
                match res {
                    Ok((key, block_time)) => {
                        // Check if ban duration has expired
                        if block_time + (BLOCKED_IP_TIMEOUT * SECOND_TO_NANOS) < now {
                            Some(key)
                        } else {
                            None
                        }
                    }
                    Err(_) => None, // skip errors
                }
            })
            .collect::<Vec<u32>>();
        
        // Unblock expired IPs
        to_remove.iter().for_each(|key| {
            let result = map.remove(key);
            if result.is_err() {
                error!(
                    "Failed to remove blocked IP {}: {:?}",
                    common::network_address_to_string(*key),
                    result.err()
                );
            } else {
                info!("Unblocked IP: {}", common::network_address_to_string(*key));
            }
        });
        
        let guard = dummy_mutex
            .lock()
            .map_err(|e| anyhow::anyhow!("Dummy Mutex poisoned: {}", e))?;
        let _ = condvar
            .wait_timeout(guard, Duration::from_secs(BLOCKED_IP_TIMEOUT))
            .map_err(|e| anyhow::anyhow!("condvar wait_timeout poisoned: {}", e))?;
    }
    Ok(())
}

/// Gets system uptime in nanoseconds using CLOCK_BOOTTIME
/// This is used for calculating timeouts and time-based cleanup operations
fn uptime_nanos() -> Result<u64, anyhow::Error> {
    let mut ts = timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let res = unsafe { clock_gettime(CLOCK_BOOTTIME, &mut ts) };
    if res == 0 {
        Ok((ts.tv_sec as u64) * SECOND_TO_NANOS + (ts.tv_nsec as u64))
    } else {
        Err(anyhow::anyhow!("Failed to get uptime"))
    }
}
