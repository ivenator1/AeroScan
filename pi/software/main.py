import time
import subprocess
import re
import multiprocessing
from prometheus_client import start_http_server, Gauge
import speedtest
import RPi.GPIO as GPIO
import os
import base64

# --- Configuration ---
PROMETHEUS_PORT = 8000
PING_TARGET = "1.1.1.1"
WIRELESS_INTERFACE = "wlan0"  # Change if your wireless interface differs

# Button Pins (BCM numbering) - Connect each to GND via a button
BUTTON_PIN_1 = 23
BUTTON_PIN_2 = 24

# Intervals
LOOP_SLEEP_INTERVAL = 0.1 # Main loop check frequency (seconds)
PING_SCAN_IP_INTERVAL = 30   # How often to run ping, scan, wireless metrics, IP check (seconds)
SPEEDTEST_CHECK_INTERVAL = 60 # How often to start/check speedtest (seconds) - should be >= PING_SCAN_IP_INTERVAL

# File to store the persistent identifier
IDENTIFIER_FILE = "/var/local/network_monitor_identifier.txt"
# --- End Configuration ---

# --- Prometheus Gauges ---
PING_RESPONSE_TIME = Gauge('network_ping_response_time_ms', 'Ping response time in ms (first packet)')
NETWORK_TTL = Gauge('network_ttl', 'Ping TTL value (first packet)')
SPEEDTEST_PING = Gauge('speedtest_ping_ms', 'Speedtest ping in ms')
DOWNLOAD_SPEED = Gauge('download_speed_mbps', 'Download speed in Mbps')
UPLOAD_SPEED = Gauge('upload_speed_mbps', 'Upload speed in Mbps')
SIGNAL_STRENGTH = Gauge('signal_strength_dbm', 'Signal strength of connected network in dBm')
NETWORK_JITTER = Gauge('network_jitter_ms', 'Network jitter in ms (calculated from 5 packets)')
LINK_QUALITY = Gauge('link_quality_percentage', 'Link quality of connected network in percentage')
WIFI_AP_SIGNAL = Gauge('wifi_ap_signal_strength_dbm', 'Signal strength of nearby WiFi APs', ['ssid', 'bssid', 'channel'])
DEVICE_IDENTIFIER = Gauge('device_unique_identifier', 'Unique identifier for the device (SN-Base64Timestamp)', ['identifier'])
NETWORK_INTERFACE_INFO = Gauge('network_interface_info', 'Basic network interface information (IP Address)', ['interface', 'ip_address'])
# --- End Prometheus Gauges ---

# --- Global Variables ---
current_device_id_label = None
raspberry_pi_serial = None
buttons_currently_pressed = False
last_check_times = {
    "ping_scan_ip": 0, # Combined schedule
    "speedtest": 0,
}
speedtest_process = None
speedtest_queue = None
# Dictionary to store current IP labels {interface: ip_address_string}
current_ip_labels = {}
# --- End Global Variables ---


# --- Functions for Network Metrics ---

def run_ping_checks(target=PING_TARGET):
    """
    Run ping with 5 packets to get first packet RTT, TTL, and calculate jitter.
    Updates PING_RESPONSE_TIME, NETWORK_TTL, and NETWORK_JITTER gauges.
    """
    response_time = -1
    ttl = -1
    jitter = -1
    print(f"Running ping checks to {target}...")

    try:
        result = subprocess.run(
            ["ping", "-c", "5", "-w", "5", target], # 5 packets, 5 second overall timeout
            capture_output=True,
            text=True,
            check=True, # Raises error on non-zero exit (e.g., host unreachable)
            timeout=6 # Slightly longer subprocess timeout
        )
        output = result.stdout
        # Find all time= and ttl= matches
        times_matches = re.findall(r"time=([\d\.]+)", output)
        ttl_matches = re.findall(r"ttl=(\d+)", output)

        times = list(map(float, times_matches))

        if times:
            # Get RTT and TTL from the first successful reply
            response_time = times[0]
            if ttl_matches:
                ttl = int(ttl_matches[0])
            print(f"  Ping First Reply: RTT={response_time:.2f} ms, TTL={ttl if ttl != -1 else 'N/A'}")
        else:
            print("  Ping: No replies received.")

        # Calculate Jitter if we have at least 2 replies
        if len(times) >= 2:
            diffs = [abs(times[i+1] - times[i]) for i in range(len(times) - 1)]
            jitter = sum(diffs) / len(diffs)
            print(f"  Ping Jitter: {jitter:.2f} ms (from {len(times)} replies)")
        elif len(times) == 1:
            jitter = 0 # No jitter possible with only one reply
            print("  Ping Jitter: 0 ms (only 1 reply)")
        else:
            # Jitter remains -1 if no replies
             print("  Ping Jitter: N/A (no replies)")


    except subprocess.TimeoutExpired:
        print(f"  Ping command timed out for {target}")
        # Metrics already default to -1
    except subprocess.CalledProcessError as e:
        # This often means host is unreachable or packets were lost completely
        # Try parsing output anyway in case some packets got through before failure
        output = e.stdout + e.stderr
        times_matches = re.findall(r"time=([\d\.]+)", output)
        ttl_matches = re.findall(r"ttl=(\d+)", output)
        times = list(map(float, times_matches))
        if times:
             response_time = times[0]
             if ttl_matches:
                 ttl = int(ttl_matches[0])
             if len(times) >= 2:
                 diffs = [abs(times[i+1] - times[i]) for i in range(len(times) - 1)]
                 jitter = sum(diffs) / len(diffs)
             elif len(times) == 1:
                 jitter = 0
        print(f"  Ping command failed for {target} (Exit code: {e.returncode}). Partial data? RTT={response_time}, TTL={ttl}, Jitter={jitter}. Error: {e.stderr.strip()}")

    except Exception as e:
        print(f"  Error in run_ping_checks: {e}")
        # Metrics already default to -1

    # Update Prometheus Gauges
    PING_RESPONSE_TIME.set(response_time)
    NETWORK_TTL.set(ttl)
    NETWORK_JITTER.set(jitter)

# (update_wireless_metrics, run_speedtest_child, scan_wifi_aps - unchanged)
def update_wireless_metrics(interface=WIRELESS_INTERFACE):
    """
    Update connected wireless metrics (signal strength and link quality) using iwconfig.
    """
    signal_level = -1 # Default to error value
    quality_percentage = -1 # Default to error value
    print(f"Checking wireless metrics for {interface}...")
    try:
        result = subprocess.run(
            ["iwconfig", interface],
            capture_output=True,
            text=True,
            check=True,
            timeout=5 # Add timeout
        )
        output = result.stdout

        link_quality_match = re.search(r"Link Quality=(\d+)/(\d+)", output)
        if link_quality_match:
            quality_current = int(link_quality_match.group(1))
            quality_max = int(link_quality_match.group(2))
            if quality_max > 0:
                 quality_percentage = (quality_current / quality_max) * 100
            else:
                 quality_percentage = 0

        signal_level_match = re.search(r"Signal level=(-?\d+)\s*dBm", output)
        if signal_level_match:
            signal_level = int(signal_level_match.group(1))

        LINK_QUALITY.set(quality_percentage)
        SIGNAL_STRENGTH.set(signal_level)

        print(f"  Wireless Metrics: Signal={signal_level if signal_level != -1 else 'N/A'} dBm, Quality={quality_percentage:.1f}%" if quality_percentage != -1 else 'N/A')

    except subprocess.TimeoutExpired:
        print(f"  iwconfig command timed out for {interface}")
        SIGNAL_STRENGTH.set(-1)
        LINK_QUALITY.set(-1)
    except subprocess.CalledProcessError as e:
        print(f"  Failed to get wireless metrics for {interface} (is it up and wireless?): {e}")
        SIGNAL_STRENGTH.set(-1)
        LINK_QUALITY.set(-1)
    except Exception as e:
        print(f"  Error in update_wireless_metrics: {e}")
        SIGNAL_STRENGTH.set(-1)
        LINK_QUALITY.set(-1)

def run_speedtest_child(result_queue):
    """
    Child process function that runs the speedtest.
    Puts results {'ping', 'download', 'upload'} (Mbps) into the queue. Sends -1 on failure.
    """
    result_data = {'ping': -1, 'download': -1, 'upload': -1}
    try:
        print("  Starting speedtest process...")
        st = speedtest.Speedtest(secure=True)
        try:
            st.get_best_server()
        except speedtest.SpeedtestException as e:
            print(f"  Could not get speedtest server: {e}")
            result_queue.put(result_data)
            return

        try:
            download_bps = st.download()
            result_data['download'] = download_bps / 1e6
        except speedtest.SpeedtestException as e:
             print(f"  Speedtest download failed: {e}")

        try:
            upload_bps = st.upload()
            result_data['upload'] = upload_bps / 1e6
        except speedtest.SpeedtestException as e:
             print(f"  Speedtest upload failed: {e}")

        results_dict = st.results.dict()
        result_data['ping'] = results_dict.get('ping', -1)

        print(f"  Speedtest Finished: Ping={result_data['ping']:.2f} ms, "
              f"Download={result_data['download']:.2f} Mbps, "
              f"Upload={result_data['upload']:.2f} Mbps")

    except Exception as e:
        print(f"  Speedtest process failed unexpectedly: {e}")
        result_data = {'ping': -1, 'download': -1, 'upload': -1}
    finally:
        result_queue.put(result_data)

def scan_wifi_aps(interface=WIRELESS_INTERFACE):
    """Scans for WiFi APs and updates Prometheus metrics."""
    print(f"Scanning for WiFi APs on {interface}...")
    aps = []
    try:
        if os.geteuid() != 0:
            print("  Warning: 'iwlist scan' may require root privileges.")
            cmd = ["iwlist", interface, "scan"]
        else:
            cmd = ["iwlist", interface, "scan"]

        result = subprocess.run(
            cmd, capture_output=True, text=True, check=True, timeout=15
        )
        output = result.stdout
        cell_blocks = output.split("Cell ")
        for block in cell_blocks[1:]:
            bssid_match = re.search(r"Address: (([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})", block)
            ssid_match = re.search(r'ESSID:"([^"]*)"', block)
            if not ssid_match:
                 ssid_match = re.search(r'ESSID:([^\n]+)', block)
            channel_match = re.search(r"Channel:(\d+)", block)
            if not channel_match:
                freq_match = re.search(r"Frequency:[\d\.]+ GHz \(Channel (\d+)\)", block)
                if freq_match: channel_match = freq_match
            signal_match = re.search(r"Signal level(?:[:=])(-?\d+)\s*dBm", block)

            if bssid_match and ssid_match and channel_match and signal_match:
                bssid = bssid_match.group(1)
                ssid = ssid_match.group(1).strip()
                if not ssid: ssid = "<hidden>"
                if 'GHz' in channel_match.string and len(channel_match.groups()) > 1: channel = channel_match.group(2)
                else: channel = channel_match.group(1)
                signal_strength = int(signal_match.group(1))
                aps.append({'ssid': ssid, 'bssid': bssid, 'channel': channel, 'signal': signal_strength})

    except subprocess.TimeoutExpired: print(f"  iwlist scan command timed out for {interface}")
    except subprocess.CalledProcessError as e: print(f"  Failed to run iwlist scan on {interface}: {e}")
    except FileNotFoundError: print("  Error: 'iwlist' command not found. Is 'wireless-tools' installed?")
    except Exception as e: print(f"  Error during WiFi AP scan: {e}")

    WIFI_AP_SIGNAL.clear()
    if aps:
        print(f"  Found {len(aps)} APs.")
        reported_aps = set()
        for ap in aps:
            label_tuple = (ap['ssid'], ap['bssid'], ap['channel'])
            if label_tuple not in reported_aps:
                try:
                    WIFI_AP_SIGNAL.labels(ssid=ap['ssid'], bssid=ap['bssid'], channel=ap['channel']).set(ap['signal'])
                    reported_aps.add(label_tuple)
                except Exception as label_err:
                    sanitized_ssid = re.sub(r'[^a-zA-Z0-9_:]', '_', ap.get('ssid', 'N/A'))
                    print(f"  Error setting label for AP {ap.get('ssid', 'N/A')} (BSSID: {ap.get('bssid','N/A')}). Sanitized: {sanitized_ssid}. Error: {label_err}")
    else:
        print("  No APs found in scan.")

# --- Function for Device IP ---
def update_device_ip(interface=WIRELESS_INTERFACE):
    """Gets the device's IPv4 address for the specified interface and updates Prometheus."""
    global current_ip_labels
    print(f"Checking IP address for {interface}...")
    current_ip = None
    try:
        # Use 'ip addr show' command - more modern than ifconfig
        result = subprocess.run(
            ["ip", "-4", "addr", "show", interface], # -4 forces IPv4
            capture_output=True,
            text=True,
            check=True, # Raise error if interface doesn't exist or command fails
            timeout=3
        )
        output = result.stdout
        # Regex to find "inet" line and extract the IP address
        ip_match = re.search(r"inet\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/", output)

        if ip_match:
            current_ip = ip_match.group(1)
            print(f"  Found IP: {current_ip}")
        else:
            print(f"  No IPv4 address found for {interface}.")

    except FileNotFoundError:
        print("  Error: 'ip' command not found. Is 'iproute2' package installed?")
    except subprocess.TimeoutExpired:
        print(f"  'ip addr show' command timed out for {interface}")
    except subprocess.CalledProcessError as e:
        # Interface might be down or not exist
        print(f"  Failed to get IP for {interface} (is it up?): {e}")
    except Exception as e:
        print(f"  Error getting IP address: {e}")

    # --- Update Prometheus ---
    last_known_ip = current_ip_labels.get(interface)

    # If IP changed or was previously unknown
    if current_ip != last_known_ip:
        # Remove the old label set for this interface, if one existed
        if last_known_ip:
            try:
                NETWORK_INTERFACE_INFO.remove(interface, last_known_ip)
                print(f"  Removed old IP label: {interface} / {last_known_ip}")
            except KeyError:
                print(f"  Old IP label {interface} / {last_known_ip} not found for removal (OK).")
            except Exception as e:
                print(f"  Error removing old IP label {interface} / {last_known_ip}: {e}")

        # Add the new label set if we found an IP
        if current_ip:
            try:
                NETWORK_INTERFACE_INFO.labels(interface=interface, ip_address=current_ip).set(1)
                current_ip_labels[interface] = current_ip # Store the new IP
                print(f"  Set new IP label: {interface} / {current_ip}")
            except Exception as e:
                print(f"  Error setting new IP label {interface} / {current_ip}: {e}")
                # If setting failed, clear our record of it
                if interface in current_ip_labels: del current_ip_labels[interface]
        else:
             # If no IP found now, ensure we don't have a stale record
             if interface in current_ip_labels: del current_ip_labels[interface]

    # Else: IP is the same as last check, do nothing to the metric

# --- Functions for Unique Identifier ---
# (get_raspberry_pi_serial, generate_new_identifier, save_identifier, load_identifier,
# update_prometheus_identifier, handle_identifier_update - unchanged)
def get_raspberry_pi_serial():
    global raspberry_pi_serial
    if raspberry_pi_serial: return raspberry_pi_serial
    try:
        with open('/proc/cpuinfo', 'r') as f:
            for line in f:
                if line.startswith('Serial'):
                    serial_match = re.search(r":\s*([0-9a-fA-F]+)$", line)
                    if serial_match:
                        raspberry_pi_serial = serial_match.group(1)
                        # print(f"Found Serial: {raspberry_pi_serial}")
                        return raspberry_pi_serial
    except Exception: pass # Ignore errors reading serial
    raspberry_pi_serial = "UnknownSN"
    print("Warning: Could not determine Raspberry Pi serial number.")
    return raspberry_pi_serial

def generate_new_identifier():
    serial = get_raspberry_pi_serial()
    timestamp_int = int(time.time())
    timestamp_bytes = timestamp_int.to_bytes(8, byteorder='big')
    timestamp_b64_bytes = base64.b64encode(timestamp_bytes)
    timestamp_b64_str = timestamp_b64_bytes.decode('utf-8')
    new_identifier = f"{serial}-{timestamp_b64_str}"
    return new_identifier

def save_identifier(identifier):
    try:
        os.makedirs(os.path.dirname(IDENTIFIER_FILE), exist_ok=True)
        with open(IDENTIFIER_FILE, 'w') as f: f.write(identifier)
        print(f"  Identifier saved to {IDENTIFIER_FILE}")
        return True
    except Exception as e:
        print(f"  ERROR: Could not write identifier file {IDENTIFIER_FILE}: {e}")
        return False

def load_identifier():
    if os.path.exists(IDENTIFIER_FILE):
        try:
            with open(IDENTIFIER_FILE, 'r') as f: identifier = f.read().strip()
            if identifier:
                print(f"Loaded identifier from {IDENTIFIER_FILE}: {identifier}")
                return identifier
        except Exception as e: print(f"Error reading identifier file {IDENTIFIER_FILE}: {e}")
    return None

def update_prometheus_identifier(new_identifier):
    global current_device_id_label
    print(f"  Updating Prometheus identifier metric to: {new_identifier}")
    old_label_to_remove = current_device_id_label
    try:
        DEVICE_IDENTIFIER.labels(identifier=new_identifier).set(1)
        current_device_id_label = new_identifier
        # print(f"  Set new Prometheus identifier label: {new_identifier}")
    except Exception as e:
        print(f"  ERROR setting new Prometheus identifier label '{new_identifier}': {e}")
        return # Abort update if we can't set the new label
    if old_label_to_remove and old_label_to_remove != new_identifier:
        try: DEVICE_IDENTIFIER.remove(old_label_to_remove)
        except KeyError: pass # Ignore if not found
        except Exception as e: print(f"  ERROR removing old Prometheus ID label '{old_label_to_remove}': {e}")

def handle_identifier_update():
    print("\n--- Generating New Identifier ---")
    new_id = generate_new_identifier()
    save_identifier(new_id)
    update_prometheus_identifier(new_id)
    print("--- Identifier Update Complete ---\n")


# --- GPIO Setup and Button Check ---
# (setup_gpio, check_buttons - unchanged)
def setup_gpio():
    """Configures the GPIO pins for the buttons."""
    try:
        GPIO.setwarnings(False) # Disable warnings about channel usage
        GPIO.setmode(GPIO.BCM) # Use Broadcom pin numbering
        GPIO.setup(BUTTON_PIN_1, GPIO.IN, pull_up_down=GPIO.PUD_UP)
        GPIO.setup(BUTTON_PIN_2, GPIO.IN, pull_up_down=GPIO.PUD_UP)
        print(f"GPIO pins {BUTTON_PIN_1} and {BUTTON_PIN_2} setup complete. Polling for button presses...")
        return True
    except RuntimeError as e:
         print(f"Error setting up GPIO: {e}. Requires root/sudo? RPi.GPIO installed?")
         return False
    except Exception as e:
        print(f"An unexpected error occurred during GPIO setup: {e}")
        return False

def check_buttons():
    """Checks the state of the two buttons and triggers update if both pressed."""
    global buttons_currently_pressed
    try:
        button1_state = GPIO.input(BUTTON_PIN_1)
        button2_state = GPIO.input(BUTTON_PIN_2)
        if button1_state == GPIO.LOW and button2_state == GPIO.LOW:
            if not buttons_currently_pressed:
                print(f"\nButton press detected on pins {BUTTON_PIN_1} and {BUTTON_PIN_2}!")
                handle_identifier_update()
                buttons_currently_pressed = True
        else:
            if buttons_currently_pressed: print("Buttons released.")
            buttons_currently_pressed = False
    except RuntimeError: print("Error reading GPIO state. Check permissions/hardware.")
    except Exception as e: print(f"An unexpected error occurred during button check: {e}")


# --- Main Execution ---
def main():
    global last_check_times, speedtest_process, speedtest_queue

    # Initial checks
    if os.geteuid() != 0:
        print("Warning: Root privileges recommended for full functionality.")
        time.sleep(2)
    # Ensure iproute2 package is likely installed
    if subprocess.run(["which", "ip"], capture_output=True).returncode != 0:
        print("Error: 'ip' command not found. Please install 'iproute2' package (e.g., sudo apt install iproute2).")
        # return # Optionally exit if core command is missing

    # Start Prometheus server
    try:
        start_http_server(PROMETHEUS_PORT)
        print(f"Prometheus metrics server started on port {PROMETHEUS_PORT}")
    except Exception as e:
        print(f"Error starting Prometheus server: {e}\nExiting.")
        return

    # Setup GPIO
    gpio_ok = setup_gpio()
    if not gpio_ok: print("Warning: GPIO setup failed. Button press disabled.")

    # Initial Identifier
    initial_id = load_identifier() or generate_new_identifier()
    if not os.path.exists(IDENTIFIER_FILE): save_identifier(initial_id)
    update_prometheus_identifier(initial_id)

    # Initialize timers
    now = time.time()
    last_check_times["ping_scan_ip"] = now - PING_SCAN_IP_INTERVAL - 1
    last_check_times["speedtest"] = now - SPEEDTEST_CHECK_INTERVAL - 1


    try:
        while True:
            current_time = time.time()

            # Check Buttons (runs every loop)
            if gpio_ok: check_buttons()

            # Scheduled Network/Scan/IP Checks
            if current_time - last_check_times["ping_scan_ip"] >= PING_SCAN_IP_INTERVAL:
                print(f"\n--- Running Scheduled Checks (Interval: {PING_SCAN_IP_INTERVAL}s) ---")
                run_ping_checks() # Combined ping RTT, TTL, Jitter
                update_wireless_metrics(WIRELESS_INTERFACE) # Connected Signal/Quality
                scan_wifi_aps(WIRELESS_INTERFACE)           # Scan nearby APs
                update_device_ip(WIRELESS_INTERFACE)        # Get device IP
                last_check_times["ping_scan_ip"] = current_time
                print("--- Scheduled Checks Complete ---")

            # Scheduled Speedtest Start
            if current_time - last_check_times["speedtest"] >= SPEEDTEST_CHECK_INTERVAL:
                if speedtest_process is None:
                    print(f"\n--- Starting New Speedtest (Interval: {SPEEDTEST_CHECK_INTERVAL}s) ---")
                    speedtest_queue = multiprocessing.Queue()
                    speedtest_process = multiprocessing.Process(target=run_speedtest_child, args=(speedtest_queue,), daemon=True)
                    speedtest_process.start()
                    last_check_times["speedtest"] = current_time
                # else: print(f"({time.strftime('%H:%M:%S')}) Speedtest interval elapsed, but previous test still running.")

            # Check for Speedtest Results (runs frequently)
            if speedtest_queue is not None:
                try:
                    result = speedtest_queue.get_nowait()
                    print("\n--- Processing Speedtest Results ---")
                    SPEEDTEST_PING.set(result['ping'])
                    DOWNLOAD_SPEED.set(result['download'])
                    UPLOAD_SPEED.set(result['upload'])
                    if speedtest_process is not None: speedtest_process.join(timeout=0.5)
                    speedtest_process = None
                    if speedtest_queue:
                        speedtest_queue.close()
                        try: speedtest_queue.join_thread()
                        except Exception: pass
                    speedtest_queue = None
                    print("--- Speedtest Results Processed ---")
                except multiprocessing.queues.Empty:
                    if speedtest_process and not speedtest_process.is_alive():
                         print("\n--- Speedtest process ended unexpectedly without result ---")
                         print(f"Exit code: {speedtest_process.exitcode}")
                         speedtest_process.join(timeout=0)
                         speedtest_process = None; speedtest_queue = None
                         SPEEDTEST_PING.set(-1); DOWNLOAD_SPEED.set(-1); UPLOAD_SPEED.set(-1)
                except Exception as e:
                    print(f"\n--- Error processing speedtest queue: {e} ---")
                    if speedtest_process and speedtest_process.is_alive(): speedtest_process.terminate(); speedtest_process.join(timeout=1)
                    speedtest_process = None; speedtest_queue = None
                    SPEEDTEST_PING.set(-1); DOWNLOAD_SPEED.set(-1); UPLOAD_SPEED.set(-1)

            # Main Loop Sleep
            time.sleep(LOOP_SLEEP_INTERVAL)

    except KeyboardInterrupt: print("\nShutdown requested.")
    finally:
        if gpio_ok: print("Cleaning up GPIO..."); GPIO.cleanup()
        if speedtest_process and speedtest_process.is_alive(): print("Terminating speedtest process..."); speedtest_process.terminate(); speedtest_process.join(timeout=2)
        print("Shutdown complete.")


if __name__ == '__main__':
    main()
