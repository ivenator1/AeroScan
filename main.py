import time
import subprocess
import re
import multiprocessing
from prometheus_client import start_http_server, Gauge
import speedtest

# Define Prometheus gauges for our metrics
PING_RESPONSE_TIME = Gauge('network_ping_response_time_ms', 'Ping response time in ms')
NETWORK_TTL = Gauge('network_ttl', 'Ping TTL value')
SPEEDTEST_PING = Gauge('speedtest_ping_ms', 'Speedtest ping in ms')
DOWNLOAD_SPEED = Gauge('download_speed_mbps', 'Download speed in Mbps')
UPLOAD_SPEED = Gauge('upload_speed_mbps', 'Upload speed in Mbps')
SIGNAL_STRENGTH = Gauge('signal_strength_dbm', 'Signal strength in dBm')
NETWORK_JITTER = Gauge('network_jitter_ms', 'Network jitter in ms')
LINK_QUALITY = Gauge('link_quality_percentage', 'Link quality in percentage')

def run_ping(target="8.8.8.8"):
    """Run a single ping command and update basic Prometheus metrics."""
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-w", "1", target],
            capture_output=True,
            text=True,
            check=True
        )
        output = result.stdout
        ttl_match = re.search(r"ttl=(\d+)", output)
        time_match = re.search(r"time=([\d\.]+)", output)
        if ttl_match and time_match:
            ttl = int(ttl_match.group(1))
            response_time = float(time_match.group(1))
            NETWORK_TTL.set(ttl)
            PING_RESPONSE_TIME.set(response_time)
            print(f"Ping: TTL={ttl}, Response Time={response_time} ms")
        else:
            print("Ping output parsing failed.")
    except subprocess.CalledProcessError as e:
        print("Ping command failed:", e)

def run_ping_extended(target="8.8.8.8"):
    """
    Run ping with 5 packets to calculate jitter.
    
    Jitter is computed as the average absolute difference between consecutive response times.
    """
    try:
        result = subprocess.run(
            ["ping", "-c", "5", "-w", "5", target],
            capture_output=True,
            text=True,
            check=True
        )
        output = result.stdout
        times = re.findall(r"time=([\d\.]+)", output)
        times = list(map(float, times))
        if len(times) >= 2:
            diffs = [abs(times[i+1] - times[i]) for i in range(len(times) - 1)]
            jitter = sum(diffs) / len(diffs)
        else:
            jitter = 0
        NETWORK_JITTER.set(jitter)
        print(f"Extended Ping: Jitter={jitter} ms")
    except subprocess.CalledProcessError as e:
        print("Extended ping command failed:", e)
        NETWORK_JITTER.set(-1)

def update_wireless_metrics(interface="wlan0"):
    """
    Update wireless metrics (signal strength and link quality) using iwconfig.
    
    Expected output from iwconfig might include lines like:
    'Link Quality=70/70  Signal level=-39 dBm'
    """
    try:
        result = subprocess.run(
            ["iwconfig", interface],
            capture_output=True,
            text=True,
            check=True
        )
        output = result.stdout
        
        # Extract link quality (e.g., "Link Quality=70/70")
        link_quality_match = re.search(r"Link Quality=(\d+)/(\d+)", output)
        if link_quality_match:
            quality_current = int(link_quality_match.group(1))
            quality_max = int(link_quality_match.group(2))
            quality_percentage = (quality_current / quality_max) * 100
            LINK_QUALITY.set(quality_percentage)
        else:
            LINK_QUALITY.set(-1)
        
        # Extract signal level (e.g., "Signal level=-39 dBm")
        signal_level_match = re.search(r"Signal level=(-?\d+)\s*dBm", output)
        if signal_level_match:
            signal_level = int(signal_level_match.group(1))
            SIGNAL_STRENGTH.set(signal_level)
        else:
            SIGNAL_STRENGTH.set(-1)
        
        print("Wireless Metrics:",
              f"Signal Level = {signal_level_match.group(1) if signal_level_match else 'N/A'} dBm,",
              f"Link Quality = {quality_percentage if link_quality_match else 'N/A'}%")
    except subprocess.CalledProcessError as e:
        print("Failed to get wireless metrics:", e)
        SIGNAL_STRENGTH.set(-1)
        LINK_QUALITY.set(-1)
    except Exception as e:
        print("Error in update_wireless_metrics:", e)
        SIGNAL_STRENGTH.set(-1)
        LINK_QUALITY.set(-1)

def run_speedtest_child(result_queue):
    """
    Child process function that runs the speedtest.
    
    It puts a dictionary with keys 'ping', 'download', and 'upload' (converted to Mbps)
    into the provided queue. If the test fails, it sends -1 for each metric.
    """
    try:
        st = speedtest.Speedtest()
        st.get_best_server()
        download_bps = st.download()
        upload_bps = st.upload()
        results = st.results.dict()
        ping_value = results.get('ping', -1)
        result_queue.put({
            'ping': ping_value,
            'download': download_bps / 1e6,  # Convert bps to Mbps
            'upload': upload_bps / 1e6,      # Convert bps to Mbps
        })
        print(f"Speedtest: Ping={ping_value} ms, Download={download_bps / 1e6:.2f} Mbps, Upload={upload_bps / 1e6:.2f} Mbps")
    except Exception as e:
        print("Speedtest failed:", e)
        result_queue.put({
            'ping': -1,
            'download': -1,
            'upload': -1,
        })

def main():
    # Start the Prometheus metrics HTTP server on port 8000.
    start_http_server(8000)
    print("Prometheus metrics available at http://localhost:8000/metrics")
    
    interval = 30  # Interval (in seconds) between tests
    speedtest_process = None
    speedtest_queue = None
    wireless_interface = "wlan0"  # Change this if your wireless interface differs
    
    while True:
        # Run basic ping and extended ping (for jitter).
        run_ping()
        run_ping_extended()
        # Update wireless metrics (signal level and link quality).
        update_wireless_metrics(wireless_interface)
        
        # Check if a speedtest result is available.
        if speedtest_queue is not None:
            try:
                result = speedtest_queue.get_nowait()
                SPEEDTEST_PING.set(result['ping'])
                DOWNLOAD_SPEED.set(result['download'])
                UPLOAD_SPEED.set(result['upload'])
                if speedtest_process is not None:
                    speedtest_process.join(timeout=0)
                speedtest_process = None
                speedtest_queue = None
            except Exception:
                pass
        
        # If no speedtest process is running, start a new one.
        if speedtest_process is None:
            speedtest_queue = multiprocessing.Queue()
            speedtest_process = multiprocessing.Process(
                target=run_speedtest_child, args=(speedtest_queue,)
            )
            speedtest_process.start()
        
        time.sleep(interval)

if __name__ == '__main__':
    main()
