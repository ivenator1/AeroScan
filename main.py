import time
import subprocess
import re
from prometheus_client import start_http_server, Gauge
import speedtest

# Define Prometheus gauges for our metrics
PING_RESPONSE_TIME = Gauge('network_ping_response_time_ms', 'Ping response time in ms')
NETWORK_TTL = Gauge('network_ttl', 'Ping TTL value')
SPEEDTEST_PING = Gauge('speedtest_ping_ms', 'Speedtest ping in ms')
DOWNLOAD_SPEED = Gauge('download_speed_mbps', 'Download speed in Mbps')
UPLOAD_SPEED = Gauge('upload_speed_mbps', 'Upload speed in Mbps')

def run_ping(target="8.8.8.8"):
    """Run the ping command and update Prometheus metrics."""
    try:
        # Run ping with 1 packet and 1 second timeout
        result = subprocess.run(
            ["ping", "-c", "1", "-w", "1", target],
            capture_output=True,
            text=True,
            check=True
        )
        output = result.stdout

        # Extract TTL and response time from the output using regex
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

def run_speedtest():
    """Run speedtest and update Prometheus metrics."""
    try:
        st = speedtest.Speedtest()
        st.get_best_server()
        # Execute download and upload tests (results in bits per second)
        download_bps = st.download()
        upload_bps = st.upload()
        results = st.results.dict()

        # Set speedtest metrics
        ping_value = results.get('ping', None)
        if ping_value is not None:
            SPEEDTEST_PING.set(ping_value)
        DOWNLOAD_SPEED.set(download_bps / 1e6)  # Convert bps to Mbps
        UPLOAD_SPEED.set(upload_bps / 1e6)      # Convert bps to Mbps

        print(f"Speedtest: Ping={ping_value} ms, Download={download_bps / 1e6:.2f} Mbps, Upload={upload_bps / 1e6:.2f} Mbps")
    except Exception as e:
        print("Speedtest failed:", e)

def main():
    # Start the Prometheus metrics HTTP server on port 8000.
    start_http_server(8000)
    print("Prometheus metrics available at http://localhost:8000/metrics")

    # Interval (in seconds) between tests
    interval = 30

    while True:
        run_ping()
        run_speedtest()
        time.sleep(interval)

if __name__ == '__main__':
    main()
