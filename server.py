"""
Aditya Dawadikar
Aniket Mali
"""

# ========== server.py ==========

import socket
from threading import Thread, Lock
import time
import signal
import sys

# Constants
TOTAL = 10_000_000       # Total number of packets expected
CHUNK = 4                # Sequence increment size
LIMIT = 65536            # Wrap-around limit for sequence number

# Global State Variables
ACK_COUNT = 0            # Acknowledged packet count
CUR_SEQ = 0              # Current sequence number
EXPECT = 1               # Next expected sequence number from client
CID = ''                 # Client ID
LAGGED = []              # List of missing packets (lagged)
OBSERVED = []            # Recently observed packet sequence numbers
YIELD = []               # Placeholder (not used in code)
SEQ_BATCH = []           # Temporary list for a received batch of packets
_frag = ''               # Placeholder for incomplete data (unused)
B_WIDTH = 8192           # Bandwidth size for receiving data
_last_activity = time.time()  # Timestamp for last client activity
_server_running = True   # Control server loop

# Logs for sequence tracking and efficiency
sink_seq = open(f"rx_{int(time.time())}.csv", "w")
sink_seq.write("seq,time\n")
sink_eff = open(f"efficiency_{int(time.time())}.csv", "w")
sink_eff.write("received,sent,eff\n")
sink_flow = open(f"recv_winsz_{int(time.time())}.csv", "w")
sink_flow.write("recv_win,timestamp\n")

# Locks for thread-safe logging
report_lock = Lock()
flow_lock = Lock()

def reset_env():
    """Reset the server-side state variables."""
    global ACK_COUNT, CUR_SEQ, EXPECT, LAGGED, OBSERVED, YIELD, SEQ_BATCH
    ACK_COUNT = 0
    CUR_SEQ = 0
    EXPECT = 1
    LAGGED.clear()
    OBSERVED.clear()
    YIELD.clear()
    SEQ_BATCH.clear()

def pulse_monitor():
    """Monitor server idleness and print status every 5 seconds."""
    while _server_running:
        idle_time = time.time() - _last_activity
        if idle_time > 5:
            print(f"[.] Server idle for {int(idle_time)}s — ACK_COUNT: {ACK_COUNT}, Lagged: {len(LAGGED)}")
        time.sleep(5)

def handle_connection(conn):
    """Handle initial client handshake and start data streaming."""
    global ACK_COUNT, CUR_SEQ, EXPECT, CID, _last_activity

    try:
        hello = conn.recv(2048).decode()
        _last_activity = time.time()
        print(f"[*] Incoming: {hello}")

        # Initial SYN or reconnect (RCN) logic
        if hello.startswith("SYN"):
            # If a new session or fresh start required
            if ACK_COUNT < 10 or CID != hello[4:] or ACK_COUNT > TOTAL * 0.99:
                conn.sendall("NEW".encode())
                CID = hello[4:]
                reset_env()
            else:
                # Client reconnect
                conn.sendall("OLD".encode())
                if conn.recv(2048).decode().startswith("SND"):
                    conn.sendall(f'{"pkt_rec_cnt": {ACK_COUNT}, "seq_num": {CUR_SEQ}}'.encode())
        elif hello.startswith("RCN"):
            conn.sendall("SND".encode())
            CID = hello[4:]
            state = eval(conn.recv(4096).decode())
            ACK_COUNT = state['pkt_success_sent']
            CUR_SEQ = state['seq_num']
            EXPECT = CUR_SEQ + CHUNK

        stream(conn)  # Start receiving packets

    except Exception as e:
        print("[!] Handshake/stream error:", e)
    finally:
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except:
            pass
        conn.close()
        print("[*] Connection closed. Waiting for next client...")

def stream(conn):
    """Receive stream of sequence packets from client and respond with ACKs."""
    global ACK_COUNT, EXPECT, CUR_SEQ, _frag, B_WIDTH, SEQ_BATCH, _last_activity

    while ACK_COUNT < TOTAL and _server_running:
        try:
            conn.settimeout(1.0)
            data = conn.recv(B_WIDTH).decode()
            conn.settimeout(None)
        except socket.timeout:
            continue
        except Exception as e:
            print("[!] Connection error during recv:", e)
            break

        if not data:
            print("[!] Client disconnected")
            break

        _last_activity = time.time()
        SEQ_BATCH = list(map(int, data.strip().split()))

        print(f"[>] Got {len(SEQ_BATCH)} packets. First: {SEQ_BATCH[0]}, Last: {SEQ_BATCH[-1]}")

        for seq in SEQ_BATCH:
            OBSERVED.append((seq, time.time()))  # Log received sequence

            # Validate sequence order
            if seq != EXPECT:
                if seq not in LAGGED:
                    LAGGED.append(EXPECT)  # Add expected packet to lagged list
            else:
                EXPECT += CHUNK  # Update expectation to next sequence
                if EXPECT > LIMIT:
                    EXPECT = 1  # Wrap around if limit exceeded

            ACK_COUNT += 1
            try:
                conn.sendall((str(EXPECT) + " ").encode())  # Acknowledge next expected seq
            except:
                break

        # Periodically log stats in a separate thread
        if len(OBSERVED) >= 1000:
            Thread(target=log_stats, args=(OBSERVED.copy(), len(LAGGED)), daemon=True).start()
            OBSERVED.clear()

        # Log progress every 100 ACKs
        if ACK_COUNT % 100 == 0:
            print(f"[✓] Received: {ACK_COUNT}")

    # Send FIN on completion
    try:
        conn.sendall(b"FIN")
    except:
        pass

def log_stats(seq_log, misses):
    """Write received sequences and efficiency stats to log files."""
    with report_lock:
        for s, t in seq_log:
            sink_seq.write(f"{s},{t}\n")
        eff = 1 - (misses / max(1, len(seq_log)))  # Efficiency: ratio of successful to total
        sink_eff.write(f"{len(seq_log)},{len(seq_log)-misses},{eff:.3f}\n")

def graceful_exit(signum, frame):
    """Handle Ctrl+C or termination to cleanly close logs and server."""
    global _server_running
    print("\n[!] Server shutting down gracefully...")
    _server_running = False
    sink_seq.close()
    sink_eff.close()
    sink_flow.close()
    sys.exit(0)

def launch():
    """Start the TCP server and listen for incoming connections."""
    host = socket.gethostname()
    port = 4001

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(5)
    server.settimeout(1)  # Allows graceful exit from while loop

    print(f"[+] Server listening on {host}:{port}")
    Thread(target=pulse_monitor, daemon=True).start()

    while _server_running:
        try:
            conn, addr = server.accept()
            print(f"[+] Connection from {addr}")
            Thread(target=handle_connection, args=(conn,), daemon=True).start()
        except socket.timeout:
            continue
        except KeyboardInterrupt:
            graceful_exit(None, None)
        except Exception as e:
            print(f"[!] Error accepting connection: {e}")

if __name__ == '__main__':
    signal.signal(signal.SIGINT, graceful_exit)  # Ctrl+C support
    launch()
