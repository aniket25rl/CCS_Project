"""
Aditya Dawadikar
Aniket Mali
"""

# ========== client.py ==========

import socket
import random
import time
from threading import Thread, Lock, Event
from collections import deque

# Constants
CLIENT_ID = "Specter"              # Identifier sent to server
PACKET_LIMIT = 10_000_000          # Total number of packets to send
INIT_SEQ = 0                       # Initial sequence number
PKT_LEN = 4                        # Sequence increment size (step per packet)
FLOW_SIZE = 1                      # Starting window size (number of packets in flight)
SEQ_WRAP = 65536                   # Sequence number wraps at this value

# Global State
_exit_flag = Event()               # Flag to indicate termination
_sent = 0                          # Successfully sent packet count
_attempts = 0                      # Total send attempts
_cur_seq = INIT_SEQ               # Current sequence number
_wsize = FLOW_SIZE                 # Current window size
_sched = []                        # Packets scheduled to send
_misses = deque()                 # Missed packets to be resent
_resend_log = [[], [], [], []]    # Retry attempts categorized by count
_seen = set()                      # Track seen packet-loop combinations
_cycle = 0                         # How many times sequence has wrapped
_created = 0                       # Total packets created (not necessarily sent)
_is_linked = False                 # Client connection status
_sock = None                       # Socket object

drp_lock = Lock()                  # Lock for thread-safe drop log
win_lock = Lock()                  # Lock for thread-safe window log

# Logging files
log_drop = open(f"drops_{int(time.time())}.csv", "w")
log_drop.write("sid,tstamp\n")
log_win = open(f"winlog_{int(time.time())}.csv", "w")
log_win.write("wsize,tstamp\n")

def should_drop():
    """Simulate 1% packet drop probability."""
    return random.random() < 0.01

def record_miss(seq, t, loop):
    """Track packet that was dropped for resend analysis."""
    pid = f"{seq}_{loop}"
    _seen.add((seq, t))
    if pid in _resend_log[0]:
        if pid in _resend_log[1]:
            if pid in _resend_log[2]:
                _resend_log[3].append(pid)
            else:
                _resend_log[2].append(pid)
        else:
            _resend_log[1].append(pid)
    else:
        _resend_log[0].append(pid)
    with drp_lock:
        log_drop.write(f"{seq},{t}\n")

def note_window(ws, t):
    """Log current window size at time t."""
    with win_lock:
        log_win.write(f"{ws},{t}\n")

def reset_state():
    """Reset all state variables (used on reconnect or fresh start)."""
    global _sent, _attempts, _cur_seq, _wsize, _sched, _misses, _seen, _resend_log, _cycle, _created
    _sent = 0
    _attempts = 0
    _cur_seq = INIT_SEQ
    _wsize = FLOW_SIZE
    _sched = []
    _misses = deque()
    _seen = set()
    _resend_log = [[], [], [], []]
    _cycle = 0
    _created = 0

def shutdown():
    """Close socket and log files gracefully."""
    try:
        if _sock:
            _sock.shutdown(socket.SHUT_RDWR)
            _sock.close()
    except:
        pass
    log_drop.close()
    log_win.close()

def summarize():
    """Print final statistics about packets sent and retries."""
    print(f"Client: {socket.gethostbyname(socket.gethostname())}")
    print(f"Sent: {_attempts}")
    print("Retries - 1x:{0} 2x:{1} 3x:{2} 4x:{3}".format(*map(len, _resend_log)))

def init_socket():
    """Create TCP connection and perform handshake with the server."""
    global _sock, _sent, _attempts, _cur_seq, _wsize, _sched, _misses
    global _resend_log, _cycle, _created, _is_linked

    host = socket.gethostname()
    port = 4001

    if _is_linked:
        return 1

    try:
        _sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        _sock.connect((host, port))
    except Exception as e:
        print("NetFail:", str(e))
        return -1

    _is_linked = True
    flag = "SYN" if _sent < 10 or _sent > (PACKET_LIMIT * 0.99) else "RCN"
    _sock.send(f"{flag} {CLIENT_ID[:10]}".encode())

    msg = _sock.recv(2048).decode()
    if msg == "NEW":
        print("Linked Fresh")
        reset_state()
    elif msg.startswith("OLD"):
        print("Resyncing...")
        _sock.send("SND".encode())
        state = eval(_sock.recv(4096).decode())
        _sent = state['pkt_rec_cnt']
        _attempts = state['pkt_rec_cnt']
        _cur_seq = state['seq_num']
    elif msg.startswith("SND"):
        sync_info = f'{{"pkt_success_sent": int({_sent}), "seq_num": int({_cur_seq})}}'
        _sock.sendall(sync_info.encode())
    else:
        print("Server unreachable!")
        return -1

    try:
        emit_stream()  # Begin packet transmission
    except KeyboardInterrupt:
        print("\n[!] Client manually interrupted.")
        _exit_flag.set()
    except Exception as e:
        print("Emit error:", e)
    finally:
        summarize()
        shutdown()

    return 0

def reconnect():
    """Attempt reconnection with exponential delay if server is down."""
    global _is_linked
    _is_linked = False
    reset_state()

    while not _is_linked and not _exit_flag.is_set():
        try:
            result = init_socket()
            if result == 0:
                return
            print("Retrying in 10 sec...")
            _exit_flag.wait(timeout=10)
        except KeyboardInterrupt:
            print("\n[!] User interrupted during reconnect.")
            _exit_flag.set()
            break
        except Exception as e:
            print(f"Connection error: {e}")
            _exit_flag.wait(timeout=10)

def emit_stream():
    """Main loop: sends packets to server, handles ACKs, resends, and adapts window size."""
    global _sock, _sent, _attempts, _cur_seq, _wsize, _sched, _misses, _seen
    global _resend_log, _cycle, _created

    print(f"Resuming @ seq: {_cur_seq}, Already sent {_sent}")

    while _sent < PACKET_LIMIT and not _exit_flag.is_set():
        _sched = []
        wait_ack = 0

        # Build schedule: resend missed first, then new packets
        for _ in range(_wsize):
            if _created < PACKET_LIMIT:
                if _cur_seq % 1000 == 1 and len(_misses):
                    while len(_sched) <= _wsize and _misses:
                        _sched.append(_misses.popleft())
                    break
                if _cur_seq + PKT_LEN > SEQ_WRAP:
                    _cur_seq = 0
                    _cycle += 1
                else:
                    _cur_seq += PKT_LEN
                _created += 1
                _sched.append(_cur_seq)
            else:
                while len(_sched) <= _wsize and _misses:
                    _sched.append(_misses.popleft())
                break

        # Send scheduled packets
        for item in _sched:
            _attempts += 1
            if should_drop():  # Simulate drop
                _misses.append(item)
                Thread(target=record_miss, args=(item, time.time(), _cycle)).start()
                if _wsize > 1:
                    _wsize = max(1, _wsize // 2)  # Shrink window size on drop
                    Thread(target=note_window, args=(_wsize, time.time())).start()
            else:
                wait_ack += 1
                try:
                    _sock.sendall((str(item) + " ").encode())
                    _sent += 1
                except Exception as e:
                    print(f"[!] Send failure: {e}")
                    return reconnect()

        # Receive ACKs
        _sock.settimeout(0.5)
        try:
            feed = _sock.recv(8192).decode()
            if "FIN" in feed:
                print("[!] Server closed session.")
                break
            confirmations = list(map(int, feed.split()))
        except socket.timeout:
            print("[!] Receive timeout. Reconnecting...")
            return reconnect()
        except Exception as e:
            print("[!] Error receiving: ", e)
            return reconnect()

        # Grow window on ACKs
        for ack in confirmations:
            if ack and _wsize < 2048:
                _wsize += 1
            wait_ack -= 1

        Thread(target=note_window, args=(_wsize, time.time())).start()
        _sock.settimeout(None)

        if _attempts % 100 == 0:
            print(f"[>] Progress: {_sent} packets sent, Window size: {_wsize}")

    summarize()
    shutdown()

if __name__ == '__main__':
    t0 = time.time()
    try:
        reconnect()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Exiting...")
        _exit_flag.set()
    finally:
        summarize()
        shutdown()
        print(f"Elapsed: {time.time() - t0:.2f} sec")
