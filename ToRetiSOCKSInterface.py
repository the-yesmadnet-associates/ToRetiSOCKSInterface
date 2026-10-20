#
# Copyright 2025 Kevin Steen <code at kevinsteen.net>
# Copyright 2026 The Yesmadnet Associates (see CREDITS)
#
# ToRetiSOCKSInterface.py -- derivative of SOCKSClientInterface.py by Kevin
# Steen (https://codeberg.org/SkyGuy/reti_socks_client), modified 2026.
#
# HDLC wire format unchanged: encode() is identical to the original, and
# get_packets() was lightly refactored and fuzz-tested against it. The SOCKS5
# username/password stream-isolation technique is Kevin Steen's design, kept
# here.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: AGPL-3.0-or-later
#

"""SOCKS5 client interface for Reticulum (ToRetiSOCKSInterface).

Connects through a SOCKS5 proxy (defaults tuned for Tor). Works with any
compliant SOCKS5 proxy by changing proxy_port / isolate / bitrate.

Required: target_host, target_port
Optional: proxy_host (127.0.0.1), proxy_port (9050), isolate (yes),
          bitrate (20_000_000), connect_timeout (20), hw_mtu, and various
          buffer/keepalive knobs.

Note: the MTU is derived from `bitrate`. 20 Mbit/s (MTU 16384) seemed to be a
good fit during our tests, but feel free to experiment.

Example (Tor):
    [[Tor Gateway]]
      type = ToRetiSOCKSInterface
      enabled = yes
      target_host = toraddress.onion
      target_port = 4965

Example (clearnet host, reached through the proxy):
    [[Clearnet Gateway]]
      type = ToRetiSOCKSInterface
      enabled = yes
      target_host = example.net
      target_port = 4242
"""

__version__ = '2.4-tor'

import random
import socket
import threading
import time

import RNS
from RNS.Interfaces.Interface import Interface


def log_error(msg, *args, **kwargs):
    RNS.log(msg % args if args else msg, level=RNS.LOG_ERROR, **kwargs)
def log_warning(msg, *args, **kwargs):
    RNS.log(msg % args if args else msg, level=RNS.LOG_WARNING, **kwargs)
def log_info(msg, *args, **kwargs):
    RNS.log(msg % args if args else msg, level=RNS.LOG_INFO, **kwargs)
def log_debug(msg, *args, **kwargs):
    RNS.log(msg % args if args else msg, level=RNS.LOG_DEBUG, **kwargs)


DEFAULT_PROXY_HOST = '127.0.0.1'
DEFAULT_PROXY_PORT = 9050
DEFAULT_BITRATE = 20_000_000
DEFAULT_RECV_BUFFER_SIZE = 262_144
DEFAULT_SOCKET_BUFFER_BYTES = 1_048_576
DEFAULT_MAX_INCOMING_BUFFER = 4 * 1024 * 1024
DEFAULT_MIN_RECONNECT_DELAY = 0.5
DEFAULT_MAX_RECONNECT_DELAY = 300.0
DEFAULT_KEEPALIVE_IDLE = 15
DEFAULT_KEEPALIVE_INTERVAL = 5
DEFAULT_KEEPALIVE_COUNT = 3
CONNECT_TIMEOUT = 20
RECONNECT_JITTER = 0.2
SOCKS5_MAX_FIELD_LEN = 255

SOCKS5_AUTH_NONE = 0x00

SOCKS5_REPLY = {
    0x01: "general SOCKS server failure",
    0x02: "connection not allowed by ruleset",
    0x03: "network unreachable",
    0x04: "host unreachable",
    0x05: "connection refused",
    0x06: "TTL expired",
    0x07: "command not supported",
    0x08: "address type not supported",
    0xF0: "onion service descriptor can not be found",
    0xF1: "onion service descriptor is invalid",
    0xF2: "onion service introduction failed",
    0xF3: "onion service rendezvous failed",
    0xF4: "onion service missing client authorization",
    0xF5: "onion service wrong client authorization",
    0xF6: "onion service address is invalid",
    0xF7: "onion service introduction timed out",
}
SOCKS5_AUTH_USERPASS = 0x02


def getint(coll, key, default, errstr):
    try:
        return int(coll.get(key, default))
    except (TypeError, ValueError):
        raise ValueError(errstr)


def getfloat(coll, key, default, errstr):
    try:
        return float(coll.get(key, default))
    except (TypeError, ValueError):
        raise ValueError(errstr)


def getbool(coll, key, default):
    val = coll.get(key, default)
    if isinstance(val, bool):
        return val
    return str(val).strip().lower() in ('yes', 'true', '1', 'on')


class HDLC():
    """HDLC framing, wire-compatible with Reticulum TCP interfaces."""
    FLAG = 0x7E
    ESC = 0x7D
    ESC_MASK = 0x20

    @staticmethod
    def encode(data):
        data = data.replace(bytes([HDLC.ESC]),
                            bytes([HDLC.ESC, HDLC.ESC ^ HDLC.ESC_MASK]))
        data = data.replace(bytes([HDLC.FLAG]),
                            bytes([HDLC.ESC, HDLC.FLAG ^ HDLC.ESC_MASK]))
        return bytes([HDLC.FLAG]) + data + bytes([HDLC.FLAG])

    @staticmethod
    def get_packets(buf):
        pkts = []
        index = 0
        n = len(buf)
        while index < n:
            start = buf.find(HDLC.FLAG, index)
            if start == -1:
                return pkts, buf[index:]
            end = buf.find(HDLC.FLAG, start + 1)
            if end == -1:
                return pkts, buf[index:]
            pkt = buf[start + 1:end]
            if pkt:
                pkt = pkt.replace(bytes([HDLC.ESC, HDLC.FLAG ^ HDLC.ESC_MASK]),
                                  bytes([HDLC.FLAG]))
                pkt = pkt.replace(bytes([HDLC.ESC, HDLC.ESC ^ HDLC.ESC_MASK]),
                                  bytes([HDLC.ESC]))
                pkts.append(bytes(pkt))
            index = end + 1
        return pkts, buf[index:]


class ToRetiSOCKSInterface(Interface):
    DEFAULT_IFAC_SIZE = 8
    AUTOCONFIGURE_MTU = True

    name = "Unnamed ToRetiSOCKSInterface"
    online = False
    running = False
    socket = None
    _run_thread = None

    def __init__(self, owner, config):
        super().__init__()
        self.owner = owner
        self.incoming_buffer = bytearray()
        self._socket_lock = threading.Lock()
        self._lifecycle_lock = threading.RLock()
        self._generation = 0

        self.reconnect_count = 0
        self.last_connected_at = None
        self.last_disconnected_at = None
        self._ever_connected = False

        config = self.get_config_obj(config)
        self.name = config.get("name")

        self.target_host = config.get('target_host', '')
        self.proxy_host = config.get('proxy_host', DEFAULT_PROXY_HOST)
        if not (self.target_host and self.proxy_host):
            raise ValueError('target_host and proxy_host must be specified')

        self.target_port = getint(config, 'target_port', None,
                                  "target_port must be a valid port number")
        self.proxy_port = getint(config, 'proxy_port', DEFAULT_PROXY_PORT,
                                 "proxy_port must be a valid port number")
        self.connect_timeout = getfloat(config, 'connect_timeout', CONNECT_TIMEOUT,
                                        "connect_timeout must be a number")
        if self.connect_timeout <= 0:
            raise ValueError("connect_timeout must be greater than 0")
        for portname, portval in (('target_port', self.target_port),
                                  ('proxy_port', self.proxy_port)):
            if not (0 < portval <= 65535):
                raise ValueError(f"{portname} must be between 1 and 65535")

        self.bitrate = getint(config, 'bitrate', DEFAULT_BITRATE,
                              "bitrate must be a valid integer")
        self.optimise_mtu()
        if self.HW_MTU is None:
            self.HW_MTU = RNS.Reticulum.MTU
        if 'hw_mtu' in config:
            self.HW_MTU = getint(config, 'hw_mtu', self.HW_MTU,
                                 "hw_mtu must be a valid integer")
        self.isolate = getbool(config, 'isolate', True)
        self.recv_buffer_size = getint(config, 'recv_buffer_size',
                                       DEFAULT_RECV_BUFFER_SIZE,
                                       "recv_buffer_size must be an integer")
        self.socket_buffer_bytes = getint(config, 'socket_buffer_bytes',
                                          DEFAULT_SOCKET_BUFFER_BYTES,
                                          "socket_buffer_bytes must be an integer")
        self.max_incoming_buffer = getint(config, 'max_incoming_buffer',
                                          DEFAULT_MAX_INCOMING_BUFFER,
                                          "max_incoming_buffer must be an integer")
        self.min_reconnect_delay = getfloat(config, 'min_reconnect_delay',
                                            DEFAULT_MIN_RECONNECT_DELAY,
                                            "min_reconnect_delay must be a number")
        self.max_reconnect_delay = getfloat(config, 'max_reconnect_delay',
                                            DEFAULT_MAX_RECONNECT_DELAY,
                                            "max_reconnect_delay must be a number")
        self.keepalive_idle = getint(config, 'keepalive_idle',
                                     DEFAULT_KEEPALIVE_IDLE,
                                     "keepalive_idle must be an integer")
        self.keepalive_interval = getint(config, 'keepalive_interval',
                                         DEFAULT_KEEPALIVE_INTERVAL,
                                         "keepalive_interval must be an integer")
        self.keepalive_count = getint(config, 'keepalive_count',
                                      DEFAULT_KEEPALIVE_COUNT,
                                      "keepalive_count must be an integer")
        self._reconnect_delay = self.min_reconnect_delay

        target_host_bytes = self.target_host.encode()
        if len(target_host_bytes) > SOCKS5_MAX_FIELD_LEN:
            raise ValueError("target_host name too long (max 255 bytes)")
        if self.isolate:
            auth_username = target_host_bytes + b':' + str(self.target_port).encode()
            if len(auth_username) > SOCKS5_MAX_FIELD_LEN:
                raise ValueError(
                    "target_host is too long once combined with target_port "
                    "for the SOCKS5 username field (max 255 bytes)")

        self.start()

    def get_status(self):
        return {
            "online": self.online,
            "reconnect_count": self.reconnect_count,
            "last_connected_at": self.last_connected_at,
            "last_disconnected_at": self.last_disconnected_at,
        }

    def __repr__(self):
        return f"ToRetiSOCKS[{self.name}]"

    def start(self):
        with self._lifecycle_lock:
            if self.running:
                log_debug(f"{self}: start called when already running")
                return
            if self._run_thread is not None:
                log_error(f"{self}: start: active thread found (should never happen)")
                self._run_thread.join()
            self._generation += 1
            self.running = True
            self._run_thread = threading.Thread(
                target=self._run, args=(self._generation,),
                name="ToRetiSOCKSInterface runloop", daemon=True)
            self._run_thread.start()

    def stop(self):
        with self._lifecycle_lock:
            log_debug(f"{self}: stop() called")
            self.running = False
            self.online = False
            self.last_disconnected_at = time.time()
            sock = self.socket
            if sock is not None:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except Exception as e:
                    log_debug(f"{self}: stop shutdown exception: {e}")
                with self._socket_lock:
                    try:
                        sock.close()
                    except Exception as e:
                        log_debug(f"{self}: stop close exception: {e}")
            run_thread, self._run_thread = self._run_thread, None
            if run_thread is not None and run_thread is not threading.current_thread():
                run_thread.join(timeout=5)

    def _restart_async(self):
        threading.Thread(target=self._restart, args=(self._generation,),
                         name="ToRetiSOCKSInterface restart", daemon=True).start()

    def _restart(self, gen=None):
        with self._lifecycle_lock:
            if gen is not None and gen != self._generation:
                return  # another restart already replaced this run
            self.stop()
            self.start()

    def process_incoming(self, data):
        self.rxb += len(data)
        self.owner.inbound(data, self)

    def process_outgoing(self, data):
        if not self.online:
            log_debug(f"{self}: tried to send before ready")
            return
        framed = HDLC.encode(data)
        view = memoryview(framed)
        datalen = len(view)
        totalsent = 0
        try:
            with self._socket_lock:
                while self.running and totalsent < datalen:
                    sent = self.socket.send(view[totalsent:])
                    if sent == 0:
                        raise IOError("Socket connection broken")
                    totalsent += sent
                    self.txb += sent
        except (IOError, OSError):
            if self.running:
                self.running = False
                log_warning(f"{self}: error sending data, restarting interface")
                self._restart_async()

    def _handle_wire_data(self, data):
        if self.incoming_buffer:
            self.incoming_buffer.extend(data)
            buf = self.incoming_buffer
        else:
            buf = data

        pkts, extra = HDLC.get_packets(buf)

        if len(extra) > self.max_incoming_buffer:
            log_warning(f"{self}: incoming buffer exceeded "
                        f"{self.max_incoming_buffer} bytes with no complete "
                        f"frame; restarting interface")
            self.incoming_buffer = bytearray()
            self.running = False
            self._restart_async()
            return

        self.incoming_buffer = bytearray(extra)
        for pkt in pkts:
            self.process_incoming(pkt)

    def _next_delay(self):
        jitter = self._reconnect_delay * RECONNECT_JITTER
        return max(0.05, self._reconnect_delay + random.uniform(-jitter, jitter))

    def _run(self, gen):
        first_attempt = True
        try:
            while self.running and gen == self._generation:
                if not first_attempt:
                    time.sleep(self._next_delay())
                    if not (self.running and gen == self._generation):
                        return
                    self._reconnect_delay = min(
                        self._reconnect_delay * 2, self.max_reconnect_delay)
                first_attempt = False

                new_socket = None
                try:
                    log_debug(f"{self}: connecting to proxy")
                    new_socket = socket.create_connection(
                        (self.proxy_host, self.proxy_port), timeout=self.connect_timeout)
                    self._tune_socket(new_socket)
                    with self._socket_lock:
                        self.socket = new_socket
                    if not (self.running and gen == self._generation):
                        raise IOError("stopped while connecting")
                    self._send_socks_handshake()
                    self.socket.settimeout(None)
                    break
                except (IOError, OSError) as e:
                    if self.running and gen == self._generation:
                        log_warning(f"{self}: connection failed, retrying in "
                                    f"~{self._reconnect_delay:.1f}s ({e})")
                    if new_socket is not None:
                        try:
                            new_socket.close()
                        except Exception:
                            pass

            if not (self.running and gen == self._generation):
                return  # stopped (or replaced) while connecting
            self.online = True
            if not (self.running and gen == self._generation):
                self.online = False  # stop() raced us between the check and the assignment
                return
            self.last_connected_at = time.time()
            if self._ever_connected:
                self.reconnect_count += 1
                log_info(f"{self} reconnected (reconnect #{self.reconnect_count})")
            else:
                self._ever_connected = True
                log_info(f"{self} connected")
            self._reconnect_delay = self.min_reconnect_delay

            self._read_loop()
        except Exception as e:
            log_error(f"{self}: run exception: {e}")
        finally:
            if gen == self._generation:
                self.running = False

    def _tune_socket(self, sock):
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, self.socket_buffer_bytes)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.socket_buffer_bytes)
        except OSError:
            pass
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        except OSError:
            return
        for opt, value in (
            (getattr(socket, 'TCP_KEEPIDLE', None), self.keepalive_idle),
            (getattr(socket, 'TCP_KEEPINTVL', None), self.keepalive_interval),
            (getattr(socket, 'TCP_KEEPCNT', None), self.keepalive_count),
        ):
            if opt is not None:
                try:
                    sock.setsockopt(socket.IPPROTO_TCP, opt, value)
                except OSError:
                    pass

    def _read_loop(self):
        while self.running:
            try:
                data = self.socket.recv(self.recv_buffer_size)
            except (IOError, OSError):
                if self.running:
                    self.running = False
                    log_warning(f"{self}: error reading data, restarting interface")
                    self._restart_async()
                return
            if not data:
                if self.running:
                    self.running = False
                    log_warning(f"{self}: stream ended, restarting interface")
                    self._restart_async()
                return
            self._handle_wire_data(data)

    def _recv_exact(self, n):
        buf = b''
        while len(buf) < n:
            chunk = self.socket.recv(n - len(buf))
            if not chunk:
                raise IOError("Proxy closed connection during SOCKS handshake")
            buf += chunk
        return buf

    def _encode_dst_addr(self):
        try:
            return b'\x01' + socket.inet_pton(socket.AF_INET, self.target_host)
        except OSError:
            pass
        try:
            return b'\x04' + socket.inet_pton(socket.AF_INET6, self.target_host)
        except OSError:
            pass
        host_bytes = self.target_host.encode()
        return b'\x03' + len(host_bytes).to_bytes(1, 'big') + host_bytes

    def _send_socks_handshake(self):
        if self.isolate:
            methods = bytes([SOCKS5_AUTH_USERPASS, SOCKS5_AUTH_NONE])
        else:
            methods = bytes([SOCKS5_AUTH_NONE])
        self.socket.sendall(bytes([0x05, len(methods)]) + methods)

        method_resp = self._recv_exact(2)
        if method_resp[0] != 0x05:
            raise IOError(f"Unexpected SOCKS version in reply: {method_resp[0]}")
        chosen = method_resp[1]

        if chosen == SOCKS5_AUTH_USERPASS:
            self._do_userpass_auth()
        elif chosen == SOCKS5_AUTH_NONE:
            if self.isolate:
                log_warning(f"{self}: proxy does not support username/"
                            f"password auth; continuing without stream isolation")
        else:
            raise IOError(f"Proxy rejected all offered auth methods "
                          f"(response: {method_resp!r})")

        self._do_connect()

    def _do_userpass_auth(self):
        username = self.target_host.encode() + b':' + str(self.target_port).encode()
        password = b'reticulum'
        if len(username) > SOCKS5_MAX_FIELD_LEN:
            raise ValueError("SOCKS5 username field too long")
        self.socket.sendall(
            b'\x01' + len(username).to_bytes(1, 'big') + username
            + len(password).to_bytes(1, 'big') + password)
        auth_resp = self._recv_exact(2)
        if auth_resp != b'\x01\x00':
            raise IOError(f"SOCKS5 authentication rejected by proxy "
                          f"(response: {auth_resp!r})")

    def _do_connect(self):
        dstaddr = self._encode_dst_addr() + self.target_port.to_bytes(2, 'big')
        self.socket.sendall(b'\x05\x01\x00' + dstaddr)

        header = self._recv_exact(4)
        ver, rep, _rsv, atyp = header[0], header[1], header[2], header[3]
        if ver != 0x05:
            raise IOError(f"Unexpected SOCKS version in reply: {ver}")
        if rep != 0x00:
            raise IOError(f"SOCKS5 CONNECT to {self.target_host}:{self.target_port} failed: "
                          f"{SOCKS5_REPLY.get(rep, 'unknown error')} (code 0x{rep:02X})")
        if atyp == 0x01:
            self._recv_exact(4 + 2)
        elif atyp == 0x03:
            name_len = self._recv_exact(1)[0]
            self._recv_exact(name_len + 2)
        elif atyp == 0x04:
            self._recv_exact(16 + 2)
        else:
            raise IOError(f"Unknown address type in SOCKS5 reply: {atyp}")


interface_class = ToRetiSOCKSInterface
