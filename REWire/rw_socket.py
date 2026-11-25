import socket
import select
import time
import logging
from enum import Enum, auto
from OpenSSL import SSL

#from openssl_psk import patch_context
#patch_context()

from . import utils
from .tls_cipher_suites import *

logger = logging.getLogger(__name__)

__all__ = [
    "UDP",
    "TCP",
    "TLS",
    "DTLS",
    "SOL_SECURITY",
    "SecurityOption",
    "RWSocket",
    "RW_TCPSocket",
    "RW_TLSSocket",
    "RW_UDPSocket",
    "RW_DTLSSocket",
    "DefaultCipherList",
    ]


DefaultCipherList = [
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    ]


SOL_SECURITY = Enum("SocketOptionLevel", "SECURITY").SECURITY


class SecurityOption(Enum):
    """Pre-connect options for SOL_SECURITY.

    CIPHERS takes EtherNet/IP cipher suite IDs. PSK takes (identity, secret).
    CA_FILE takes a PEM trust bundle and enables chain verification by default.
    VERIFY_PEER selects chain verification and uses OpenSSL's default trust
    paths if CA_FILE is absent. Peer names and addresses are not checked.
    CLIENT_CERT takes (certificate_chain_file, private_key_file).
    SESSION_REUSE takes an established DTLS socket.
    """

    CIPHERS = auto()
    PSK = auto()
    CA_FILE = auto()
    VERIFY_PEER = auto()
    CLIENT_CERT = auto()
    SESSION_REUSE = auto()


class RWSocket:
    def __init__(
        self,
        host_address,
        server_address,
        ):

        self._host_address = host_address
        self._server_address = server_address

    def setsockopt(self, level, option, value, *args):
        if level is SOL_SECURITY:
            raise ValueError("Security options require a TLS or DTLS socket")
        self._socket.setsockopt(level, option, value, *args)

    @property
    def host_ip(self):
        return self._socket.getsockname()[0]

    @property
    def host_port(self):
        return self._socket.getsockname()[1]

    @property
    def peer_ip(self):
        return self._socket.getpeername()[0]

    @property
    def peer_port(self):
        return self._socket.getpeername()[1]

    @property
    def peer_certs(self):
        try:
            return [crt.to_cryptography() for crt in self.socket._socket.get_peer_cert_chain()]
        except:
            return []

    @property
    def cipher(self):
        cs = _lib.SSL_get_current_cipher(self._socket._ssl)
        return ""
        return str(_lib.SSL_CIPHER_find(cs))

    @property
    def cipher_name(self):
        return self._socket.get_cipher_name()


class RW_TCPSocket(RWSocket):
    def __init__(
        self,
        host_address,
        server_address,
        timeout: float=1.0,
        ) -> None:

        super(RW_TCPSocket, self).__init__(host_address, server_address)
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind(host_address)
        self._socket.settimeout(timeout)
        self._sessions = [] # Sessions using this socket

    def connect(self) -> None:
        try:
            peer = self._socket.getpeername()
        except Exception:
            self._socket.connect(self._server_address)

    def send(self, payload):
        self._socket.sendall(payload)
        logger.debug("Data sent\n{}".format(utils.hex_dump(payload)))

    def receive(self, timeout: float=1.0):
        rsp = []
        while True:
            readables, _, _ = select.select([self._socket], [], [], timeout)

            if readables:
                try:
                    data = self._socket.recv(65535)
                    if not data:
                        self._socket.shutdown(socket.SHUT_WR | socket.SHUT_RD)
                        self._socket.close()
                    else:
                        logger.debug("Data received\n{}".format(utils.hex_dump(data)))
                        rsp.append((data, self._socket.getpeername(), time.time()))
                except SSL.WantReadError:
                    continue
            break
        return rsp

    def close(self):
        self._socket.close()


class _SecureSocket:
    def __init__(self, host_address, server_address, timeout=5.0):
        super().__init__(host_address, server_address, timeout=timeout)
        self._security_options = {}
        self._security_started = False
        self.handshake_done = False

    def setsockopt(self, level, option, value, *args):
        """Set a native socket option or configure security before connect()."""
        if level is not SOL_SECURITY:
            return super().setsockopt(level, option, value, *args)
        if self._security_started or self._socket.fileno() == -1:
            raise RuntimeError("Security options must be set on an open socket before connect()")
        if args or not isinstance(option, SecurityOption):
            raise ValueError("Expected a SecurityOption and one value")
        if option is SecurityOption.CIPHERS:
            value = tuple(value)
            if not value:
                raise ValueError("CIPHERS requires at least one cipher suite")
            for cipher in value:
                if not TLSCipherSuite(cipher).openssl_name:
                    raise ValueError(f"Unsupported cipher suite: {cipher!r}")
        elif option is SecurityOption.PSK:
            identity, secret = value
            if isinstance(identity, str):
                identity = identity.encode("utf-8")
            if not isinstance(identity, bytes) or not identity or b"\x00" in identity:
                raise ValueError("PSK requires a nonempty identity without NUL bytes")
            if not isinstance(secret, bytes) or not secret:
                raise ValueError("PSK requires a nonempty bytes secret")
            if not hasattr(SSL.Context, "set_psk_client_callback"):
                raise NotImplementedError("The installed pyOpenSSL backend has no PSK client callback")
            value = (identity, secret)
        elif option is SecurityOption.VERIFY_PEER:
            if not isinstance(value, bool):
                raise TypeError("VERIFY_PEER requires a bool")
        elif option is SecurityOption.CLIENT_CERT:
            cert_file, key_file = value
            value = (cert_file, key_file)
        elif option is SecurityOption.SESSION_REUSE:
            if not isinstance(self, RW_DTLSSocket) or not isinstance(value, RW_DTLSSocket):
                raise ValueError("SESSION_REUSE requires an established DTLS socket")
            if not value.handshake_done:
                raise ValueError("SESSION_REUSE requires an established DTLS socket")
            value = value._socket.get_session()
            if value is None:
                raise ValueError("The DTLS socket has no session to reuse")
        self._security_options[option] = value

    def _configure_security(self):
        options = self._security_options
        is_dtls = isinstance(self, RW_DTLSSocket)
        context = SSL.Context(SSL.DTLS_CLIENT_METHOD if is_dtls else SSL.TLS_CLIENT_METHOD)
        version = 0xFEFD if is_dtls else SSL.TLS1_2_VERSION  # DTLS 1.2 wire version
        context.set_min_proto_version(version)
        context.set_max_proto_version(version)

        ca_file = options.get(SecurityOption.CA_FILE)
        verify = options.get(SecurityOption.VERIFY_PEER, ca_file is not None)
        if ca_file is not None:
            context.load_verify_locations(ca_file)
        elif verify:
            context.set_default_verify_paths()
        context.set_verify(SSL.VERIFY_PEER if verify else SSL.VERIFY_NONE)

        if SecurityOption.CLIENT_CERT in options:
            cert_file, key_file = options[SecurityOption.CLIENT_CERT]
            context.use_certificate_chain_file(cert_file)
            context.use_privatekey_file(key_file)
            context.check_privatekey()

        suites = options.get(SecurityOption.CIPHERS, DefaultCipherList)
        cipher_string = ":".join(TLSCipherSuite(cipher).openssl_name for cipher in suites)
        if "NULL" in cipher_string:
            cipher_string += ":@SECLEVEL=0"
            logger.warning("SSL security level lowered for a configured NULL cipher suite.")
        context.set_cipher_list(cipher_string.encode("ascii"))

        if SecurityOption.PSK in options:
            psk = options[SecurityOption.PSK]
            context.set_psk_client_callback(lambda connection, hint: psk)

        connection = SSL.Connection(context, self._socket)
        if SecurityOption.SESSION_REUSE in options:
            connection.set_session(options[SecurityOption.SESSION_REUSE])
        connection.set_connect_state()
        self._socket = connection
        self._security_started = True

    def connect(self) -> None:
        if self.handshake_done:
            return
        if not self._security_started:
            self._configure_security()
        try:
            self._socket.getpeername()
        except OSError:
            self._socket.connect(self._server_address)
        timeout = self._socket.gettimeout()
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            try:
                self._socket.do_handshake()
                break
            except (SSL.WantReadError, SSL.WantWriteError) as error:
                remaining = None if deadline is None else deadline - time.monotonic()
                if remaining is not None and remaining <= 0:
                    raise TimeoutError("Secure socket handshake timed out") from error
                timer = self._socket.DTLSv1_get_timeout() if isinstance(self, RW_DTLSSocket) else None
                wait = remaining
                if timer is not None and (wait is None or timer < wait):
                    wait = timer
                reading = isinstance(error, SSL.WantReadError)
                readables, writables, _ = select.select(
                    [self._socket] if reading else [],
                    [] if reading else [self._socket],
                    [],
                    wait,
                )
                if not (readables or writables):
                    if deadline is not None and time.monotonic() >= deadline:
                        raise TimeoutError("Secure socket handshake timed out") from error
                    if timer is not None:
                        self._socket.DTLSv1_handle_timeout()
        self.handshake_done = True
        if "NULL" in (self.cipher_name or ""):
            logger.warning("The negotiated cipher provides no encryption.")

    def send(self, payload):
        if not self.handshake_done:
            raise OSError("The secure socket is not connected")
        return super().send(payload)

    def receive(self, timeout=1.0):
        if not self.handshake_done:
            raise OSError("The secure socket is not connected")
        return super().receive(timeout)

    def close(self):
        try:
            if self.handshake_done:
                self._socket.shutdown()
        finally:
            self.handshake_done = False
            self._socket.close()

    @property
    def cipher_name(self):
        if self.handshake_done:
            return self._socket.get_cipher_name()
        return None

    @property
    def peer_certs(self):
        if not self.handshake_done:
            return []
        return [cert.to_cryptography() for cert in self._socket.get_peer_cert_chain() or ()]


class RW_TLSSocket(_SecureSocket, RW_TCPSocket):
    pass


class RW_UDPSocket(RWSocket):
    def __init__(
        self,
        host_address,
        server_address,
        broadcast=False,
        timeout: float=2.0,
        ) -> None:

        super(RW_UDPSocket, self).__init__(host_address, server_address)
        self._broadcast = broadcast
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self._socket.settimeout(timeout)
        if broadcast is True:
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self._socket.bind(host_address)

    def connect(self) -> None:
        pass

    def send(self, payload) -> None:
        self._socket.sendto(payload, self._server_address)
        logger.debug("Data sent\n{}".format(utils.hex_dump(payload)))

    def receive(self, timeout: float=2.0):
        rsp = []
        t_start = time.time()
        while True:
            try:
                self._socket.settimeout(timeout - (time.time() - t_start))
                data, addr = self._socket.recvfrom(65535)
                rsp.append((bytearray(data), addr, time.time()))
                logger.debug("Data received\n{}".format(utils.hex_dump(data)))
                if not self._broadcast:
                    break
            except socket.timeout:
                break
            except Exception as err:
                print(err)
                break

        return rsp

    def close(self):
        self._socket.close()

    @property
    def is_broadcast(self):
        return True if self._socket.getsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST) > 0 else False


class RW_DTLSSocket(_SecureSocket, RW_UDPSocket):
    def send(self, payload):
        if not self.handshake_done:
            raise OSError("The secure socket is not connected")
        self._socket.sendall(payload)
        logger.debug("Data sent\n{}".format(utils.hex_dump(payload)))

    def receive(self, timeout: float=1.0):
        if not self.handshake_done:
            raise OSError("The secure socket is not connected")
        rsp = []
        readables, _, _ = select.select([self._socket], [], [], timeout)

        if readables:
            data = self._socket.recv(65535)
            if not data:
                self._socket.shutdown(socket.SHUT_WR | socket.SHUT_RD)
                self._socket.close()
            else:
                logger.debug("Data received\n{}".format(utils.hex_dump(data)))
                rsp.append((data, self._socket.getpeername(), time.time()))
        return rsp

def UDP(host_ip, server_ip, timeout: float=1.0, security=False):
    if security is True:
        return RW_DTLSSocket((host_ip, 0), (server_ip, 2221), timeout=timeout)
    return RW_UDPSocket((host_ip, 0), (server_ip, 44818), timeout=timeout,
                        broadcast=server_ip == "255.255.255.255")


def TCP(host_ip, server_ip, timeout: float=1.0, security=False):
    if security is True:
        return RW_TLSSocket((host_ip, 0), (server_ip, 2221), timeout=timeout)
    return RW_TCPSocket((host_ip, 0), (server_ip, 44818), timeout=timeout)


def TLS(host_ip, server_ip, timeout: float=1.0):
    return TCP(host_ip, server_ip, timeout, security=True)


def DTLS(host_ip, server_ip, timeout: float=1.0):
    return UDP(host_ip, server_ip, timeout, security=True)
