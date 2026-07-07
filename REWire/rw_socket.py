import socket
import select
import time
import logging
from dataclasses import dataclass
from OpenSSL import SSL

#from openssl_psk import patch_context
#patch_context()

from . import utils
from .tls_cipher_suites import *

logger = logging.getLogger(__name__)

__all__ = [
    "UDP",
    "TCP",
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


@dataclass
class ClientPSK:
    connection: SSL.Connection
    identity: bytes
    secret: bytes


class RWSocket:
    pre_shared_keys = []

    def __init__(
        self,
        host_address,
        server_address,
        ):

        self._host_address = host_address
        self._server_address = server_address

    @staticmethod
    def client_psk_callback(connection: SSL.Connection, psk_id: bytes):
        for client_psk in RWSocket.pre_shared_keys:
            if client_psk.connection == connection:
                return (client_psk.identity, client_psk.secret)
        return ("", b"")

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
        except:
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


class RW_TLSSocket(RW_TCPSocket):
    def __init__(
        self,
        host_address,
        server_address,
        timeout=5.0,
        ciphers=None,
        psk=None
        ) -> None:

        super(RW_TLSSocket, self).__init__(host_address, server_address, timeout)

        ssl_ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
        ssl_ctx.set_min_proto_version(SSL.TLS1_2_VERSION)
        ssl_ctx.set_max_proto_version(SSL.TLS1_2_VERSION)
        ssl_ctx.set_verify(SSL.VERIFY_NONE)
        ssl_ctx.set_options(SSL.OP_SINGLE_ECDH_USE)

        if ciphers:
            cipher_string = ":".join(TLSCipherSuite(cipher).openssl_name for cipher in ciphers)
        else:
            cipher_string = ":".join(TLSCipherSuite(cipher).openssl_name for cipher in DefaultCipherList)

        if "NULL" in cipher_string:
            cipher_string += ":@SECLEVEL=0"
            logger.warning("SSL security set to lowest level due the using of NULL cipher suite.")
        ssl_ctx.set_cipher_list(cipher_string)

        if psk and psk[0] != "":
            ssl_ctx.set_psk_client_callback(RWSocket.client_psk_callback)

        self._socket = SSL.Connection(ssl_ctx, self._socket)

        if psk and psk[0] != "":
            RWSocket.pre_shared_keys.append(ClientPSK(self._socket, psk[0], psk[1]))

        self._socket.set_connect_state()

    def connect(self) -> None:
        try:
            peer = self._socket.getpeername()
        except:
            self._socket.connect(self._server_address)
        while True:
            try:
                self._socket.do_handshake()
                break
            except SSL.WantReadError:
                continue
        if "NULL" in self.cipher_name:
            logger.warning("Security warning! Only data integrity in the current DTLS communication.")

    def close(self):
        self._socket.shutdown()
        self._socket.close()


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


class RW_DTLSSocket(RW_UDPSocket):
    def __init__(
        self,
        host_address,
        server_address,
        timeout: float=5.0,
        ciphers=None,
        psk=("", b""),
        reuse=None,
        ) -> None:

        super(RW_DTLSSocket, self).__init__(host_address, server_address, timeout=timeout)
        self.handshake_done = False

        ssl_ctx = SSL.Context(SSL.DTLS_CLIENT_METHOD)
        ssl_ctx.set_min_proto_version(SSL.TLS1_2_VERSION)
        ssl_ctx.set_max_proto_version(SSL.TLS1_2_VERSION)
        ssl_ctx.set_verify(SSL.VERIFY_NONE)
        ssl_ctx.set_options(SSL.OP_SINGLE_ECDH_USE)

        if ciphers:
            cipher_string = ":".join(TLSCipherSuite(cipher).openssl_name for cipher in ciphers)
        else:
            cipher_string = ":".join(TLSCipherSuite(cipher).openssl_name for cipher in DefaultCipherList)

        if "NULL" in cipher_string:
            cipher_string += ":@SECLEVEL=0"
            logger.warning("SSL security set to lowest level due the using of NULL cipher suite.")
        ssl_ctx.set_cipher_list(cipher_string)

        if psk and psk[0] != "":
            ssl_ctx.set_psk_client_callback(RWSocket.client_psk_callback)

        self._socket = SSL.Connection(ssl_ctx, self._socket)

        if psk and psk[0] != "":
            RWSocket.pre_shared_keys.append(CLIENT_PSK(self._socket, psk[0], psk[1]))

        if reuse:
            self._socket.set_session(reuse._socket.get_session())
        else:
            pass
        ssl_ctx.set_info_callback(self.info_cb)
        self._socket.set_connect_state()

    def connect(self) -> None:
        if self.handshake_done is False:
            self._socket.connect(self._server_address)
            #x = self._socket.renegotiate()
            #print(x)

            while True:
                try:
                    self._socket.do_handshake()
                    break
                except SSL.WantReadError:
                    continue
            if "NULL" in self.cipher_name:
                logger.warning("Security warning! DTLS session provides only data integrity!")

    def send(self, payload):
        self._socket.sendall(payload)
        logger.debug("Data sent\n{}".format(utils.hex_dump(payload)))

    def receive(self, timeout: float=1.0):
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

    def close(self):
        self._socket.shutdown()
        self._socket.close()
        self.handshake_done = False

    def info_cb(self, ctx, where, ret_code):
        if where & SSL.SSL_CB_HANDSHAKE_DONE:
            self.handshake_done = True


def UDP(host_ip, server_ip, timeout: float=1.0, security=False, **kwargs):
        if security is True:
            ciphers = kwargs.get("ciphers", None)
            psk = kwargs.get("psk", None)
            reuse = kwargs.get("reuse", None)
            return RW_DTLSSocket((host_ip, 0), (server_ip, 2221), timeout=timeout, ciphers=ciphers, psk=psk, reuse=reuse)
        return RW_UDPSocket((host_ip, 0), (server_ip, 44818), timeout=timeout,
                broadcast=True if server_ip=="255.255.255.255" else False
                )


def TCP(host_ip, server_ip, timeout: float=1.0, security=False, **kwargs):
        if security is True:
            ciphers = kwargs.get("ciphers", None)
            psk = kwargs.get("psk", None)
            return RW_TLSSocket((host_ip, 0), (server_ip, 2221), timeout=timeout, ciphers=ciphers, psk=psk)
        return RW_TCPSocket((host_ip, 0), (server_ip, 44818), timeout=timeout)