"""
Low-level binary framing: 4-byte big-endian length prefix followed by payload.
Both approaches use this for all discrete messages over a socket.
"""
import struct

_HDR = struct.Struct(">I")  # 4-byte unsigned int, big-endian
_MAX_FRAME = 128 * 1024 * 1024  # 128 MiB sanity limit for control frames


def send_frame(sock, data: bytes) -> None:
    """Send *data* as a length-prefixed frame."""
    sock.sendall(_HDR.pack(len(data)) + data)


def recv_frame(sock) -> bytes:
    """Block until a complete length-prefixed frame is received."""
    (length,) = _HDR.unpack(_recv_exact(sock, _HDR.size))
    if length > _MAX_FRAME:
        raise ValueError(f"Frame size {length} exceeds limit {_MAX_FRAME}")
    return _recv_exact(sock, length)


def _recv_exact(sock, n: int) -> bytes:
    """Read exactly *n* bytes, blocking until available or connection closes."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(min(65536, n - len(buf)))
        if not chunk:
            raise ConnectionError(
                f"Connection closed after {len(buf)}/{n} bytes"
            )
        buf.extend(chunk)
    return bytes(buf)
