#!/usr/bin/env python3
"""Direct-to-Samba SMB2 NEGOTIATE RTT probes for the network study."""

import os
import socket
import statistics
import struct
import sys
import time


def receive_exact(connection, size):
    data = bytearray()
    while len(data) < size:
        chunk = connection.recv(size - len(data))
        if not chunk:
            raise RuntimeError("server closed before completing SMB2 NEGOTIATE response")
        data.extend(chunk)
    return bytes(data)


def negotiate_request():
    # Every probe uses a fresh TCP connection, and the first request on a connection must use
    # MessageId 0; Samba drops the connection on any other value (smb2_validate_sequence_number).
    message_id = 0
    # Match SMBNegotiateCodec.probeDialects, including preauth, encryption, and signing contexts.
    client_guid = os.urandom(16)
    header = struct.pack(
        "<4sHHHHHHIIQIIQ16s",
        b"\xfeSMB",
        64,
        0,
        0,
        0,
        0,
        1,
        0,
        0,
        message_id,
        0,
        0,
        0,
        bytes(16),
    )
    dialects = struct.pack("<HHHHH", 0x0202, 0x0210, 0x0300, 0x0302, 0x0311)
    salt = os.urandom(32)
    preauth_data = struct.pack("<HHH32s", 1, len(salt), 1, salt)
    encryption_data = struct.pack("<HHH", 2, 2, 1)  # AES-128-GCM, AES-128-CCM
    signing_data = struct.pack("<HH", 1, 2)  # AES-GMAC

    def context(kind, data, pad_to_eight):
        encoded = struct.pack("<HHI", kind, len(data), 0) + data
        if pad_to_eight:
            encoded += bytes((-len(encoded)) % 8)
        return encoded

    contexts = (
        context(1, preauth_data, True)
        + context(2, encryption_data, True)
        + context(8, signing_data, False)
    )
    negotiate = struct.pack("<HHHHI16sIHH", 36, 5, 1, 0, 0x40, client_guid, 112, 3, 0)
    smb2 = header + negotiate + dialects + bytes(2) + contexts
    return b"\x00" + len(smb2).to_bytes(3, "big") + smb2


def receive_negotiate_response(connection):
    direct_tcp_header = receive_exact(connection, 4)
    if direct_tcp_header[0] != 0:
        raise RuntimeError("server returned a non-SMB direct TCP response")
    response_size = int.from_bytes(direct_tcp_header[1:], "big")
    if response_size < 64 or response_size > 65536:
        raise RuntimeError(f"invalid SMB2 NEGOTIATE response size: {response_size}")
    return receive_exact(connection, response_size)


def validate_response(response):
    if response[:4] != b"\xfeSMB" or struct.unpack_from("<H", response, 12)[0] != 0:
        raise RuntimeError("server returned an invalid SMB2 NEGOTIATE response")
    if struct.unpack_from("<I", response, 8)[0] != 0:
        raise RuntimeError("server returned a failed SMB2 NEGOTIATE status")
    if not (struct.unpack_from("<I", response, 16)[0] & 1):
        raise RuntimeError("SMB2 NEGOTIATE response flag was not set")


def direct_probe(host, port):
    # Connect first, then time only the SMB request/response. Direct container IP bypasses docker-proxy.
    samples_ms = []
    for _ in range(15):
        with socket.create_connection((host, port), timeout=5) as connection:
            connection.settimeout(5)
            request = negotiate_request()
            start = time.perf_counter_ns()
            connection.sendall(request)
            response = receive_negotiate_response(connection)
            elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000
            validate_response(response)
            samples_ms.append(elapsed_ms)
    print(f"{statistics.median(samples_ms):.3f}")


def held_probe(host, port, workdir):
    # Open TCP sessions before the exact-flow tc filters are installed. This keeps TCP
    # connection establishment outside the timed interval and outside probe counters.
    connections = []
    try:
        for _ in range(15):
            connection = socket.create_connection((host, port), timeout=5)
            connection.settimeout(5)
            connections.append(connection)

        client_ips = {connection.getsockname()[0] for connection in connections}
        if len(client_ips) != 1:
            raise RuntimeError("probe sessions selected more than one client IP")
        ready_path = os.path.join(workdir, "ready")
        temporary_ready_path = ready_path + ".tmp"
        with open(temporary_ready_path, "w", encoding="utf-8") as handle:
            handle.write(next(iter(client_ips)) + "\n")
            for connection in connections:
                handle.write(str(connection.getsockname()[1]) + "\n")
        # Publish the complete 16-field tuple list atomically so the shell cannot
        # install filters from a partially written readiness file.
        os.replace(temporary_ready_path, ready_path)

        go_path = os.path.join(workdir, "go")
        deadline = time.monotonic() + 30
        while not os.path.exists(go_path):
            if time.monotonic() >= deadline:
                raise RuntimeError("timed out waiting for the probe filters")
            time.sleep(0.01)

        samples_ms = []
        for connection in connections:
            request = negotiate_request()
            start = time.perf_counter_ns()
            connection.sendall(request)
            response = receive_negotiate_response(connection)
            elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000
            validate_response(response)
            samples_ms.append(elapsed_ms)
        with open(os.path.join(workdir, "result"), "w", encoding="utf-8") as handle:
            handle.write(f"{statistics.median(samples_ms):.3f}\n")
    except Exception as error:  # surfaced to the shell through the worker exit status and stderr
        with open(os.path.join(workdir, "error"), "w", encoding="utf-8") as handle:
            handle.write(str(error) + "\n")
        raise
    finally:
        for connection in connections:
            connection.close()


def main():
    if len(sys.argv) < 4:
        raise SystemExit("usage: network-performance-study-rtt-probe.py direct|hold HOST PORT [WORKDIR]")
    mode, host, port_text = sys.argv[1:4]
    port = int(port_text)
    if mode == "direct":
        direct_probe(host, port)
    elif mode == "hold" and len(sys.argv) == 5:
        held_probe(host, port, sys.argv[4])
    else:
        raise SystemExit("invalid probe mode")


if __name__ == "__main__":
    main()
