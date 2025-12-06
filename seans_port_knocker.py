#!/usr/bin/env python3
import os, sys, base64, socket, logging, struct, zlib, time, ipaddress, pathlib, subprocess
from collections import deque
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

def parse_message(msg: bytes):
    payload, checksum_bytes = msg[:-4], msg[-4:]
    checksum = struct.unpack("!I", checksum_bytes)[0]
    valid = (checksum == zlib.crc32(payload) & 0xFFFFFFFF)
    sec_offset, port_offset = struct.unpack("BB", payload[:2])
    body = payload[2:]
    seconds = struct.unpack("!I", body[sec_offset-2:sec_offset+2])[0]
    port = struct.unpack("!H", body[port_offset-2:port_offset])[0]
    return seconds, port, valid

def decode_addr(addr):
    address = addr[0]
    ip = ipaddress.ip_address(address)
    if ip.version == 4:
        protocol = "ipv4"
    elif ip.version == 6:
        if ip.ipv4_mapped:
            protocol = "ipv4"
            address = ip.ipv4_mapped
        else:
            protocol = "ipv6"
    else:
        raise ValueError("Unknown IP protocol")
    return protocol, address


def read_systemd_credential_as_text(credential_name: str) -> str:
    
    credentials_dir = os.environ.get("CREDENTIALS_DIRECTORY")
    if not credentials_dir:
        raise FileNotFoundError(
            "The CREDENTIALS_DIRECTORY environment variable is missing. "
            "Ensure the service unit uses SetCredentialEncrypted=."
        )

    secret_path = pathlib.Path(credentials_dir) / credential_name
    try:
        with open(secret_path, 'r', encoding='utf-8') as f:
            secret_key_text = f.read().strip()
        return secret_key_text
    except FileNotFoundError:
        raise FileNotFoundError(
            f"Secret file not found at: {secret_path}. "
            "Check that the credential name matches the service file."
        )

PORT = int(os.getenv("PORT", "9999"))

CREDENTIAL_NAME = "CHACHA20_KEY"
KEY_B64 = read_systemd_credential_as_text(CREDENTIAL_NAME)
if not KEY_B64:
    sys.exit("Set CHACHA20_KEY to a base64-encoded 32-byte key.")
KEY = base64.b64decode(KEY_B64)
if len(KEY) != 32:
    sys.exit("CHACHA20_KEY must decode to 32 bytes.")

# IPv6 socket that also accepts IPv4
BUFFER_SIZE=10000
sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
sock.bind(("::", PORT))
aead = ChaCha20Poly1305(KEY)

# Simple replay protection: track recent nonces
seen, order = set(), deque(maxlen=10000)

print(f"Listening on UDP port {PORT} (IPv4/IPv6).")
while True:
#  try:
    pkt, addr = sock.recvfrom(65535)
    print(f"New attempt...")
    if len(pkt) < 12 + 16:  # 12-byte nonce + 16-byte tag minimum
        continue
    nonce, ct = pkt[:12], pkt[12:]
    if nonce in seen:
        continue
    try:
        msg = aead.decrypt(nonce, ct, b"seans-port-knocker-v1")
    except Exception:
        continue
    seen.add(nonce); order.append(nonce)
    if len(order) == order.maxlen:
        old = order.popleft()
        seen.discard(old)

    seconds, port, valid = parse_message(msg)
    if not valid:
        continue

    skew = abs(int(time.time()) - seconds)
    if skew > 2:
        continue

    protocol, address = decode_addr(addr)
    
    print(f"Valid message from {protocol} {address} - {skew} {port}")
    #  For now, ignore requested port and have firewall open the expected one
    if protocol == 'ipv4':
        subprocess.run(['firewall-cmd', '--ipset=sshknock', f"--add-entry={address}"])
    elif protocol == 'ipv6':
        subprocess.run(['firewall-cmd', '--ipset=sshknock6', f"--add-entry={address}"])

#  except:
#    pass

