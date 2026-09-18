import socket
import sys

def encode(*args):
    parts = []
    for arg in args:
        arg_str = str(arg)
        parts.append(f"{len(arg_str)}.{arg_str}")
    return ",".join(parts) + ";"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("127.0.0.1", 4822))

s.sendall(encode("select", "rdp").encode('utf-8'))
data = s.recv(4096)
print("Handshake response:", data)

s.sendall(encode("size", "1920", "1080", "96").encode('utf-8'))
s.sendall(encode("audio", "audio/L16").encode('utf-8'))
s.sendall(encode("video").encode('utf-8'))
s.sendall(encode("image", "image/png", "image/jpeg").encode('utf-8'))
s.sendall(encode("connect").encode('utf-8'))

while True:
    data = s.recv(4096)
    if not data:
        break
    # Print the first few bytes to see what instruction it is
    print("Received:", data[:100])
    
    # Auto-reply to sync
    if b"sync" in data:
        print("Got sync!")
