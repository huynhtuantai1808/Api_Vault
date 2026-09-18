import socket
import select
import logging

class GuacamoleClient:
    """
    A simple Python client to connect to guacd (Apache Guacamole daemon) 
    and perform the initial handshake.
    """
    def __init__(self, host='127.0.0.1', port=4822, timeout=10):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock = None
        self.leftover = b""

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))

    def _encode(self, *args):
        parts = []
        for arg in args:
            arg_str = str(arg)
            parts.append(f"{len(arg_str)}.{arg_str}")
        return ",".join(parts) + ";"

    def _decode(self, data):
        # A simple generator to decode Guacamole instructions
        buffer = data
        while buffer:
            semicolon = buffer.find(';')
            if semicolon == -1:
                break
            instruction = buffer[:semicolon+1]
            buffer = buffer[semicolon+1:]
            
            parts = []
            inst_buffer = instruction[:-1] # remove semicolon
            while inst_buffer:
                dot = inst_buffer.find('.')
                if dot == -1:
                    break
                length = int(inst_buffer[:dot])
                val = inst_buffer[dot+1:dot+1+length]
                parts.append(val)
                inst_buffer = inst_buffer[dot+1+length:]
                if inst_buffer.startswith(','):
                    inst_buffer = inst_buffer[1:]
            yield parts

    def send(self, *args):
        msg = self._encode(*args)
        self.sock.sendall(msg.encode('utf-8'))

    def handshake(self, protocol, **kwargs):
        """
        Perform Guacamole handshake:
        1. select,<protocol>
        2. recv args
        3. send size, audio, video, image
        4. connect,<args...>
        5. recv ready
        """
        self.send("select", protocol)
        
        # Read args response
        data = b""
        while b";" not in data:
            data += self.sock.recv(4096)
            
        text = data.decode('utf-8')
        args_inst = next(self._decode(text))
        
        if args_inst[0] != "args":
            raise Exception(f"Expected args, got {args_inst[0]}")
            
        arg_names = args_inst[1:]
        
        # Send size, audio, video, image
        width = kwargs.get('width', 1920)
        height = kwargs.get('height', 1080)
        self.send("size", str(width), str(height), "96")
        self.send("audio", "audio/L16")
        self.send("video")
        self.send("image", "image/png", "image/jpeg", "image/webp")
        
        # Build connect arguments
        connect_args = ["connect"]
        for arg_name in arg_names:
            connect_args.append(kwargs.get(arg_name, ""))
            
        self.send(*connect_args)
        
        # Read ready response
        ready_data = b""
        while b";" not in ready_data:
            ready_data += self.sock.recv(4096)
            
        ready_text = ready_data.decode('utf-8')
        semicolon_idx = ready_data.find(b';')
        
        self.leftover = ready_data[semicolon_idx+1:]
        ready_inst = next(self._decode(ready_data[:semicolon_idx+1].decode('utf-8')))
        
        if ready_inst[0] != "ready":
            raise Exception(f"Expected ready, got {ready_inst[0]}")
            
        return ready_inst[1] # connection ID

    def read(self, size=4096):
        if self.leftover:
            data = self.leftover
            self.leftover = b""
            return data
        return self.sock.recv(size)

    def write(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        self.sock.sendall(data)
        
    def close(self):
        if self.sock:
            self.sock.close()
