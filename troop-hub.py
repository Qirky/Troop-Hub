import socket, socketserver
import time
import json
import tempfile
from threading import Thread
from subprocess import Popen, PIPE, STDOUT
from hashlib import md5

class JSONMessage:
    """ Wrapper for JSON messages sent to the server """
    def __init__(self, data):
        self.data = data

    def __str__(self):
        return self.string

    @property
    def string(self):
        """
        Prepares the json message to be sent with first 4 digits
        denoting the length of the message
        """
        if not hasattr(self, "_string"):
            packet = str(json.dumps(self.data, separators=(',',':')))
            length = "{:04d}".format( len(packet) )
            self._string = length + packet
        return self._string

    def __len__(self):
        return len(str(self))

class HubRequestHandler(socketserver.BaseRequestHandler):
    path = "../troop/run-server.py"
    def handle(self):
        """
        self.request = socket
        self.server  = HubServer
        self.client_address = (address, port)
        """
        # Return error message if too many connected etc
        data = self.validate_request()
        if not data:
            return

        # Set port and password or Troop Server
        port = self.server.get_next_port()
        args = [
            self.path,
            '--port', str(port),
            '--password', data['password']
            ]
        self.process = Popen(args, stdout=PIPE)

        # Add to server and start
        self.server.add_client(self.client_address, self)
        self.send({'address': (self.server.public_ip,  port)})
        self.println("New session started")

        self.alive = True

        data = self.recv()
        if not self.alive:
            return
        if not data:
            return self.kill()

        return

    def validate_request(self):
        """ Checks whether to continue handling the request """
        if len(self.server._clients) >= self.server._max_clients:
            return self.error(
                "Max number of running Troop instances reached",
                in_validation=True
            )
        if self.client_address in self.server:
            return self.error(
                "A running Troop server has already been started from "
                "this address",
                in_validation=True
            )
        data = self.recv()
        if 'password' not in data:
            return self.error("No password set", in_validation=True)
        return data

    def error(self, message, in_validation=False):
        '''
        Sends an error to the client and kills the process if post-validation
        '''
        self.send({'error': message})
        if not in_validation:
            return self.kill()

    def kill(self):
        self.alive = False
        self.process.kill()
        self.server.remove_client(self.client_address)
        self.println("Session has finished")
        return 0

    def recv(self):
        """ Reads data from the socket """
        # Get number single int that tells us how many digits to read
        try:
            bits = int(self.request.recv(4).decode())
        except:
            return None
        if bits > 0:
            # Read the remaining data (JSON)
            data = self.request.recv(bits).decode()
            # Convert back to Python data structure
            return json.loads(data)

    def send(self, data):
        """ Converts Python data structure to JSON message and
            sends to a connected socket """
        msg = JSONMessage(data)
        # Get length and store as string
        msg_len, msg_str = len(msg), str(msg).encode()
        # Continually send until we know all of the data has been sent
        sent = 0
        while sent < msg_len:
            bits = self.request.send(msg_str[sent:])
            sent += bits
        return

    def println(self, message):
        print("{} - {} [origin @ {}:{}]".format(
            self.id,
            message,
            *self.client_address
        ))

    @property
    def id(self):
        if not hasattr(self, '_id'):
            self.server._id += 1
            self._id = self.server._id
        return self._id

class HubServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    def __init__(self, *args, **kwargs):
        HOST = kwargs.get('host', "0.0.0.0")
        PORT = kwargs.get('port', 57990)
        super().__init__((HOST, PORT), HubRequestHandler)

        self._ip_addr, self._port = self.server_address
        self._max_clients = kwargs.get('max_clients', 10)
        self._thread = Thread(target=self.serve_forever)
        self._clients = {}
        self._id = 0 # ID tracker for handlers

    def run(self):
        print("Troop Hub running on {}:{}".format(
            self.public_ip,
            self._port
        ))
        try:
            self.serve_forever()
        except KeyboardInterrupt:
            print("Exiting...")
            return self.kill()
        return

    @property
    def public_ip(self):
        if not hasattr(self, '_public_ip'):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                self._public_ip = s.getsockname()[0]
                s.close()
            except OSError:
                self._public_ip = socket.gethostbyname("localhost")
        return self._public_ip

    def get_next_port(self):
        """ Returns the next available port """
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        next_port = self._port + 1
        while True:
            port_in_use = s.connect_ex(('127.0.0.1', next_port))
            if not port_in_use:
                return next_port
            next_port += 1
        return

    def __contains__(self, address):
        return address[0] in (addr[0] for addr in self._clients)

    def add_client(self, address, client):
        self._clients[address] = client

    def remove_client(self, address):
        # Check if process needs killing first
        del self._clients[address]

    def kill(self):
        """ Cleanly kills all connected clients then exits """
        for client in list(self._clients.values()):
            client.error("Troop Hub Service has been manually terminated")
        return


if __name__ == "__main__":

    server = HubServer()
    server.run()
