import socket, socketserver
import time
import json
from threading import Thread
from subprocess import Popen, PIPE, STDOUT

# Load conf settings

PATH = '.'
PORT = 57990

try:
    f = open('conf.txt')
    for line in f.readlines():
        if line.startswith('path'):
            PATH = line.split('=')[-1]
        elif line.startswith('port'):
            PORT = int(line.split('=')[-1])
    f.close()
except FileNotFoundError:
    pass

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
    path = PATH
    def handle(self):
        """
        self.request = socket
        self.server  = HubServer
        self.client_address = (address, port)
        """
        # Get type of request
        request = self.recv()
        if 'type' not in request:
            return self.error('No request type given', in_validation=True)

        handle = getattr(self, 'handle_' + request['type'].lower())
        return handle(request)

    def handle_query(self, data):
        '''
        Returns the (address, port) tuple for a Troop server with a given name
        '''
        if 'name' not in data:
            return self.error('No instance name given')
        instance = self.server._clients.get(data['name'])
        return self.send({'result': getattr(instance, 'public_address', None)})

    def handle_server(self, data):
        '''
        Starts a new Troop server on this Hub
        '''
        # Return error message if too many connected etc
        validated = self.validate_request(data)
        if not validated:
            return

        # Set port and password or Troop Server
        self.name = data['name']
        self.port = self.server.get_next_port()
        self.public_address = (self.server.public_ip,  self.port)
        args = [
            self.path,
            '--port', str(self.port),
            '--password', data['password']
            ]
        self.process = Popen(args, stdout=PIPE)

        # Add to server and start
        self.server.add_client(self)
        self.send({'address': self.public_address})
        self.println("New session started")

        self.alive = True

        while True:
            data = self.recv()
            if not self.alive:
                return
            if not data:
                return self.kill()

        return

    def validate_request(self, request):
        """ Checks whether to continue handling the request """
        if 'name' not in request:
            return self.error("No instance name given", in_validation=True)
        if 'password' not in request:
            return self.error("No password set", in_validation=True)
        if len(self.server._clients) >= self.server._max_clients:
            return self.error(
                "Max number of running Troop instances reached",
                in_validation=True
            )
        if self.client_address[0] in self.server.address_book():
            return self.error(
                "A running Troop server has already been started from "
                "this address",
                in_validation=True
            )
        if request['name'] in self.server.server_names():
            return self.error(
                "A running Troop server already exists with this name"
            )
        return request

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
        self.server.remove_client(self.name)
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
        print("({}) {} -> {} [origin @ {}:{}]".format(
            self.id, self.name, message,
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
        host = kwargs.get('host', "0.0.0.0")
        port = kwargs.get('port', PORT)
        super().__init__((host, port), HubRequestHandler)

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

    def address_book(self):
        return (addr[0] for addr in self._clients.keys())

    def server_names(self):
        return (server.name for server in self._clients.values())

    def add_client(self, client):
        self._clients[client.name] = client

    def remove_client(self, name):
        # TODO Check if process needs killing first
        del self._clients[name]

    def kill(self):
        """ Cleanly kills all connected clients then exits """
        for client in list(self._clients.values()):
            client.error("Troop Hub Service has been manually terminated")
        return


if __name__ == "__main__":

    server = HubServer()
    server.run()
