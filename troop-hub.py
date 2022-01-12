#!/usr/bin/env python3

import socket, socketserver
import ipaddress
import time, datetime
import json
import os, os.path
from threading import Thread
from subprocess import Popen, PIPE, STDOUT
import sys, logging

try:
    # Not needed for running HubServer
    import daemon
    import signal
    import psutil
except:
    pass

# Set up logging

LOGFILE = 'server.log'

class Logger:
    def __init__(self, filepath):
        self.filepath = filepath
        self.enabled = False

    def enable(self):
        self.enabled = True
        with open(self.filepath, 'w') as f:
            f.truncate()

    def info(self, string):
        if self.enabled:
            with open(self.filepath, 'a') as f:
                log = "{} - {}\n".format(
                    datetime.datetime.utcnow().isoformat(),
                    string
                )
                f.write(log)

logger = Logger(LOGFILE)

# Load conf settings

PATH = '.'
PORT = 57990
WHITELIST = []

try:
    with open('conf.json') as f:
        data = json.loads(f.read())
    PATH = data.get('path') or PATH
    PORT = data.get('port') or PORT
    WHITELIST = data.get('whitelist') or WHITELIST
except FileNotFoundError:
    pass

def get_troop_executable():
    return os.path.join(PATH, 'run-server.py')

class Whitelist:
    def __init__(self, addresses):
        local = ['127.0.0.1']
        self.networks = [
            ipaddress.IPv4Network(addr) for addr in local + list(addresses)
        ]

    def __contains__(self, address):
        address = ipaddress.IPv4Address(address)
        for network in self.networks:
            if address in network:
                return True
        return False

WHITELIST = Whitelist(WHITELIST)

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
    def handle(self):
        """
        self.request = socket
        self.server  = HubServer
        self.client_address = (address, port)
        """
        self.daemonized = False

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

    def handle_kill(self, data):
        '''
        Used to manually kill a hub by name. Accepts only requests from
        localhost.
        '''
        if 'name' not in data:
            return self.error('No instance name given', in_validation=True)

        elif self.client_address[0] not in WHITELIST:
            return self.error(
                'External kill request denied', in_validation=True
            )

        instance = self.server._clients.get(data['name'])
        if not instance:
            return self.error(
                'Hub instance "{}" not found'.format(data['name']),
                in_validation=True
            )

        instance.error('Session manually killed by admin.')
        self.send({'data': 'success'})

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
            get_troop_executable(),
            '--port', str(self.port),
            '--password', data['password']
            ]
        self.process = Popen(args, stdout=PIPE)

        # Add to server and start
        self.server.add_client(self)
        self.send({'address': self.public_address})
        self.println("New session started")

        # Don't poll client if daemonized
        self.daemonized = data.get('daemon')
        if not self.daemonized:
            self.alive = True
            while True:
                data = self.recv()
                if not self.alive:
                    return
                if not data:
                    return self.kill()

        return

    def handle_list(self, request):
        """
        Returns a JSON string with information about the existing server
        instances. Request must come from a whitelisted IP.
        """
        if self.client_address[0] not in WHITELIST:
            return self.error(
                'Status request made from invalid address {}'.format(
                    self.client_address[0]
                ),
                in_validation=True
            )

        return self.send({'data': self.server.server_list()})

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

        ip = self.client_address[0]
        if ip not in WHITELIST and ip in self.server.address_book():
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
        if not self.daemonized:
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
        output = "({}) {} -> {} [origin @ {}:{}]".format(
            self.id, self.name, message,
            *self.client_address
        )
        if not self.server._daemon_mode:
            print(output)
        logger.info(output)

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

        self._daemon_mode = kwargs.get('daemon', False)
        self._lockfile = kwargs.get('lockfile')

        logger.info('Booting')

        super().__init__((host, port), HubRequestHandler)

        if self._daemon_mode and not self._lockfile:
            raise ValueError(
                "'lockfile' argument must be provided when 'daemon' mode is set."
            )

        self._ip_addr, self._port = self.server_address
        self._max_clients = kwargs.get('max_clients', 10)
        self._thread = Thread(target=self.serve_forever)
        self._thread.daemon = True
        self._clients = {}
        self._id = 0 # ID tracker for handlers
        self._running = False

    def run(self):

        print("Troop Hub running on {}:{}".format(
            self.public_ip,
            self._port
        ))

        # Start thread and write pid to lockfile
        self._thread.start()
        self._running = True

        while self._running:
            try:
                if self._daemon_mode and not os.path.exists(self._lockfile):
                    self.write_to_lockfile()
                time.sleep(1)
            except KeyboardInterrupt:
                print("Exiting...")
                self.kill()
            except Exception as err:
                print(err)
                logger.info(str(err))

        self.server_close()
        return

    def write_to_lockfile(self, pid=None):
        """ Writes the pid to the lockfile. Defaults to os.getpid() """
        with open(self._lockfile, 'w') as f:
            pid = (pid or os.getpid())
            f.write(str(pid))
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
        return (client.client_address[0] for client in self._clients.values())

    def server_names(self):
        return (server.name for server in self._clients.values())

    def server_list(self):
        return [{
            'name': server.name,
            'id': server.id
        } for server in self._clients.values()]

    def add_client(self, client):
        self._clients[client.name] = client

    def remove_client(self, name):
        del self._clients[name]

    def kill(self):
        """ Cleanly kills all connected clients then exits """
        for client in list(self._clients.values()):
            client.error("Troop Hub Service has been manually terminated")
        self._running = False
        return

class HubDaemon:
    lockfile = '.daemon.lock'
    allowed_commands = ['start', 'stop', 'restart', 'status', 'kill']

    def __init__(self, debug=False):
        self.debug = debug

    def _kill(self, signum=None, frame=None):
        ''' Kills the daemon - not a server '''
        os.remove(self.lockfile)
        sys.exit(0)

    def start(self, *args):
        # Check if process exists
        if self.get_pid():
            sys.exit("Process already running")

        print("Starting Troop Hub Service")

        logger.enable()

        kwargs = {}
        if self.debug:
            kwargs.update(stdout=sys.stdout, stderr=sys.stdout)
        kwargs.update(
            working_directory='.',
            signal_map={
                signal.SIGTERM: self._kill,
                signal.SIGTSTP: self._kill
            }
        )

        with daemon.DaemonContext(**kwargs):
            HubServer(daemon=True, lockfile=self.lockfile).run()

    def stop(self, *args, kill=True):
        pid = self.get_pid()
        if not pid:
            sys.exit('No running Troop Hub Service')
        print("Killing Troop Hub Service - pid: {}".format(pid))
        os.kill(pid, signal.SIGKILL)
        if kill:
            self._kill()
        else:
            os.remove(self.lockfile)
        return

    def status(self, *args):
        pid = self.get_pid()
        if not pid:
            sys.exit('No running Troop Hub Service')
        parent = psutil.Process(pid)
        output = []
        output.append("Troop Hub Service")
        output.append("Running Servers: {}".format(parent.num_threads() - 2))
        cpu_total = parent.cpu_percent(0.1)
        for child in parent.children(recursive=True):
            cpu_total += child.cpu_percent(0.1)
        output.append("CPU: {}%".format(cpu_total))
        print("\n".join(output))

    def restart(self, *args):
        self.stop(kill=False)
        self.start()

    def kill(self, hubname):
        ''' Command to kill a hub, not the daemon '''
        pid = self.get_pid()
        if not pid:
            sys.exit('No running Troop Hub Service')

        # Kill via socket
        s = socket.socket()
        s.connect(('localhost', PORT))
        s.send(
            JSONMessage({
                'type': 'kill',
                'name': hubname
            }).string.encode()
        )
        bits = int(s.recv(4).decode())
        data = json.loads(s.recv(bits).decode())
        if 'error' in data:
            print("Error: " + data['error'])
        else:
            print("Hub '{}' manually killed.".format(hubname))
        s.close()

    def run(self, args):
        # Re-run imports to confirm installation
        import daemon, signal, psutil

        if not len(args):
            return self.exit()
        command = args[0].lower()
        if command in self.allowed_commands:
            handler = getattr(self, command, None)
            if handler:
                return handler(*args[1:])
        return self.exit()

    def get_pid(self):
        if os.path.exists(self.lockfile):
            with open(self.lockfile) as f:
                pid = int(f.readline().strip())
                if psutil.pid_exists(pid):
                    return pid
        return None

    def exit(self):
        sys.exit("Usage: python {} [-d] [{}]".format(
            sys.argv[0], ", ".join(self.allowed_commands)
        ))


if __name__ == "__main__":

    assert os.path.exists(get_troop_executable()), "Could not find 'run-server.py'"

    if len(sys.argv) == 1:

        HubServer(max_clients=10).run()

    elif sys.argv[1] == '-d':

        import daemon
        import signal
        import psutil

        process = HubDaemon()
        process.run(sys.argv[2:])

    else:

        HubDaemon().exit()
