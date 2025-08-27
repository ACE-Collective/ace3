from dataclasses import dataclass
from datetime import datetime
import ipaddress
import logging
import os
import re
import socket
import sys
from threading import RLock, Thread
import threading
import time
from typing import Optional
from saq.configuration.config import get_config
from saq.constants import CONFIG_NETWORK_SEMAPHORE
from saq.environment import get_data_dir
from saq.error.reporting import report_exception
from saq.network_semaphore.fallback import initialize_fallback_semaphores
from saq.network_semaphore.logging import LoggingSemaphore

@dataclass
class NetworkSemaphoreConfig:
    bind_address: str
    bind_port: int
    semaphore_limits: dict[str, int]
    stats_dir: str

    @staticmethod
    def load_from_config() -> "NetworkSemaphoreConfig":
        config = get_config()[CONFIG_NETWORK_SEMAPHORE]
        semaphore_limits = {}
        for key in config.keys():
            if key.startswith('semaphore_'):
                semaphore_name = key[len('semaphore_'):]
                semaphore_limits[semaphore_name] = config.getint(key)

        return NetworkSemaphoreConfig(
            bind_address=config['bind_address'],
            bind_port=config.getint('bind_port'),
            semaphore_limits=semaphore_limits,
            stats_dir=os.path.join(get_data_dir(), "var", "stats", "network_semaphore"))


class NetworkSemaphoreServer:
    def __init__(self, config: Optional[NetworkSemaphoreConfig] = None):
        if config is None:
            config = NetworkSemaphoreConfig.load_from_config()

        self.config = config

        # the main thread that listens for new connections
        self.server_thread: Optional[Thread] = None
        self.monitor_thread: Optional[Thread] = None

        self.shutdown_event = threading.Event()
        self.server_started_event = threading.Event()
        self.monitor_started_event = threading.Event()

        # the main listening socket
        self.server_socket: Optional[socket.socket] = None

        # load and initialize all the semaphores we're going to use
        self.defined_semaphores = {} # key = semaphore_name, value = LoggingSemaphore
        self.undefined_semaphores = {} # key = semaphore_name, value = LoggingSemaphore
        self.undefined_semaphores_lock = RLock()

        # TODO emit statistics instead
        # we keep some stats and metrics on semaphores in this directory
        if not os.path.isdir(self.config.stats_dir):
            os.makedirs(self.config.stats_dir)

    @property
    def is_shutdown(self) -> bool:
        return self.shutdown_event.is_set()

    def start(self):
        initialize_fallback_semaphores(force=True)

        self.server_thread = Thread(target=self.server_loop, name="Network Server")
        self.server_thread.start()

        self.monitor_thread = Thread(target=self.monitor_loop, name="Monitor")
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
    
    def wait_for_start(self, timeout: float = 5) -> bool:
        return self.server_started_event.wait(timeout) and self.monitor_started_event.wait(timeout)
    
    def stop(self):
        self.shutdown_event.set()

        try:
            logging.debug("closing network socket...")
            # force the accept() call to break
            try:
                s = socket.socket()
                s.connect((self.config.bind_address, self.config.bind_port))
                s.close()
            except Exception as e:
                logging.debug(f"unable to force accept() call to break: {e}")
        except Exception as e:
            logging.error(f"unable to close network socket: {e}")
    
    def wait(self):
        if self.server_thread:
            logging.debug("joining server thread...")
            self.server_thread.join()
        if self.monitor_thread:
            logging.debug("joining monitor thread...")
            self.monitor_thread.join()

        logging.debug("server stopped")

    def add_undefined_semaphore(self, name, count=1):
        """Adds a new undefined network semaphore with the given name and optional count.
           Returns the created semaphore."""
        with self.undefined_semaphores_lock:
            self.undefined_semaphores[name] = LoggingSemaphore(count)
            self.undefined_semaphores[name].semaphore_name = name 
            logging.info(f"adding undefined semaphore {name}")
            return self.undefined_semaphores[name]

    def maintain_undefined_semaphores(self):
        with self.undefined_semaphores_lock:
            targets = []
            for semaphore_name in self.undefined_semaphores.keys():
                if self.undefined_semaphores[semaphore_name].count == 0:
                    targets.append(semaphore_name)

            for target in targets:
                logging.debug(f"finished with undefined semaphore {target}")
                del self.undefined_semaphores[target]

            if self.undefined_semaphores:
                logging.info(f"tracking {len(self.undefined_semaphores)} undefined semaphores")

    def load_configured_semaphores(self):
        """Loads all network semaphores defined in the configuration."""
        for semaphore_name, count in self.config.semaphore_limits.items():
            self.defined_semaphores[semaphore_name] = LoggingSemaphore(count)
            self.defined_semaphores[semaphore_name].semaphore_name = semaphore_name 

    def get_semaphore(self, name: str) -> Optional[LoggingSemaphore]:
        return self.defined_semaphores.get(name)

    def monitor_loop(self):
        semaphore_status_path = os.path.join(self.config.stats_dir, 'semaphore.status')
        self.monitor_started_event.set()
        while not self.is_shutdown:
            with open(semaphore_status_path, 'w') as fp:
                for semaphore in self.defined_semaphores.values():
                    fp.write(f'{semaphore.semaphore_name}: {semaphore.count}')

            self.shutdown_event.wait(1)

    def server_loop(self):
        self.load_configured_semaphores()
        self.server_started_event.set()
        while not self.is_shutdown:
            try:
                self.server_socket = socket.socket() # defaults to AF_INET, SOCK_STREAM
                self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.server_socket.bind((self.config.bind_address, self.config.bind_port))
                self.server_socket.listen(5)

                while not self.is_shutdown:
                    logging.debug(f"waiting for next connection on {self.config.bind_address}:{self.config.bind_port}")
                    client_socket, remote_address = self.server_socket.accept()
                    remote_host, remote_port = remote_address
                    logging.info(f"got connection from {remote_host}:{remote_port}")
                    if self.is_shutdown:
                        break

                    # start a thread to deal with this client
                    t = Thread(target=self.client_loop, args=(remote_host, remote_port, client_socket), name=f"Client {remote_host}")
                    t.daemon = True
                    t.start()
                    
            except Exception as e:
                logging.error(f"uncaught exception: {e}")
                report_exception()

                # TODO clean up socket stuff to restart
                self.shutdown_event.wait(1)

        try:
            logging.debug("closing server socket...")
            self.server_socket.close()
            logging.debug("server socket closed")
        except Exception as e:
            logging.debug(f"unable to close server socket: {e}")

        logging.debug("server loop exited")

    def client_loop(self, remote_host, remote_port, client_socket):
        remote_connection = f'{remote_host}:{remote_port}'
        try:
            logging.debug(f"started thread to handle connection from {remote_connection}")

            # read the next command from the client
            command = client_socket.recv(128).decode('ascii')
            if command == '':
                logging.debug("detected client disconnect")
                return

            logging.info(f"got command [{command}] from {remote_connection}")
            # super simple protocol
            # CLIENT SEND -> acquire:semaphore_name|
            # SERVER SEND -> wait|
            # SERVER SEND -> locked|
            # CLIENT SEND -> wait|
            # CLIENT SEND -> release|
            # SERVER SEND -> ok|
            # any invalid input or errors causes the connection to terminate

            m = re.match(r'^acquire:([^|]+)\|$', command)
            if m is None:
                logging.warning(f"invalid command \"{command}\" from {remote_connection}")
                return

            semaphore_name = m.group(1)

            try:
                semaphore = self.defined_semaphores[semaphore_name]
            except KeyError:
                with self.undefined_semaphores_lock:
                    try:
                        semaphore = self.undefined_semaphores[semaphore_name]
                    except KeyError:
                        semaphore = self.add_undefined_semaphore(semaphore_name, 1)

            semaphore_acquired = False
            request_time = datetime.now()
            try:
                while True:
                    logging.debug(f"attempting to acquire semaphore {semaphore_name}")
                    semaphore_acquired = semaphore.acquire(blocking=True, timeout=1)
                    if not semaphore_acquired:
                        logging.info("{} waiting for semaphore {} cumulative waiting time {}".format(
                            remote_connection, semaphore_name, datetime.now() - request_time))
                        # send a heartbeat message back to the client
                        client_socket.sendall("wait|".encode('ascii'))
                        continue

                    logging.info(f"acquired semaphore {semaphore_name}")
                    client_socket.sendall("locked|".encode('ascii'))
                    break

                # now wait for either the client to release the semaphore
                # or for the connection to break
                release_time = datetime.now()
                while True:
                    command = client_socket.recv(128).decode('ascii')
                    if command == '':
                        logging.debug("detected client disconnect")
                        return

                    logging.debug("got command {} from {} semaphore capture time {}".format(
                        command, remote_connection, datetime.now() - release_time))

                    if not command.endswith('|'):
                        logging.error("missing pipe at end of command")
                        return

                    # deal with the possibility of multiple commands sent in a single packet
                    # strip the last pipe
                    # XXX not 100% sure on this but here it is
                    command = command[:-1]
                    commands = command.split('|')
                    if 'release' in commands:
                        # send the OK to the client
                        client_socket.sendall('ok|'.encode('ascii'))
                        break

                    if all([x == 'wait' for x in commands]):
                        logging.debug("got wait command(s)...")
                        continue

                    logging.error(f"invalid command {command} from connection {remote_connection}")
                    return
            finally:
                try:
                    if semaphore_acquired:
                        semaphore.release()
                        logging.info(f"released semaphore {semaphore_name}")
                        self.maintain_undefined_semaphores()
                except Exception as e:
                    logging.error(f"error releasing semaphore {semaphore_name}: {e}")

        except Exception as e:
            logging.info(f"uncaught exception for {remote_connection}: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass