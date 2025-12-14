from datetime import datetime, timedelta
import logging
import socket
from threading import Event, Thread
from saq.configuration.config import get_service_config
from saq.constants import SERVICE_NETWORK_SEMAPHORE
from saq.environment import get_global_runtime_settings
from saq.error.reporting import report_exception
from saq.network_semaphore.config import NetworkSemaphoreConfig
from saq.network_semaphore.fallback import add_undefined_fallback_semaphore, get_defined_fallback_semaphores, get_undefined_fallback_semaphores, get_undefined_fallback_semaphores_lock, maintain_undefined_semaphores


class NetworkSemaphoreClient:
    def __init__(self, cancel_request_callback=None):
        # the remote connection to the network semaphore server
        self.socket = None
        # this is set to True if the client was able to acquire a semaphore
        self.semaphore_acquired = False
        # the name of the acquired semaphore
        self.semaphore_name = None
        # a failsafe thread to make sure we end up releasing the semaphore
        self.failsafe_thread = None
        # set when the semaphore is released (causing the failsafe thread to exit)
        self.release_event = None
        # reference to the relavent configuration section
        self.config: NetworkSemaphoreConfig = get_service_config(SERVICE_NETWORK_SEMAPHORE)
        # if we ended up using a fallback semaphore
        self.fallback_semaphore = None
        # use this to cancel the request to acquire a semaphore
        self.cancel_request_flag = False
        # OR use this function to determine if we should cancel the request
        # the function returns True if the request should be cancelled, False otherwise
        self.cancel_request_callback = cancel_request_callback

    @property
    def request_is_cancelled(self):
        """Returns True if the request has been cancelled, False otherwise.
           The request is cancelled if cancel_request_flag is True OR 
           cancel_request_callback is defined and it returns True."""
        
        return self.cancel_request_flag or ( self.cancel_request_callback is not None
                                             and self.cancel_request_callback() )

    def acquire(self, semaphore_name, timeout=None):
        if self.semaphore_acquired:
            logging.warning(f"semaphore {self.semaphore_name} already acquired")
            return True

        deadline = None
        if timeout is not None:
            deadline = datetime.now() + timedelta(seconds=timeout)

        try:
            self.socket = socket.socket()
            logging.debug("attempting connection to {} port {}".format(self.config.remote_address, self.config.remote_port))

            self.socket.connect((self.config.remote_address, self.config.remote_port))
            logging.info(f"requesting semaphore {semaphore_name}")

            # request the semaphore
            self.socket.sendall('acquire:{}|'.format(semaphore_name).encode('ascii'))

            # wait for the acquire to complete
            wait_start = datetime.now()

            while not self.request_is_cancelled:
                command = self.socket.recv(128).decode('ascii')
                if command == '':
                    raise RuntimeError("detected client disconnect")

                logging.debug(f"received command {command} from server")

                # deal with the possibility of multiple commands sent in a single packet
                # (remember to strip the last pipe)
                commands = command[:-1].split('|')
                if 'locked' in commands:
                    logging.info(f"semaphore {semaphore_name} locked")
                    self.semaphore_acquired = True
                    self.semaphore_name = semaphore_name
                    self.release_event = Event()
                    self.start_failsafe_monitor()
                    return True

                elif all([x == 'wait' for x in commands]):
                    pass

                else:
                    raise ValueError(f"received invalid command {command}")

                # have we timed out waiting?
                if deadline and datetime.now() >= deadline:
                    logging.error(f"attempt to acquire semaphore {semaphore_name} timed out")

                    try:
                        self.socket.close()
                    except Exception:
                        pass

                    return False

            logging.debug(f"semaphore request for {semaphore_name} cancelled")

            try:
                self.socket.close()
            except Exception:
                pass

            return False

        except Exception as e:
            logging.warning(f"unable to acquire network semaphore {semaphore_name}: {e}")

            try:
                self.socket.close()
            except Exception as e:
                pass

            # use the fallback semaphore
            try:
                logging.warning(f"acquiring fallback semaphore {semaphore_name}")
                while not self.request_is_cancelled:
                    try:
                        semaphore = get_defined_fallback_semaphores()[semaphore_name]
                    except KeyError:
                        try:
                            with get_undefined_fallback_semaphores_lock():
                                semaphore = get_undefined_fallback_semaphores()[semaphore_name]
                        except KeyError:
                            semaphore = add_undefined_fallback_semaphore(semaphore_name)

                    if semaphore.acquire(blocking=True, timeout=0.1):
                        logging.info(f"fallback semaphore {semaphore_name} acquired")
                        self.fallback_semaphore = semaphore
                        self.semaphore_acquired = True
                        self.semaphore_name = semaphore_name
                        self.release_event = Event()
                        self.start_failsafe_monitor()
                        return True

                    if deadline and datetime.now() >= deadline:
                        logging.error(f"attempt to acquire semaphore {semaphore_name} timed out")
                        return False
                
                return False
                    
            except Exception as e:
                logging.error(f"unable to use fallback semaphore {semaphore_name}: {e}")
                report_exception()

            return False

    def cancel_request(self):
        self.cancel_request_flag = True

    def failsafe_loop(self):
        # we start a side-thread to monitor this time the semaphore is held
        # we basically just log the fact that we still have it so we can
        # see that when we are debugging
        try:
            acquire_time = datetime.now()
            while not self.release_event.wait(3):
                logging.debug("semaphore {} lock time {}".format(
                    self.semaphore_name, datetime.now() - acquire_time))

                # if we are still in network mode then send a keep-alive message to the server
                if self.fallback_semaphore is None:
                    self.socket.sendall('wait|'.encode('ascii'))

            logging.debug(f"detected release of semaphore {self.semaphore_name}")
                
        except Exception as e:
            # this can happen when the remote side abruptly closes the connection
            # such as when a process gets killed
            logging.warning(f"failsafe on semaphore {self.semaphore_name} error {e}")

            try:
                self.socket.close()
            except:
                pass

    def start_failsafe_monitor(self):
        self.failsafe_thread = Thread(target=self.failsafe_loop, name=f"Failsafe {self.semaphore_name}")
        self.failsafe_thread.daemon = True
        self.failsafe_thread.start()

    def release(self):
        if not self.semaphore_acquired:
            logging.warning(f"release called on unacquired semaphore {self.semaphore_name}")

        # are we releasing a fallback semaphore?
        if self.fallback_semaphore is not None:
            logging.info(f"releasing fallback semaphore {self.semaphore_name}")
            try:
                self.fallback_semaphore.release()
            except Exception as e:
                logging.error(f"unable to release fallback semaphore {self.semaphore_name}: {e}")
                report_exception(e)

            # make sure we set this so that the monitor thread exits
            self.semaphore_acquired = False
            self.release_event.set()
            self.failsafe_thread.join()
            maintain_undefined_semaphores()
            return

        try:
            # send the command for release
            logging.info(f"releasing semaphore {self.semaphore_name}")
            self.socket.sendall("release|".encode('ascii'))

            # wait for the ok
            command = self.socket.recv(128).decode('ascii')
            if command == '':
                logging.debug("detected client disconnect")
                return

            logging.debug(f"recevied response from server: {command}")
            if command == 'ok|':
                logging.debug(f"successfully released semaphore {self.semaphore_name}")
                return
            else:
                logging.error("invalid response from server")
                return

        except Exception as e:
            logging.error(f"error trying to release semaphore {self.semaphore_name}: {e}")
        finally:
            try:
                self.socket.close()
            except Exception:
                pass

            # make sure we set this so that the monitor thread exits
            self.semaphore_acquired = False
            self.release_event.set()
            self.failsafe_thread.join()

class NetworkSemaphore():
    def __init__(self, name):
        self.name = name
        self.semaphore = NetworkSemaphoreClient()

    def __enter__(self):
        if not get_global_runtime_settings().semaphores_enabled:
            return self

        if not self.semaphore.acquire(self.name):
            raise RuntimeError(f'failed to acquire network semaphore: {self.name}')

        return self

    def __exit__(self, type, value, traceback):
        if self.semaphore.semaphore_acquired:
            self.semaphore.release()