import logging
logging.basicConfig(level=logging.DEBUG,
    format='%(asctime)s - %(name)s.%(levelname)-8s %(message)s')


import threading

import struct
logger = logging.getLogger('Timer')

class WatchdogTimer:
    def __init__(self, timeout, on_timeout):
        self.timeout = timeout
        self.on_timeout = on_timeout
        self._reset_event = threading.Event()
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        while not self._stop_event.is_set():
            triggered = not self._reset_event.wait(timeout=self.timeout)
            if triggered and not self._stop_event.is_set():
                self.on_timeout()
                break
            self._reset_event.clear()

    def reset(self):
        """Call this periodically to keep the watchdog alive."""
        self._reset_event.set()

    def stop(self):
        """Disarm the watchdog cleanly."""
        self._stop_event.set()
        self._reset_event.set()  # unblock the wait

"""
class WatchdogTimer(Exception):
    def __init__(self, timeout_sec, args=None, name='', handler=None):
        self.timeout = timeout_sec
        self.handler = handler
        self.args = args
        if self.handler is None:
            self.handler = self.default_handler
        self.timer = Timer(self.timeout, self.handler, args)
        self.timer.start()
        self.name = name

    def reset(self, timeout_sec=0):
        self.timer.cancel()
        if timeout_sec == 0:
            timeout_sec = self.timeout
        self.timeout = timeout_sec
        self.timer = Timer(timeout_sec, self.handler, self.args)
        self.timer.start()

    def stop(self):
        self.timer.cancel()
        #logger.debug('Connection timer stopped! {}'.format(self.name))

    def default_handler(self, *args):
        logger.error('Connection timeout! {} - timeout={:.3f} seconds'.format(self.name, self.timeout))

class CIP_Class3_WDT(WatchdogTimer):
    def __init__(self, timeout_sec, class3_client, name='', handler=None):
        if handler is None:
            handler = self.default_handler
        super(CIP_Class3_WDT, self).__init__(timeout_sec, [class3_client],
                name, handler)

    def default_handler(self, *args):
        client = args[0]
        logger.error('Connection timeout! {} - timeout={:.3f} seconds'.format(client, self.timeout))
        #client.ucmm.disconnect(client)
        #TODO cleanup and close socket

class EIP_EncapsulationInactivity_WDT(WatchdogTimer):
    def __init__(self, timeout_sec, uc_client, name='', handler=None):
        if handler is None:
            handler = self.default_handler
        super(EIP_EncapsulationInactivity_WDT, self).__init__(timeout_sec,
                [uc_client], name, handler)

    def default_handler(self, *args):
        session = args[0]
        logger.error('Connection timeout! {} - timeout={:.3f} seconds'.format(self.name, self.timeout))
        session.sock.close()
"""
