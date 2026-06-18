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
