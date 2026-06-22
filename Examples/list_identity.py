import logging
logging.basicConfig(level=logging.INFO,
    format="%(asctime)s - %(levelname)-8s <%(name)s> %(message)s")
logger = logging.getLogger(__name__)

from REWire import (
    UDP,
    TCP,
    list_identity,
)

def list_identity_demo(host_ip):
    """
    Example demonstrating the list_identity service of the encapsulation layer.

    This example covers three list_identity scenarios:
        - Broadcast List Identity over UDP.
        - Unicast List Identity over UDP.
        - Unicast List Identity over TCP.

    Note: When using the built-in NIC and standard OS timestamping, the
          measured delays are not accurate to the millisecond. However, they are
          sufficiently accurate for calculating the average response delay.
    """
    logger.info("Testing ListIdentity timing over UDP broadcast with 700 ms delay...")

    TEST_CYCLES = 100
    MAX_DELAY_MS = 700

    report = {}
    sock = UDP(host_ip, "255.255.255.255")
    for _ in range(TEST_CYCLES):
        discovered_devices = list_identity(sock, max_delay_ms=MAX_DELAY_MS)

        for device in discovered_devices:
            sender_ip = device["address"][0]
            response_delay = device["delay"]
            delay_list = report.get(sender_ip, [])
            delay_list.append(response_delay)
            report[sender_ip] = delay_list

    logger.info(f"*** Result for {TEST_CYCLES} list identity requests with a max_acceptable delay of {MAX_DELAY_MS}ms.:")
    for addr, delay_list in report.items():
        avrg_delay = sum(delay_list) / len(delay_list)

        logger.info(f"    - Device {addr} replied with an average delay of {avrg_delay} sec.")

    logger.info('Testing unicast ListIdentity timing over UDP...')
    for addr, _ in report.items():
        TEST_CYCLES = 5

        for _ in range(TEST_CYCLES):
            sock = UDP(host_ip, addr)
            discovered_devices = list_identity(sock)
            assert len(discovered_devices) == 1

            sender_ip = discovered_devices[0]["address"][0]
            response_delay = discovered_devices[0]["delay"]

            if response_delay > 0.05:
                logger.error(f"Device {sender_ip} replied a unicast list identity request"
                             f" with a {respnse_delay}ms delay.")
    logger.info('Testing unicast ListIdentity timing over TCP...')
    for addr, _ in report.items():
        TEST_CYCLES = 5

        for _ in range(TEST_CYCLES):
            sock = TCP(host_ip, addr)
            sock.connect()
            discovered_devices = list_identity(sock)
            assert len(discovered_devices) == 1

            sender_ip = discovered_devices[0]["address"][0]
            response_delay = discovered_devices[0]["delay"]

            if response_delay > 0.05:
                logger.error(f"Device {sender_ip} replied a unicast list identity request"
                             f" with a {respnse_delay}ms delay.")


if __name__ == "__main__":
    host_ip = "192.168.210.100"
    list_identity_demo(host_ip)