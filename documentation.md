# Overview

REWire is built around two core modules that handle protocol serialization and deserialization.

**`rw_packet`** — Based on [dpkt](https://github.com/kbandla/dpkt) by Dug Song, this module defines the `Packet` base class, which provides the core serialization and deserialization interface. Every EtherNet/IP data structure is implemented as a subclass of `Packet`.

**`cip_types`** — Provides basic and complex CIP data type abstractions. All types implement the same interface as the `Packet` clas and serve as the field types used to compose `Packet` subclasses. As an example see the NOP packet from the eip_encapsulation.py

```python
from .rw_packet import Packet
from .cip_types import *

...
class NOP(Packet):
    _fields = (
        ("command",             UINT(EncapsulationCommands.NOP)),
        ("length",              UINT(0)),
        ("session_handle",      UDINT(0)),
        ("status",              UDINT(0)),
        ("sender_context",      SenderContext(0)),
        ("options",             UDINT(0)),
        )


```

Both modules are described in detail later in this document.



REWire is designed around the structure of the EtherNet/IP™ protocol itself. The following modules realize this layered architecture:

**`eip_encapsulation`** — EtherNet/IP™ encapsulation protocol packets and services.

**`explicit_transport`** — Abstract base class for explicit communication, providing CIP service interfaces for both unconnected and connected messaging.

**`unconnected_client`** — UCMM packets and services for unconnected explicit communication.

**`connected_client`** — CIP Class 3 packets and services for connected explicit communication.

**`io_client`** — CIP Class 0/1 packets and services, including those required to establish I/O connections over DTLS.

**`cip_objects`** — A suite of CIP object abstractions offering attribute-level access and object-specific services.

**`rw_socket`** — Socket wrappers providing a unified interface for TCP, UDP, TLS, and DTLS sockets.

The following diagram demonstrates the API layering of REWire.

![](https://codeberg.org/omidbimo/REWire/src/branch/main/images/LayeringModel.drawio.svg)




