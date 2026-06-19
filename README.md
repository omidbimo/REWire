# REWire



REWire is a Python library for EtherNet/IP™ scanner communication, designed for protocol testing, device validation, and custom EtherNet/IP tooling.

Rather than treating EtherNet/IP as a collection of unrelated services, REWire models the protocol stack as a hierarchy of packet-processing layers. Each layer is responsible for constructing, processing, and forwarding packets, providing a consistent programming model throughout the library.

This architecture allows working at different levels of abstraction. Common operations - such as sending a `Get_Attribute_Single` request over UCMM - are available through simple high-level APIs, while advanced use cases retain direct access to encapsulation layer, connection management, and CIP messaging.


The long-term goal is comprehensive coverage of the core EtherNet/IP protocol, while keeping the library modular, extensible, and faithful to the protocol's architecture.


[API Documentation](https://codeberg.org/omidbimo/REWire/src/branch/main/documentation.md)
