from cryptography                                   import x509
from cryptography.utils                             import int_to_bytes
from cryptography.x509.oid                          import NameOID, ExtensionOID
from cryptography.hazmat.backends                   import default_backend
from cryptography.hazmat.primitives                 import serialization
from cryptography.hazmat.primitives                 import hashes
from cryptography.hazmat.primitives.asymmetric      import rsa
from cryptography.hazmat.primitives.asymmetric      import ec
from cryptography.hazmat.primitives.serialization   import load_pem_private_key
from cryptography.hazmat.primitives.serialization   import pkcs12

__all__ = [
    "hex_dump",
    "print_cert",
    "print_csr",
]

def hex_dump(data):
    msg = ""
    for block in range(0, len(data), 16):
        offset = block
        msg += "{:04X}  ".format(offset) + " ".join("{:02X}".format(octet) for octet in data[block:block+16]).ljust(48, " ")
        msg += " " + "".join("{}".format(chr(octet))
                                if octet <= 126 and octet >= 33
                                else "."
                                for octet in data[block:block+16] ) + "\n"
    return msg

def print_cert(crt):
    print("Retrieved Server Certificate:")
    print("\n".join("    {}".format(line) for line in crt.public_bytes(serialization.Encoding.PEM).splitlines()))
    print("")
    try:
        isCA = crt.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value.ca
    except:
        isCA = False

    print("    - {}".format(crt.version))
    print("    - Serial Number: {}".format(":".join("{:02X}".format(byte) for byte in int_to_bytes(crt.serial_number))))
    print("    - {}".format(crt.signature_algorithm_oid._name))
    print("    - Valid from: ({}) to: ({})".format(crt.not_valid_before, crt.not_valid_after))
    print("    - Issuer:\n{}".format( "\n".join("        - {} = {}".format(attr.oid._name, attr.value) for attr in crt.issuer)))
    print("    - Subject:\n{}".format( "\n".join("        - {} = {}".format(attr.oid._name, attr.value) for attr in crt.subject)))
    print("    - CA cert: {}".format(isCA))
    print("    - signature:")
    print("        - Algorithm: {}".format(crt.signature_algorithm_oid._name))
    print("        - Len:       {}".format(len(crt.signature)))
    print("\n".join("        {}".format(":".join("{:02X}".format(byte) for byte in crt.signature[offset:offset + 18])) for offset in range(0, len(crt.signature), 18)))

def print_csr(CSR):
    print("\n".join("    {}".format(line) for line in CSR.public_bytes(serialization.Encoding.PEM).splitlines()))
    print("")
    try:
        isCA = CSR.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value.ca
    except:
        isCA = False
    msg = ""
    msg += "    - {}\n".format(CSR.signature_algorithm_oid._name)
    msg += "    - Subject:\n{}\n".format( "\n".join("        - {} = {}".format(attr.oid._name, attr.value) for attr in CSR.subject))
    san_data = CSR.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    if san_data:
        msg += "    - Subject Alternative Names:\n"
    msg += "        - iPAddress: {}\n".format( " ".join("{}".format(name) for name in san_data.value.get_values_for_type(x509.IPAddress)))
    msg += "        - DNSName: {}\n".format( " ".join("{}".format(name) for name in san_data.value.get_values_for_type(x509.DNSName)))
    msg += "        - UniformResourceIdentifier: {}\n".format( " ".join("{}".format(name) for name in san_data.value.get_values_for_type(x509.UniformResourceIdentifier)))
    msg += "        - RFC822Name: {}\n".format( " ".join("{}".format(name) for name in san_data.value.get_values_for_type(x509.RFC822Name)))
    msg += "        - DirectoryName: {}\n".format( " ".join("{}".format(name) for name in san_data.value.get_values_for_type(x509.DirectoryName)))
    msg += "        - RegisteredID: {}\n".format( " ".join("{}".format(name) for name in san_data.value.get_values_for_type(x509.RegisteredID)))
    msg += "        - OtherName: {}\n".format( " ".join("{}".format(name) for name in san_data.value.get_values_for_type(x509.OtherName)))
    msg += "    - CA cert: {}\n".format(isCA)
    msg += "    - signature\n"
    msg += "        - Algorithm: {}\n".format(CSR.signature_algorithm_oid._name)
    msg += "        - Len:       {}\n".format(len(CSR.signature))
    msg += "\n".join("        {}".format(":".join("{:02X}".format(byte) for byte in CSR.signature[offset:offset + 18])) for offset in range(0, len(CSR.signature), 18))
    print(msg)

