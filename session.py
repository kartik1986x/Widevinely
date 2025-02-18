from typing import Optional

from Crypto.Random import get_random_bytes

from pywidevinely.key import Key
from pywidevinely.utils.protos.license_protocol_pb2 import SignedDrmCertificate


class Session:
    def __init__(self, number: int):
        self.number = number
        self.id = get_random_bytes(16)
        self.service_certificate: Optional[SignedDrmCertificate] = None
        self.context: dict[bytes, tuple[bytes, bytes]] = {}
        self.keys: list[Key] = []
        self.opened_at = None
