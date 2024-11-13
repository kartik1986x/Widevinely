from __future__ import annotations

import base64
import binascii
import re
from typing import Union, Optional

import requests
from Crypto.Hash import SHA1
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from google.protobuf.message import DecodeError
from pywidevinely.cdm import Cdm
from pywidevinely.device import Device
from pywidevinely.exceptions import (
    InvalidInitData,
    InvalidLicenseType,
    InvalidLicenseMessage,
    DeviceMismatch,
    SignatureMismatch,
)
from pywidevinely.key import Key

from pywidevinely.utils.protos.license_protocol_pb2 import (
    LicenseType,
    SignedMessage,
    License,
    ClientIdentification,
    SignedDrmCertificate,
)
from pywidevinely.pssh import PSSH
from pywidevinely.utils import logger

log = logger.getLogger("remotecdm")


class RemoteCdm(Cdm):
    """Remote Accessible CDM using pywidevinely's serve schema."""

    def __init__(
        self,
        device_type: Union[Device.Types, str],
        system_id: int,
        security_level: int,
        host: str,
        secret: str,
        device_name: str,
        test_: bool,
    ):
        """Initialize a Widevine Content Decryption Module (CDM)."""
        if not device_type:
            log.exit("Device Type must be provided")
        if isinstance(device_type, str):
            device_type = Device.Types[device_type]
        if not isinstance(device_type, Device.Types):
            log.exit(
                f"Expected device_type to be a {Device.Types!r} not {device_type!r}"
            )

        if not system_id:
            log.exit("System ID must be provided")
        if not isinstance(system_id, int):
            log.exit(f"Expected system_id to be a {int} not {system_id!r}")

        if not security_level:
            log.exit("Security Level must be provided")
        if not isinstance(security_level, int):
            log.exit(f"Expected security_level to be a {int} not {security_level!r}")

        if not host:
            log.exit("API Host must be provided")
        if not isinstance(host, str):
            log.exit(f"Expected host to be a {str} not {host!r}")

        if secret and not isinstance(secret, str):
            log.exit(f"Expected secret to be a {str} not {secret!r}")

        if not device_name:
            log.exit("API Device name must be provided")
        if not isinstance(device_name, str):
            log.exit(f"Expected device_name to be a {str} not {device_name!r}")

        self.device_type = device_type
        self.system_id = system_id
        self.security_level = security_level
        self.host = host
        self.device_name = device_name

        # spoof client_id and rsa_key just so we can construct via super call
        super().__init__(
            device_type,
            system_id,
            security_level,
            ClientIdentification(),
            RSA.generate(2048),
            test_,
        )

        self.__session = requests.Session()
        self.__session.headers.update({"X-Secret-Key": secret})

        try:
            r = requests.head(self.host)
        except requests.exceptions.ConnectionError:
            log.exit(f"Could not establish connection with {self.host!r}")

        if r.status_code != 200:
            log.exit(f"Could not test Remote API version [{r.status_code}]")
        server = r.headers.get("Server")
        if not server or "pywidevinely serve" not in server.lower():
            log.exit(
                f"This Remote CDM API does not seem to be a pywidevinely serve API ({server})."
            )
        server_version = re.search(
            r"pywidevinely serve v([\d.]+)", server, re.IGNORECASE
        )
        if not server_version:
            log.exit(
                "The pywidevinely server API is not stating the version correctly, cannot continue."
            )
        server_version = server_version.group(1)
        if server_version < "1.5.6":
            log.exit(
                f"This pywidevinely serve API version ({server_version}) is not supported."
            )

    @classmethod
    def from_device(cls, device: Device) -> RemoteCdm:
        NotImplementedError
        log.exit("You cannot load a RemoteCdm from a local Device file.")

    def open(self, CdmTest: Optional[bool] = False) -> bytes:
        r = self.__session.get(
            url=f"{self.host}/{self.device_name}/open", params={"CdmTest": CdmTest}
        ).json()
        if r["status"] != 200:
            ValueError
            log.exit(f"Cannot Open CDM Session: {r['message']} [{r['status']}]")
        r = r["data"]

        if int(r["device"]["system_id"]) != self.system_id:
            DeviceMismatch
            log.exit(
                "The System ID specified does not match the one specified in the API response."
            )

        if int(r["device"]["security_level"]) != self.security_level:
            DeviceMismatch
            log.exit(
                "The Security Level specified does not match the one specified in the API response."
            )

        return bytes.fromhex(r["session_id"])

    def close(self, session_id: bytes) -> None:
        r = self.__session.get(
            url=f"{self.host}/{self.device_name}/close/{session_id.hex()}"
        ).json()
        if r["status"] != 200:
            ValueError
            log.exit(f"Cannot Close CDM Session, {r['message']} [{r['status']}]")

    def set_service_certificate(
        self, session_id: bytes, certificate: Optional[Union[bytes, str]]
    ) -> str:
        if certificate is None:
            certificate_b64 = None
        elif isinstance(certificate, str):
            certificate_b64 = certificate  # assuming base64
        elif isinstance(certificate, bytes):
            certificate_b64 = base64.b64encode(certificate).decode()
        else:
            log.exit(
                f"Expecting Certificate to be base64 or bytes, not {certificate!r}"
            )

        r = self.__session.post(
            url=f"{self.host}/{self.device_name}/set_service_certificate",
            json={"session_id": session_id.hex(), "certificate": certificate_b64},
        ).json()
        if r["status"] != 200:
            ValueError
            log.exit(
                f"Cannot Set CDMs Service Certificate, {r['message']} [{r['status']}]"
            )
        r = r["data"]

        return r["provider_id"]

    def get_service_certificate(
        self, session_id: bytes
    ) -> Optional[SignedDrmCertificate]:
        r = self.__session.post(
            url=f"{self.host}/{self.device_name}/get_service_certificate",
            json={"session_id": session_id.hex()},
        ).json()
        if r["status"] != 200:
            ValueError
            log.exit(
                f"Cannot Get CDMs Service Certificate, {r['message']} [{r['status']}]"
            )
        r = r["data"]

        service_certificate = r["service_certificate"]
        if not service_certificate:
            return None

        service_certificate = base64.b64decode(service_certificate)
        signed_drm_certificate = SignedDrmCertificate()

        try:
            signed_drm_certificate.ParseFromString(service_certificate)
            if signed_drm_certificate.SerializeToString() != service_certificate:
                raise DecodeError("partial parse")
        except DecodeError as e:
            # could be a direct unsigned DrmCertificate, but reject those anyway
            log.exit(f"Could not parse certificate as a SignedDrmCertificate, {e}")

        try:
            pss.new(RSA.import_key(self.root_cert.public_key)).verify(
                msg_hash=SHA1.new(signed_drm_certificate.drm_certificate),
                signature=signed_drm_certificate.signature,
            )
        except (ValueError, TypeError):
            SignatureMismatch
            log.exit(
                "Signature Mismatch on SignedDrmCertificate, rejecting certificate"
            )
        return signed_drm_certificate

    def get_license_challenge(
        self,
        session_id: bytes,
        pssh: PSSH,
        type_: Union[int, str] = LicenseType.STREAMING,
        privacy_mode: bool = True,
    ) -> bytes:
        if not pssh:
            InvalidInitData
            log.exit("A pssh must be provided.")
        if not isinstance(pssh, PSSH):
            InvalidInitData
            log.exit(f"Expected pssh to be a {PSSH}, not {pssh!r}")

        try:
            if isinstance(type_, int):
                type_ = LicenseType.Name(int(type_))
            elif isinstance(type_, str):
                type_ = LicenseType.Name(LicenseType.Value(type_))
            elif isinstance(type_, LicenseType):
                type_ = LicenseType.Name(type_)
            else:
                raise InvalidLicenseType()
        except ValueError:
            InvalidLicenseType
            log.exit(f"License Type {type_!r} is invalid")

        r = self.__session.post(
            url=f"{self.host}/{self.device_name}/get_license_challenge/{type_}",
            json={
                "session_id": session_id.hex(),
                "init_data": pssh.dumps(),
                "privacy_mode": privacy_mode,
            },
        ).json()
        if r["status"] != 200:
            ValueError
            log.exit(f"Cannot get Challenge, {r['message']} [{r['status']}]")
        r = r["data"]

        try:
            challenge = base64.b64decode(r["challenge_b64"])
            license_message = SignedMessage()
            license_message.ParseFromString(challenge)
            if license_message.SerializeToString() != challenge:
                raise DecodeError("partial parse")
        except DecodeError as e:
            InvalidLicenseMessage
            log.exit(f"Failed to parse license request, {e}")

        return license_message.SerializeToString()

    def parse_license(
        self, session_id: bytes, license_message: Union[SignedMessage, bytes, str]
    ) -> None:
        if not license_message:
            InvalidLicenseMessage
            log.exit("Cannot parse an empty license_message")

        if isinstance(license_message, str):
            try:
                license_message = base64.b64decode(license_message)
            except (binascii.Error, binascii.Incomplete) as e:
                InvalidLicenseMessage
                log.exit(f"Could not decode license_message as Base64, {e}")

        if isinstance(license_message, bytes):
            signed_message = SignedMessage()
            try:
                signed_message.ParseFromString(license_message)
                if signed_message.SerializeToString() != license_message:
                    raise DecodeError("partial parse")
            except DecodeError as e:
                InvalidLicenseMessage
                log.exit(f"Could not parse license_message as a SignedMessage, {e}")
            license_message = signed_message

        if not isinstance(license_message, SignedMessage):
            InvalidLicenseMessage
            log.exit(
                f"Expecting license_response to be a SignedMessage, got {license_message!r}"
            )

        if license_message.type != SignedMessage.MessageType.LICENSE:
            InvalidLicenseMessage
            log.exit(
                f"Expecting a LICENSE message, not a "
                f"'{SignedMessage.MessageType.Name(license_message.type)}' message."
            )

        r = self.__session.post(
            url=f"{self.host}/{self.device_name}/parse_license",
            json={
                "session_id": session_id.hex(),
                "license_message": base64.b64encode(
                    license_message.SerializeToString()
                ).decode(),
            },
        ).json()
        if r["status"] != 200:
            ValueError
            log.exit(f"Cannot parse License, {r['message']} [{r['status']}]")

    def get_keys(
        self, session_id: bytes, type_: Optional[Union[int, str]] = None
    ) -> list[Key]:
        try:
            if isinstance(type_, str):
                License.KeyContainer.KeyType.Value(type_)  # only test
            elif isinstance(type_, int):
                type_ = License.KeyContainer.KeyType.Name(type_)
            elif type_ is None:
                type_ = "ALL"
            else:
                TypeError
                log.exit(
                    f"Expected type_ to be a {License.KeyContainer.KeyType} or int, not {type_!r}"
                )
        except ValueError as e:
            ValueError
            log.exit(f"Could not parse type_ as a {License.KeyContainer.KeyType}, {e}")

        r = self.__session.post(
            url=f"{self.host}/{self.device_name}/get_keys/{type_}",
            json={"session_id": session_id.hex()},
        ).json()
        if r["status"] != 200:
            ValueError
            log.exit(f"Could not get {type_} Keys, {r['message']} [{r['status']}]")
        r = r["data"]

        return [
            Key(
                type_=key["type"],
                kid=Key.kid_to_uuid(bytes.fromhex(key["key_id"])),
                key=bytes.fromhex(key["key"]),
                permissions=key["permissions"],
            )
            for key in r["keys"]
        ]


__ALL__ = (RemoteCdm,)
