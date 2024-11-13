from __future__ import annotations

import base64
import binascii
import os
import random
import subprocess
import sys
import re
import json
import time
from datetime import datetime

from appdirs import AppDirs
from construct import ConstError, ConstructError
from pathlib import Path
from typing import Union, Optional
from uuid import UUID

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA1, HMAC, SHA256, CMAC
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pss
from Crypto.Util import Padding
from google.protobuf.message import DecodeError
import requests

from pywidevinely.device import Device
from pywidevinely.exceptions import (
    InvalidSession,
    InvalidLicenseType,
    SignatureMismatch,
    InvalidInitData,
    InvalidLicenseMessage,
    NoKeysLoaded,
    InvalidContext,
)
from pywidevinely.key import Key
from pywidevinely.utils.protos.license_protocol_pb2 import (
    DrmCertificate,
    SignedMessage,
    SignedDrmCertificate,
    LicenseType,
    LicenseRequest,
    ProtocolVersion,
    ClientIdentification,
    EncryptedClientIdentification,
    License,
)
from pywidevinely.pssh import PSSH
from pywidevinely.session import Session
from pywidevinely.utils import logger, get_binary_path, clean_line

log = logger.getLogger("cdm")


class Cdm:
    system_id = b"\xed\xef\x8b\xa9\x79\xd6\x4a\xce\xa3\xc8\x27\xdc\xd5\x1d\x21\xed"
    uuid = UUID(bytes=system_id)
    urn = f"urn:uuid:{uuid}"
    key_format = urn
    service_certificate_challenge = b"\x08\x04"
    common_privacy_cert = (
        "CAUSxwUKwQIIAxIQFwW5F8wSBIaLBjM6L3cqjBiCtIKSBSKOAjCCAQoCggEBAJntWzsyfateJO/DtiqVtZhSCtW8y"
        "zdQPgZFuBTYdrjfQFEEQa2M462xG7iMTnJaXkqeB5UpHVhYQCOn4a8OOKkSeTkwCGELbxWMh4x+Ib/7/up34QGeHl"
        "eB6KRfRiY9FOYOgFioYHrc4E+shFexN6jWfM3rM3BdmDoh+07svUoQykdJDKR+ql1DghjduvHK3jOS8T1v+2RC/TH"
        "hv0CwxgTRxLpMlSCkv5fuvWCSmvzu9Vu69WTi0Ods18Vcc6CCuZYSC4NZ7c4kcHCCaA1vZ8bYLErF8xNEkKdO7Dev"
        "Sy8BDFnoKEPiWC8La59dsPxebt9k+9MItHEbzxJQAZyfWgkCAwEAAToUbGljZW5zZS53aWRldmluZS5jb20SgAOuN"
        "HMUtag1KX8nE4j7e7jLUnfSSYI83dHaMLkzOVEes8y96gS5RLknwSE0bv296snUE5F+bsF2oQQ4RgpQO8GVK5uk5M"
        "4PxL/CCpgIqq9L/NGcHc/N9XTMrCjRtBBBbPneiAQwHL2zNMr80NQJeEI6ZC5UYT3wr8+WykqSSdhV5Cs6cD7xdn9"
        "qm9Nta/gr52u/DLpP3lnSq8x2/rZCR7hcQx+8pSJmthn8NpeVQ/ypy727+voOGlXnVaPHvOZV+WRvWCq5z3CqCLl5"
        "+Gf2Ogsrf9s2LFvE7NVV2FvKqcWTw4PIV9Sdqrd+QLeFHd/SSZiAjjWyWOddeOrAyhb3BHMEwg2T7eTo/xxvF+YkP"
        "j89qPwXCYcOxF+6gjomPwzvofcJOxkJkoMmMzcFBDopvab5tDQsyN9UPLGhGC98X/8z8QSQ+spbJTYLdgFenFoGq4"
        "7gLwDS6NWYYQSqzE3Udf2W7pzk4ybyG4PHBYV3s4cyzdq8amvtE/sNSdOKReuHpfQ="
    )
    root_signed_cert = SignedDrmCertificate()
    root_signed_cert.ParseFromString(
        base64.b64decode(
            "CpwDCAASAQAY3ZSIiwUijgMwggGKAoIBgQC0/jnDZZAD2zwRlwnoaM3yw16b8udNI7EQ24dl39z7nzWgVwNTTPZtNX2meNuzNtI/nECplSZy"
            "f7i+Zt/FIZh4FRZoXS9GDkPLioQ5q/uwNYAivjQji6tTW3LsS7VIaVM+R1/9Cf2ndhOPD5LWTN+udqm62SIQqZ1xRdbX4RklhZxTmpfrhNfM"
            "qIiCIHAmIP1+QFAn4iWTb7w+cqD6wb0ptE2CXMG0y5xyfrDpihc+GWP8/YJIK7eyM7l97Eu6iR8nuJuISISqGJIOZfXIbBH/azbkdDTKjDOx"
            "+biOtOYS4AKYeVJeRTP/Edzrw1O6fGAaET0A+9K3qjD6T15Id1sX3HXvb9IZbdy+f7B4j9yCYEy/5CkGXmmMOROtFCXtGbLynwGCDVZEiMg1"
            "7B8RsyTgWQ035Ec86kt/lzEcgXyUikx9aBWE/6UI/Rjn5yvkRycSEbgj7FiTPKwS0ohtQT3F/hzcufjUUT4H5QNvpxLoEve1zqaWVT94tGSC"
            "UNIzX5ECAwEAARKAA1jx1k0ECXvf1+9dOwI5F/oUNnVKOGeFVxKnFO41FtU9v0KG9mkAds2T9Hyy355EzUzUrgkYU0Qy7OBhG+XaE9NVxd0a"
            "y5AeflvG6Q8in76FAv6QMcxrA4S9IsRV+vXyCM1lQVjofSnaBFiC9TdpvPNaV4QXezKHcLKwdpyywxXRESYqI3WZPrl3IjINvBoZwdVlkHZV"
            "dA8OaU1fTY8Zr9/WFjGUqJJfT7x6Mfiujq0zt+kw0IwKimyDNfiKgbL+HIisKmbF/73mF9BiC9yKRfewPlrIHkokL2yl4xyIFIPVxe9enz2F"
            "RXPia1BSV0z7kmxmdYrWDRuu8+yvUSIDXQouY5OcCwEgqKmELhfKrnPsIht5rvagcizfB0fbiIYwFHghESKIrNdUdPnzJsKlVshWTwApHQh7"
            "evuVicPumFSePGuUBRMS9nG5qxPDDJtGCHs9Mmpoyh6ckGLF7RC5HxclzpC5bc3ERvWjYhN0AqdipPpV2d7PouaAdFUGSdUCDA=="
        )
    )
    root_cert = DrmCertificate()
    root_cert.ParseFromString(root_signed_cert.drm_certificate)

    MAX_NUM_OF_SESSIONS = 16

    def __init__(
        self,
        device_type: Union[Device.Types, str],
        system_id: int,
        security_level: int,
        client_id: ClientIdentification,
        rsa_key: RSA.RsaKey,
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
            ValueError
            log.exit("System ID must be provided")
        if not isinstance(system_id, int):
            TypeError
            log.exit(f"Expected system_id to be a {int} not {system_id!r}")

        if not security_level:
            ValueError
            log.exit("Security Level must be provided")
        if not isinstance(security_level, int):
            TypeError
            log.exit(f"Expected security_level to be a {int} not {security_level!r}")

        if not client_id:
            ValueError
            log.exit("Client ID must be provided")
        if not isinstance(client_id, ClientIdentification):
            TypeError
            log.exit(
                f"Expected client_id to be a {ClientIdentification} not {client_id!r}"
            )

        if not rsa_key:
            ValueError
            log.exit("RSA Key must be provided")
        if not isinstance(rsa_key, RSA.RsaKey):
            TypeError
            log.exit(f"Expected RSA Key to be a {RSA.RsaKey} not {rsa_key!r}")

        self.device_type = device_type
        self.system_id = system_id
        self.security_level = security_level
        self.__client_id = client_id

        self.test_ = test_

        self.__signer = pss.new(rsa_key)
        self.__decrypter = PKCS1_OAEP.new(rsa_key)

        self.__sessions: dict[bytes, Session] = {}

    def device(
        config,
        directories,
        service,
        serviceProfile=None,
        cdm=None,
        localDevice=None,
        deviceName=None,
    ):
        """
        Prepare either a Remote- or Local CDM device for a specified service.
        Will exit with an error if there's a problem getting one.
        """
        # See if there's a CDM specified for the service or its profile
        if not deviceName:
            deviceName = config.cdm.get(service) or config.cdm.get("default")
        if not deviceName:
            log.exit(
                f"No CDM device specified for '{service}' and could not find a default one"
            )

        if deviceName == "StreamFabCdm":
            localDevice = Device.load(
                os.path.join(
                    os.path.dirname(os.path.realpath(__file__)) + "/utils",
                    "StreamFabCdm.wvd",
                )
            )
        else:
            if isinstance(deviceName, dict):
                if not serviceProfile:
                    log.exit(
                        "CDM config is mapped for profiles, but no profile was chosen"
                    )
                deviceName = deviceName.get(serviceProfile)
                if not deviceName:
                    log.exit(f"There is no CDM mapped for profile {serviceProfile}")

            # CDM specified, let's see if we can find the CDM as WVD device
            try:
                localDevice = Device.load(
                    os.path.join(directories.devices, f"{deviceName}.wvd")
                )
            except ConstError:
                log.warning_("CDM WVD device migrated to version 2\n")
                try:
                    migrated_device = Device.migrate(
                        open(directories.devices / f"{deviceName}.wvd", "rb+").read()
                    )
                except (ConstructError, ValueError) as e:
                    log.exit(f" - {e}")

                migrated_device.dump(directories.devices / f"{deviceName}.wvd")
                localDevice = Device.load(
                    os.path.join(directories.devices, f"{deviceName}.wvd")
                )
            except FileNotFoundError:
                # No WVD device found, try to find the CDM folder itself
                dirs = [
                    os.path.join(directories.devices, deviceName),
                    os.path.join(
                        AppDirs("widevinely", False).user_data_dir,
                        "devices",
                        deviceName,
                    ),
                    os.path.join(
                        AppDirs("widevinely", False).site_data_dir,
                        "devices",
                        deviceName,
                    ),
                ]

                for dir_ in dirs:
                    try:
                        localDeviceConfig = json.load(open(f"{dir_}/wv.json", "r+"))
                        localDevice = Device(
                            type_=(
                                Device.Types.ANDROID
                                if localDeviceConfig["session_id_type"].lower()
                                == "android"
                                else Device.Types.CHROME
                            ),
                            security_level=int(localDeviceConfig["security_level"]),
                            flags={},
                            private_key=open(
                                f"{dir_}/device_private_key", "rb+"
                            ).read(),
                            client_id=open(
                                f"{dir_}/device_client_id_blob", "rb+"
                            ).read(),
                        )
                    except FileNotFoundError:
                        pass

        if localDevice:
            cdm = Cdm(
                device_type=localDevice.type,
                system_id=localDevice.system_id,
                security_level=localDevice.security_level,
                client_id=localDevice.client_id,
                rsa_key=localDevice.private_key,
                test_=False,
            )
            cdm.client_id = localDevice.client_id

        # No CDM folder found, try to find a specified API for the CDM
        cdm_api = next(iter(x for x in config.cdm_api if x["name"] == deviceName), None)
        if cdm_api:
            # Will cause CircularImportError if we place it on top
            from pywidevinely.remotecdm import RemoteCdm

            cdm = RemoteCdm(
                device_type=(
                    Device.Types.ANDROID
                    if cdm_api["device_type"] == "ANDROID"
                    else Device.Types.CHROME
                ),
                device_name=cdm_api["device_name"],
                system_id=cdm_api["system_id"],
                security_level=cdm_api["security_level"],
                host=cdm_api["host"],
                secret=cdm_api["secret"],
                test_=False,
            )

        if cdm:
            cdm.api = bool(not localDevice)
            return cdm

        # Could not find the CDM specified
        log.exit(f"Device {deviceName!r} could not be found")
        exit()

    @classmethod
    def from_device(cls, device: Device, test_: Optional[bool] = False) -> Cdm:
        """Initialize a Widevine CDM from a Widevine Device (.wvd) file."""
        return cls(
            device_type=device.type,
            system_id=device.system_id,
            security_level=device.security_level,
            client_id=device.client_id,
            rsa_key=device.private_key,
            test_=test_,
        )

    def open(self, CdmTest: Optional[bool] = False) -> bytes:
        """
        Open a Widevine Content Decryption Module (CDM) session.
        """
        session = Session(len(self.__sessions) + 1)
        session.opened_at = datetime.utcnow()
        self.__sessions[session.id] = session
        self.test_ = CdmTest

        return session.id

    def close(self, session_id: bytes) -> None:
        """
        Close a Widevine Content Decryption Module (CDM) session.

        Parameters:
            session_id: Session identifier.

        Raises:
            InvalidSession: If the Session identifier is invalid.
        """
        session = self.__sessions.get(session_id)
        if not session:
            InvalidSession
            log.error_(f"Session identifier {session_id!r} is invalid.", debug=True)
        del self.__sessions[session_id]

    def set_service_certificate(
        self, session_id: bytes, certificate: Optional[Union[bytes, str]]
    ) -> str:
        """
        Set a Service Privacy Certificate for Privacy Mode. (optional but recommended)

        The Service Certificate is used to encrypt Client IDs in Licenses. This is also
        known as Privacy Mode and may be required for some services or for some devices.
        Chrome CDM requires it as of the enforcement of VMP (Verified Media Path).

        We reject direct DrmCertificates as they do not have signature verification and
        cannot be verified. You must provide a SignedDrmCertificate or a SignedMessage
        containing a SignedDrmCertificate.

        Parameters:
            session_id: Session identifier.
            certificate: SignedDrmCertificate (or SignedMessage containing one) in Base64
                or Bytes form obtained from the Service. Some services have their own,
                but most use the common privacy cert, (common_privacy_cert). If None, it
                will remove the current certificate.

        Raises:
            InvalidSession: If the Session identifier is invalid.
            DecodeError: If the certificate could not be parsed as a SignedDrmCertificate
                nor a SignedMessage containing a SignedDrmCertificate.
            SignatureMismatch: If the Signature of the SignedDrmCertificate does not
                match the underlying DrmCertificate.

        Returns the Service Provider ID of the verified DrmCertificate if successful.
        If certificate is None, it will return the now unset certificate's Provider ID.
        """
        session = self.__sessions.get(session_id)
        if not session:
            InvalidSession
            log.error_(f"Session identifier {session_id!r} is invalid.", debug=True)

        if certificate is None:
            if session.service_certificate:
                drm_certificate = DrmCertificate()
                drm_certificate.ParseFromString(
                    session.service_certificate.drm_certificate
                )
                provider_id = drm_certificate.provider_id
            else:
                provider_id = None
            session.service_certificate = None
            return provider_id

        if isinstance(certificate, str):
            try:
                certificate = base64.b64decode(certificate)  # assuming base64
            except binascii.Error:
                DecodeError
                log.exit(
                    "Could not decode certificate string as Base64, expected bytes."
                )
        elif not isinstance(certificate, bytes):
            DecodeError
            log.exit(f"Expecting Certificate to be bytes, not {certificate!r}")

        signed_message = SignedMessage()
        signed_drm_certificate = SignedDrmCertificate()
        drm_certificate = DrmCertificate()

        try:
            signed_message.ParseFromString(certificate)
            if signed_message.SerializeToString() == certificate:
                signed_drm_certificate.ParseFromString(signed_message.msg)
            else:
                signed_drm_certificate.ParseFromString(certificate)
                if signed_drm_certificate.SerializeToString() != certificate:
                    raise DecodeError("partial parse")
        except DecodeError as e:
            # could be a direct unsigned DrmCertificate, but reject those anyway
            DecodeError
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

        try:
            drm_certificate.ParseFromString(signed_drm_certificate.drm_certificate)
            if (
                drm_certificate.SerializeToString()
                != signed_drm_certificate.drm_certificate
            ):
                raise DecodeError("partial parse")
        except DecodeError as e:
            DecodeError
            log.exit(
                f"Could not parse signed certificate's message as a DrmCertificate, {e}"
            )

        # must be stored as a SignedDrmCertificate as the signature needs to be kept for RemoteCdm
        # if we store as DrmCertificate (no signature) then RemoteCdm cannot verify the Certificate
        session.service_certificate = signed_drm_certificate
        return drm_certificate.provider_id

    def get_service_certificate(
        self, session_id: bytes
    ) -> Optional[SignedDrmCertificate]:
        """
        Get the currently set Service Privacy Certificate of the Session.
        Parameters:
            session_id: Session identifier.
        Raises:
            InvalidSession: If the Session identifier is invalid.
        Returns the Service Certificate if one is set, otherwise None.
        """
        session = self.__sessions.get(session_id)
        if not session:
            InvalidSession
            log.error_(f"Session identifier {session_id!r} is invalid.", debug=True)

        return session.service_certificate

    def get_license_challenge(
        self,
        session_id: bytes,
        pssh: PSSH,
        type_: Union[int, str] = LicenseType.STREAMING,
        privacy_mode: bool = True,
    ) -> bytes:
        """
        Get a License Request (Challenge) to send to a License Server.

        Parameters:
            session_id: Session identifier.
            pssh: PSSH Object to get the init data from.
            type_: Type of License you wish to exchange, often `STREAMING`. The `OFFLINE`
                Licenses are for Offline licensing of Downloaded content.
            privacy_mode: Encrypt the Client ID using the Privacy Certificate. If the
                privacy certificate is not set yet, this does nothing.

        Raises:
            InvalidSession: If the Session identifier is invalid.
            InvalidInitData: If the Init Data (or PSSH box) provided is invalid.
            InvalidLicenseType: If the type_ parameter value is not a License Type. It
                must be a LicenseType enum, or a string/int representing the enum's keys
                or values.

        Returns a SignedMessage containing a LicenseRequest message. It's signed with
        the Private Key of the device provision.
        """
        session = self.__sessions.get(session_id)
        if not session:
            InvalidSession
            log.error_(f"Session identifier {session_id!r} is invalid.", debug=True)

        if not pssh:
            InvalidInitData
            log.exit("A pssh must be provided.")
        if not isinstance(pssh, PSSH):
            InvalidInitData
            log.info_(f"Expected PSSH to be a {PSSH}, not {pssh!r}")

        try:
            if isinstance(type_, int):
                LicenseType.Name(int(type_))
            elif isinstance(type_, str):
                type_ = LicenseType.Value(type_)
            elif not isinstance(type_, LicenseType):
                raise InvalidLicenseType()
        except ValueError:
            InvalidLicenseType
            log.exit(f"License Type {type_!r} is invalid")

        if self.device_type == Device.Types.ANDROID:
            # OEMCrypto's request_id seems to be in AES CTR Counter block form with no suffix
            # Bytes 5-8 does not seem random, in real tests they have been consecutive \x00 or \xFF
            # Real example: A0DCE548000000000500000000000000
            request_id = get_random_bytes(4) + (b"\x00" * 4)  # (?)
            request_id += session.number.to_bytes(8, "little")  # counter
            # as you can see in the real example, it is stored as uppercase hex and re-encoded
            # it's really 16 bytes of data, but it's stored as a 32-char HEX string (32 bytes)
            request_id = request_id.hex().upper().encode()
        else:
            request_id = get_random_bytes(16)

        license_request = LicenseRequest()
        license_request.type = LicenseRequest.RequestType.Value("NEW")
        license_request.request_time = int(time.time())
        license_request.protocol_version = ProtocolVersion.Value("VERSION_2_1")
        license_request.key_control_nonce = random.randrange(1, 2**31)

        # pssh_data may be either a WidevineCencHeader or custom data
        # we have to assume the pssh.init_data value is valid, we cannot test
        license_request.content_id.widevine_pssh_data.pssh_data.append(pssh.init_data)
        license_request.content_id.widevine_pssh_data.license_type = type_
        license_request.content_id.widevine_pssh_data.request_id = request_id

        if session.service_certificate and privacy_mode:
            # encrypt the client id for privacy mode
            license_request.encrypted_client_id.CopyFrom(
                self.encrypt_client_id(
                    client_id=self.__client_id,
                    service_certificate=session.service_certificate,
                )
            )
        else:
            license_request.client_id.CopyFrom(self.__client_id)

        license_message = SignedMessage()
        license_message.type = SignedMessage.MessageType.LICENSE_REQUEST
        license_message.msg = license_request.SerializeToString()
        license_message.signature = self.__signer.sign(SHA1.new(license_message.msg))

        session.context[request_id] = self.derive_context(license_message.msg)

        return license_message.SerializeToString()

    def parse_license(
        self, session_id: bytes, license_message: Union[SignedMessage, bytes, str]
    ) -> None:
        """
        Load Keys from a License Message from a License Server Response.

        License Messages can only be loaded a single time. An InvalidContext error will
        be raised if you attempt to parse a License Message more than once.

        Parameters:
            session_id: Session identifier.
            license_message: A SignedMessage containing a License message.

        Raises:
            InvalidSession: If the Session identifier is invalid.
            InvalidLicenseMessage: The License message could not be decoded as a Signed
                Message or License message.
            InvalidContext: If the Session has no Context Data. This is likely to happen
                if the License Challenge was not made by this CDM instance, or was not
                by this CDM at all. It could also happen if the Session is closed after
                calling parse_license but not before it got the context data.
            SignatureMismatch: If the Signature of the License SignedMessage does not
                match the underlying License.
        """
        session = self.__sessions.get(session_id)
        if not session:
            InvalidSession
            log.error_(f"Session identifier {session_id!r} is invalid.", debug=True)

        if not license_message:
            InvalidLicenseMessage
            log.exit("Cannot parse an empty license_message")

        if isinstance(license_message, str):
            try:
                license_message = base64.b64decode(license_message)
            except (binascii.Error, binascii.Incomplete) as e:
                InvalidLicenseMessage
                if license_message == "chromecdm_fallback":
                    return license_message
                log.exit(f"Could not decode license_message as Base64, {e}")

        if isinstance(license_message, bytes):
            signed_message = SignedMessage()
            try:
                signed_message.ParseFromString(license_message)
                if signed_message.SerializeToString() != license_message:
                    DecodeError
                    log.exit(license_message)
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

        licence = License()
        licence.ParseFromString(license_message.msg)

        context = session.context.get(licence.id.request_id)
        if not context:
            InvalidContext
            log.exit(
                "Cannot parse a license message without first making a license request"
            )

        enc_key, mac_key_server, _ = self.derive_keys(
            *context, key=self.__decrypter.decrypt(license_message.session_key)
        )

        # 1. Explicitly use the original `license_message.msg` instead of a re-serializing from `licence`
        #    as some differences may end up in the output due to differences in the proto schema
        # 2. The oemcrypto_core_message (unknown purpose) is part of the signature algorithm starting with
        #    OEM Crypto API v16 and if available, must be prefixed when HMAC'ing a signature.

        computed_signature = (
            HMAC.new(mac_key_server, digestmod=SHA256)
            .update(license_message.oemcrypto_core_message or b"")
            .update(license_message.msg)
            .digest()
        )

        if license_message.signature != computed_signature and self.system_id != 21889:
            SignatureMismatch
            log.exit("Signature Mismatch on License Message, rejecting license")

        session.keys = [Key.from_key_container(key, enc_key) for key in licence.key]

        del session.context[licence.id.request_id]

    def get_keys(
        self, session_id: bytes, type_: Optional[Union[int, str]] = None
    ) -> list[Key]:
        """
        Get Keys from the loaded License message.
        Parameters:
            session_id: Session identifier.
            type_: (optional) Key Type to filter by and return.
        Raises:
            InvalidSession: If the Session identifier is invalid.
            TypeError: If the provided type_ is an unexpected value type.
            ValueError: If the provided type_ is not a valid Key Type.
        """
        session = self.__sessions.get(session_id)
        if not session:
            InvalidSession
            log.error_(f"Session identifier {session_id!r} is invalid.", debug=True)

        try:
            if isinstance(type_, str):
                type_ = License.KeyContainer.KeyType.Value(type_)
            elif isinstance(type_, int):
                License.KeyContainer.KeyType.Name(type_)  # only test
            elif type_ is not None:
                TypeError
                log.exit(
                    f"Expected type_ to be a {License.KeyContainer.KeyType} or int, not {type_!r}"
                )
        except ValueError as e:
            ValueError
            log.exit(f"Could not parse type_ as a {License.KeyContainer.KeyType}, {e}")

        return [
            key
            for key in session.keys
            if not type_ or key.type == License.KeyContainer.KeyType.Name(type_)
        ]

    def decrypt(
        self,
        session_id: bytes,
        track,
        input_file: Union[Path, str],
        output_file: Union[Path, str],
        temp_dir: Optional[Union[Path, str]] = None,
    ):
        """
        Decrypt a Widevine-encrypted file using Shaka-packager.
        Shaka-packager is much more stable than mp4decrypt.

        Parameters:
            session_id: Session identifier.
            track: Video or Audio Track which needs to be decrypted.
            input_file: File to be decrypted with Session's currently loaded keys.
            output_file: Location to save decrypted file.
            temp_dir: Directory to store temporary data while decrypting.

        Raises:
            ValueError: If the input or output paths have not been supplied or are
                invalid.
            NoKeysLoaded: No License was parsed for this Session, No Keys available.
            EnvironmentError: If the shaka-packager executable could not be found.
            subprocess.CalledProcessError: If the shaka-packager call returned a non-zero
                exit code.
        """
        if not input_file:
            ValueError
            log.exit("Cannot decrypt nothing, specify an input path")
        if not output_file:
            ValueError
            log.exit("Cannot decrypt nowhere, specify an output path")

        if not isinstance(input_file, (Path, str)):
            ValueError
            log.exit(f"Expecting input_file to be a Path or str, got {input_file!r}")
        if not isinstance(output_file, (Path, str)):
            ValueError
            log.exit(f"Expecting output_file to be a Path or str, got {output_file!r}")
        if not isinstance(temp_dir, (Path, str)) and temp_dir is not None:
            ValueError
            log.exit(f"Expecting temp_dir to be a Path or str, got {temp_dir!r}")

        if not track.kid:
            log.exit("Expected an key_id but none is provided.")
        if not track.key:
            log.exit("Expected an content key but none is provided.")

        input_file = Path(input_file)
        output_file = Path(output_file)
        if temp_dir:
            temp_dir = Path(temp_dir)

        session = self.__sessions.get(session_id)
        if not session:
            InvalidSession
            log.error_(f"Session identifier {session_id!r} is invalid.", debug=True)

        if not session.keys:
            NoKeysLoaded
            log.exit("No Keys are loaded yet, cannot decrypt")

        platform = {"win32": "win", "darwin": "osx"}.get(sys.platform, sys.platform)
        executable = get_binary_path(
            "decrypter", f"decrypter-{platform}", f"decrypter-{platform}-x64"
        )
        if not executable:
            EnvironmentError
            log.exit(
                f"Unable to find decrypter, decrypter-{platform} or decrypter-{platform}-x64 binary"
            )

        args = [
            f"input={input_file},stream=0,output={output_file}",
            "--enable_raw_key_decryption",
            "--keys",
            ",".join(
                [
                    "label=0:key_id={}:key={}".format(
                        track.kid.lower(), track.key.lower()
                    ),
                    # Apple TV+ needs this as shaka pulls the incorrect KID, idk why
                    "label=1:key_id={}:key={}".format("0" * 32, track.key.lower()),
                ]
            ),
        ]

        if temp_dir:
            temp_dir.mkdir(parents=True, exist_ok=True)
            args.extend(["--temp_dir", str(temp_dir)])

        decrypt = subprocess.Popen(
            [executable, *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        )

        for line in iter(decrypt.stdout.readline, ""):
            if "%" in line.strip():
                progress = line.replace("\n", "")
                log.info_(f"{clean_line}   {progress}")

        if "Decrypted successfully" in line:
            log.info_(f"{clean_line}[green]   ✓ Completed {progress}[/green]")
        else:
            log.exit(f"{clean_line}   x Failed {progress}")

    @staticmethod
    def encrypt_client_id(
        client_id: ClientIdentification,
        service_certificate: Union[SignedDrmCertificate, DrmCertificate],
        key: bytes = None,
        iv: bytes = None,
    ) -> EncryptedClientIdentification:
        """Encrypt the Client ID with the Service's Privacy Certificate."""
        privacy_key = key or get_random_bytes(16)
        privacy_iv = iv or get_random_bytes(16)

        if isinstance(service_certificate, SignedDrmCertificate):
            drm_certificate = DrmCertificate()
            drm_certificate.ParseFromString(service_certificate.drm_certificate)
            service_certificate = drm_certificate
        if not isinstance(service_certificate, DrmCertificate):
            ValueError
            log.exit(
                f"Expecting Service Certificate to be a DrmCertificate, not {service_certificate!r}"
            )

        enc_client_id = EncryptedClientIdentification()
        enc_client_id.provider_id = service_certificate.provider_id
        enc_client_id.service_certificate_serial_number = (
            service_certificate.serial_number
        )

        enc_client_id.encrypted_client_id = AES.new(
            privacy_key, AES.MODE_CBC, privacy_iv
        ).encrypt(Padding.pad(client_id.SerializeToString(), 16))

        enc_client_id.encrypted_privacy_key = PKCS1_OAEP.new(
            RSA.importKey(service_certificate.public_key)
        ).encrypt(privacy_key)
        enc_client_id.encrypted_client_id_iv = privacy_iv

        return enc_client_id

    @staticmethod
    def derive_context(message: bytes) -> tuple[bytes, bytes]:
        """Returns 2 Context Data used for computing the AES Encryption and HMAC Keys."""

        def _get_enc_context(msg: bytes) -> bytes:
            label = b"ENCRYPTION"
            key_size = 16 * 8  # 128-bit
            return label + b"\x00" + msg + key_size.to_bytes(4, "big")

        def _get_mac_context(msg: bytes) -> bytes:
            label = b"AUTHENTICATION"
            key_size = 32 * 8 * 2  # 512-bit
            return label + b"\x00" + msg + key_size.to_bytes(4, "big")

        return _get_enc_context(message), _get_mac_context(message)

    @staticmethod
    def derive_keys(
        enc_context: bytes, mac_context: bytes, key: bytes
    ) -> tuple[bytes, bytes, bytes]:
        """
        Returns 3 keys derived from the input message.
        Key can either be a pre-provision device aes key, provision key, or a session key.

        For provisioning:
        - enc: aes key used for unwrapping RSA key out of response
        - mac_key_server: hmac-sha256 key used for verifying provisioning response
        - mac_key_client: hmac-sha256 key used for signing provisioning request

        When used with a session key:
        - enc: decrypting content and other keys
        - mac_key_server: verifying response
        - mac_key_client: renewals

        With key as pre-provision device key, it can be used to provision and get an
        RSA device key and token/cert with key as session key (OAEP wrapped with the
        post-provision RSA device key), it can be used to decrypt content and signing
        keys and verify licenses.
        """

        def _derive(session_key: bytes, context: bytes, counter: int) -> bytes:
            return (
                CMAC.new(session_key, ciphermod=AES)
                .update(counter.to_bytes(1, "big") + context)
                .digest()
            )

        enc_key = _derive(key, enc_context, 1)
        mac_key_server = _derive(key, mac_context, 1)
        mac_key_server += _derive(key, mac_context, 2)
        mac_key_client = _derive(key, mac_context, 3)
        mac_key_client += _derive(key, mac_context, 4)

        return enc_key, mac_key_server, mac_key_client

    def test(
        self,
        cdm,
        deviceType=None,
        moduleName=None,
        systemId=None,
        verbose=False,
        silent=False,
    ):
        """
        Test Cdm device by getting Content Keys with a test video of DRMToday.
        https://content.players.castlabs.com/demos/drm-agent/manifest.mpd

        The ctx argument will lead to the Cdm that will have
        the device private key among other required information.
        """
        if not getattr(self, "session", None):
            self = Cdm
            session = requests.Session()
        else:
            session = self.session

        try:
            session_id = cdm.open(CdmTest=True)
            cdm.session_id = session_id
        except ValueError as e:
            if cdm.api:
                error = json.loads("{" + e.args[0].split("{")[1].split("} ")[0] + "}")
                log.info_(f"{error['message']}", style="error")
            else:
                log.info_(f"Could not use CDM: {e!r}", style="error")
            exit()

        if getattr(cdm, "api", None):
            moduleName = re.sub(r"_([0-9]+)_L(1|3)", "", cdm.device_name).replace(
                "_", " "
            )

        client_info = {}
        for entry in cdm._Cdm__client_id.client_info:
            client_info[entry.name] = entry.value

        if not silent:
            if client_info:
                log.info_(
                    f" - [content]COMPANY_NAME[/content] {client_info['company_name'].upper()}"
                )
            log.info_(
                f" - [content]DEVICE_TYPE[/content]  {deviceType or cdm.device_type.name}{' (API)' if cdm.api else ''}"
            )
            log.info_(
                f" - [content]MODULE_NAME[/content]  {'StreamFabCdm' if cdm.system_id == 21889 else moduleName or client_info['model_name']}"
            )
            log.info_(f" - [content]SYSTEM_ID[/content]    {27175 if cdm.system_id == 21889 else systemId or cdm.system_id}")
            log.info_(f" - [content]SECURITY[/content]     L{cdm.security_level}")

            if verbose:
                log.info_(
                    f" - [content]ARCHITECTURE[/content] {client_info['architecture_name']}"
                )
                if client_info.get("build_info"):
                    log.info_(
                        f" - [content]BUILD_INFO[/content]   {client_info['build_info']}"
                    )
                if client_info.get("device_id"):
                    log.info_(
                        f" - [content]DEVICE_ID[/content]    {client_info['device_id']}"
                    )
                if client_info.get("os_version"):
                    log.info_(
                        f" - [content]OS_VERSION[/content]   {client_info['os_version']}"
                    )

        status = " - [content]DRM_STATUS[/content]"
        if cdm.system_id == 21889:
            status += "   00000 ([success]VALID[/success])"
            if not silent:
                log.info_(status)
            return cdm.close(cdm.session_id)        
        else:
            # The PSSH can always be the same while testing.
            pssh = "AAAAMnBzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAABISEG9rG5iE+D0Lhmob2KyjkNI="

            # This License Server requires authorization with an Authentication Token
            # This is also the case for real services, most of the time.
            license_server = "https://lic.staging.drmtoday.com/license-proxy-widevine/cenc/?assetId=agent-327"

            # OFFLINE is specified if it's a PSSH for a download/offline mode title, e.g., the
            # Download feature on Netflix Apps. Otherwise its mostly STREAMING or AUTOMATIC.
            # For this test it does not seem to care about which one will be specified.
            license_type = "STREAMING"

            cdm.set_service_certificate(
                session_id=session_id,
                certificate=(
                    "CAUSxQUKvwIIAxIQKHA0VMAI9jYYredEPbbEyBiL5/mQBSKOAjCCAQoCggEBALUhErjQXQI/zF2V4sJRwcZJtBd82NK+"
                    "7zVbsGdD3mYePSq8MYK3mUbVX9wI3+lUB4FemmJ0syKix/XgZ7tfCsB6idRa6pSyUW8HW2bvgR0NJuG5priU8rmFeWKq"
                    "FxxPZmMNPkxgJxiJf14e+baq9a1Nuip+FBdt8TSh0xhbWiGKwFpMQfCB7/+Ao6BAxQsJu8dA7tzY8U1nWpGYD5LKfdxk"
                    "agatrVEB90oOSYzAHwBTK6wheFC9kF6QkjZWt9/v70JIZ2fzPvYoPU9CVKtyWJOQvuVYCPHWaAgNRdiTwryi901goMDQ"
                    "oJk87wFgRwMzTDY4E5SGvJ2vJP1noH+a2UMCAwEAAToSc3RhZ2luZy5nb29nbGUuY29tEoADmD4wNSZ19AunFfwkm9rl"
                    "1KxySaJmZSHkNlVzlSlyH/iA4KrvxeJ7yYDa6tq/P8OG0ISgLIJTeEjMdT/0l7ARp9qXeIoA4qprhM19ccB6SOv2FgLM"
                    "paPzIDCnKVww2pFbkdwYubyVk7jei7UPDe3BKTi46eA5zd4Y+oLoG7AyYw/pVdhaVmzhVDAL9tTBvRJpZjVrKH1lexjO"
                    "Y9Dv1F/FJp6X6rEctWPlVkOyb/SfEJwhAa/K81uDLyiPDZ1Flg4lnoX7XSTb0s+Cdkxd2b9yfvvpyGH4aTIfat4YkF9N"
                    "kvmm2mU224R1hx0WjocLsjA89wxul4TJPS3oRa2CYr5+DU4uSgdZzvgtEJ0lksckKfjAF0K64rPeytvDPD5fS69eFuy3"
                    "Tq26/LfGcF96njtvOUA4P5xRFtICogySKe6WnCUZcYMDtQ0BMMM1LgawFNg4VA+KDCJ8ABHg9bOOTimO0sswHrRWSWX1"
                    "XF15dXolCk65yEqz5lOfa2/fVomeopkU"
                ),
            )

            challenge = cdm.get_license_challenge(
                session_id=session_id, pssh=PSSH(pssh), type_=license_type
            )
        
            if not getattr(self, "device_test", None):
                self.device_test = session.post(
                    url=license_server,
                    data=challenge,
                    headers={
                        "user-agent": "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                        "dt-custom-data": "eyJ1c2VySWQiOiJwdXJjaGFzZSIsInNlc3Npb25JZCI6ImRlZmF1bHQiLCJtZXJjaGFudCI6ImNsaWVudF9kZXYifQ==",
                    },
                )

            if self.device_test.status_code == 200:
                status += "   00000 ([success]VALID[/success])"
                self.device_info = self.device_test.json()
            else:
                """
                - Most of these were taken from the old player JS.
                    40002 was inferred based on tests with actual keys.

                - DRM_STATUS_CODES
                    "00000": "Success",
                    "01000": "General Internal Error",
                    "02000": "General Request Error",
                    "03000": "General Request Authentication Error",
                    "30000": "General DRM Error",
                    "40000": "General Widevine Modular Error",
                    "40001": "Widevine Device Certificate Revocation",
                    "40002": "Widevine Device Certificate Serial Number Revocation",
                    "41000": "General Widevine Classic Error",
                    "42000": "General PlayReady Error",
                    "43000": "General FairPlay Error",
                    "44000": "General OMA Error",
                    "44001": "OMA Device Registration Failed",
                    "45000": "General CDRM Error",
                    "45001": "CDRM Device Registration Failed",
                    "70000": "General Output Protection Error",
                    "70001": "All keys filtered by EOP settings",
                    "80000": "General CSL Error",
                    "80001": "Too many concurrent streams",
                    "90000": "General GBL Error",
                    "90001": "License delivery prohibited in your region"
                """

                status += f"   {(self.device_test.headers.get('x-dt-resp-code') or '40001')} ([error]REVOKED[/error])"

        if not silent:
            log.info_(status)
        cdm.close(cdm.session_id)

        return (
            self.device_test.status_code
            if self.device_test.status_code == 200
            else (self.device_test.headers.get("x-dt-resp-code") or "40001")
        )


__ALL__ = (Cdm,)
