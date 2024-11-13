import os

from pywidevinely import Device
from pywidevinely.utils.protos.license_protocol_pb2 import ClientIdentification

from widevinely.utils import logger

log = logger.getLogger("wvd.ClientID")


class parse:
    """
    Parse ClientID information from a file.
    Both client_id.blob files and .WVD Widevine Device files are allowed.
    """

    def __init__(self, path) -> None:
        client_id = ClientIdentification()
        is_wvd = path.name.endswith(".wvd")

        if not is_wvd and not path.name.endswith("_blob"):
            if "device_client_id" in path.name:
                path = path / f"{path.name}_blob"
            else:
                path = path / "device_client_id_blob"
            if not os.path.isfile(path):
                log.exit(
                    f"Could not find any file called 'device_client_id_blob' in directory\n{str(path.parent)!r}"
                )

        if is_wvd:
            client_id = Device.load(path).client_id
        else:
            with open(path, "rb") as fd:
                data = fd.read()
            client_id.ParseFromString(data)

        print(client_id)
