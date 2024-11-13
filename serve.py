import base64
import asyncio
from pathlib import Path
from typing import Optional, Union
from datetime import timedelta, datetime

from google.protobuf.message import DecodeError
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

from pywidevinely import __version__
from pywidevinely.pssh import PSSH
from pywidevinely.utils import logger
from pywidevinely.cdm import Cdm
from pywidevinely.device import Device
from pywidevinely.exceptions import (
    InvalidSession,
    SignatureMismatch,
    InvalidInitData,
    InvalidLicenseType,
    InvalidLicenseMessage,
    InvalidContext,
)

log = logger.getLogger("serve")
scheduler = BackgroundScheduler()

try:
    from aiohttp import web
except ImportError:
    log.exit(
        "\nMissing the extra dependencies for serve functionality. "
        "\nYou may install them under poetry with `poetry install -E serve`",
        debug=False,
    )

routes = web.RouteTableDef()


@scheduler.scheduled_job(IntervalTrigger(seconds=30))
def close_toomany_sessions():
    if "cdm_" in globals():
        if len(cdm_._Cdm__sessions) >= cdm_.MAX_NUM_OF_SESSIONS:
            sessions = sorted(
                cdm_._Cdm__sessions, key=lambda ses: cdm_._Cdm__sessions[ses].opened_at
            )
            for session_id in sessions[-10:]:
                del cdm_._Cdm__sessions[session_id]
            logger.getLogger("serve").info_(
                f"Closed 10/{len(sessions)} opened sessions because there were too many open.",
                debug=True,
            )


@scheduler.scheduled_job(IntervalTrigger(hours=1))
def close_oldest_sessions(treshold=30):
    if "cdm_" in globals():
        for session_id in cdm_._Cdm__sessions.copy():
            if cdm_._Cdm__sessions[
                session_id
            ].opened_at < datetime.utcnow() + timedelta(seconds=-treshold):
                logger.getLogger("serve").info_(
                    f"Closed all sessions older than {treshold} minutes.", debug=True
                )
                del cdm_._Cdm__sessions[session_id]


async def _startup(app: web.Application):
    global devices
    scheduler.start()
    app["cdms"]: dict[tuple[str, str], Cdm] = {}  # type: ignore
    app["config"]["devices"] = {
        path.stem: path for x in app["config"]["devices"] for path in [Path(x)]
    }
    devices = app["config"]["devices"].values()
    for device in app["config"]["devices"].values():
        if not device.is_file():
            FileNotFoundError
            log.error_(
                f"\nDevice filepath {str(device)!r} does not exist.", debug=False
            )
            asyncio.get_event_loop().stop()


async def _cleanup(app: web.Application):
    app["cdms"].clear()
    del app["cdms"]
    app["config"].clear()
    del app["config"]


@routes.get("/")
async def ping(request: web.Request) -> web.Response:
    if not respect_privacy:
        logger.getLogger(request.remote, api=True).success_(
            "Successfully connected to the Cdm Api.", debug=True
        )
    return web.json_response({"status": 200, "message": "Pong!"})


@routes.get("/{device}/open")
async def open_(request: web.Request) -> web.Response:
    secret_key = request.headers["X-Secret-Key"]
    device_name = request.match_info["device"]
    user = request.app["config"]["users"][secret_key]

    global log
    log = logger.getLogger(
        f"{user['username']}{f' [{request.remote}]' if not respect_privacy else ''}",
        api=True,
    )

    log.success_("Succesfully authenticated", debug=True)

    if (
        device_name not in user["devices"]
        or device_name not in request.app["config"]["devices"]
    ):
        # we don't want to be verbose with the error as to not reveal device names
        # by trial and error to users that are not authorized to use them
        if device_name not in request.app["config"]["devices"]:
            log.error_(
                f"Device {device_name!r} could not be found",
                debug=True,
            )
        elif device_name not in user["devices"]:
            log.error_(
                f"User is not authorized to use device {device_name!r}",
                debug=True,
            )

        return web.json_response(
            {
                "status": 403,
                "message": f"Device {device_name!r} is not found or you are not authorized to use it.",
            },
            status=403,
        )

    global cdm_
    cdm: Optional[Cdm] = request.app["cdms"].get((secret_key, device_name))
    if not cdm:
        device = Device.load(request.app["config"]["devices"][device_name])
        cdm = request.app["cdms"][(secret_key, device_name)] = Cdm.from_device(
            device, test_=request.query["CdmTest"]
        )
        cdm_ = cdm

    session_id = cdm.open()
    cdm.test_ = bool(request.query["CdmTest"] == "True")

    log.success_(
        f"Successfully opened a Cdm{' Test ' if cdm.test_ else ' '}Session: {session_id.hex()}"
    )
    return web.json_response(
        {
            "status": 200,
            "message": "Success",
            "data": {
                "session_id": session_id.hex(),
                "CDM TEST": True if cdm.test_ else False,
                "device": {
                    "system_id": cdm.system_id,
                    "security_level": cdm.security_level,
                },
            },
        }
    )


@routes.get("/{device}/close/{session_id}")
async def close(request: web.Request) -> web.Response:
    secret_key = request.headers["X-Secret-Key"]
    device_name = request.match_info["device"]
    session_id = bytes.fromhex(request.match_info["session_id"])

    cdm: Optional[Cdm] = request.app["cdms"].get((secret_key, device_name))
    if not cdm:
        log.error_(
            f"Was trying to close a Cdm session for {device_name!r} but it has not been opened yet",
            debug=True,
        )
        return web.json_response(
            {
                "status": 400,
                "message": f"No Cdm session for {device_name!r} has been opened yet. No session to close.",
            },
            status=400,
        )

    try:
        cdm.close(session_id)
    except InvalidSession:
        log.error_(
            f"Was trying to use an invalid Session Id '{session_id.hex()}', it may have expired."
        )
        return web.json_response(
            {
                "status": 400,
                "message": f"Invalid Session Id '{session_id.hex()}', it may have expired.",
            },
            status=400,
        )

    log.success_(
        f"Succesfully closed Cdm{' Test ' if cdm.test_ else ' '}Session '{session_id.hex()}'"
    )
    return web.json_response(
        {
            "status": 200,
            "message": f"Successfully closed{' Test ' if cdm.test_ else ' '}Session '{session_id.hex()}'.",
        }
    )


@routes.post("/{device}/set_service_certificate")
async def set_service_certificate(request: web.Request) -> web.Response:
    secret_key = request.headers["X-Secret-Key"]
    device_name = request.match_info["device"]

    body = await request.json()
    for required_field in ("session_id", "certificate"):
        if required_field == "certificate":
            has_field = (
                required_field in body
            )  # it needs the key, but can be empty/null
        else:
            has_field = body.get(required_field)
        if not has_field:
            log.error_(
                f"Missing required field '{required_field}' in JSON body.", debug=True
            )
            return web.json_response(
                {
                    "status": 400,
                    "message": f"Missing required field '{required_field}' in JSON body.",
                },
                status=400,
            )

    # get session id
    session_id = bytes.fromhex(body["session_id"])

    # get cdm
    cdm: Optional[Cdm] = request.app["cdms"].get((secret_key, device_name))
    if not cdm:
        log.error_(
            f"Was trying to close a Cdm session for {device_name!r} but it has not been opened yet",
            debug=True,
        )
        return web.json_response(
            {
                "status": 400,
                "message": f"No Cdm session for {device_name!r} has been opened yet. No session to use.",
            },
            status=400,
        )

    # set service certificate
    certificate = body.get("certificate")
    try:
        provider_id = cdm.set_service_certificate(session_id, certificate)
    except InvalidSession:
        log.error_(
            f"Was trying to use an invalid Session Id '{session_id.hex()}', it may have expired."
        )
        return web.json_response(
            {
                "status": 400,
                "message": f"Invalid Session Id '{session_id.hex()}', it may have expired.",
            },
            status=400,
        )
    except DecodeError as e:
        log.error_(f"Invalid Service Certificate; {e}", debug=True)
        return web.json_response(
            {"status": 400, "message": f"Invalid Service Certificate; {e}"}, status=400
        )
    except SignatureMismatch:
        log.error_(
            "Signature Validation failed on the Service Certificate, rejected.",
            debug=True,
        )
        return web.json_response(
            {
                "status": 400,
                "message": "Signature Validation failed on the Service Certificate, rejecting.",
            },
            status=400,
        )

    # set service certificate
    certificate = body.get("certificate")
    provider_id = cdm.set_service_certificate(session_id, certificate)

    if not cdm.test_:
        log.success_(
            f"Successfully {['set', 'unset'][not certificate]} the Service Certificate."
        )
    return web.json_response(
        {
            "status": 200,
            "message": f"Successfully {['set', 'unset'][not certificate]} the Service Certificate.",
            "data": {"provider_id": provider_id},
        }
    )


@routes.post("/{device}/get_service_certificate")
async def get_service_certificate(request: web.Request) -> web.Response:
    secret_key = request.headers["X-Secret-Key"]
    device_name = request.match_info["device"]

    body = await request.json()
    for required_field in ("session_id",):
        if not body.get(required_field):
            log.error_(
                f"Missing required field '{required_field}' in JSON body.", debug=True
            )
            return web.json_response(
                {
                    "status": 400,
                    "message": f"Missing required field '{required_field}' in JSON body.",
                },
                status=400,
            )

    # get session id
    session_id = bytes.fromhex(body["session_id"])

    # get cdm
    cdm: Optional[Cdm] = request.app["cdms"].get((secret_key, device_name))
    if not cdm:
        log.error_(
            f"No Cdm session for {device_name} has been opened yet. No session to use.",
            debug=True,
        )
        return web.json_response(
            {
                "status": 400,
                "message": f"No Cdm session for {device_name} has been opened yet. No session to use.",
            },
            status=400,
        )

    # get service certificate
    try:
        service_certificate = cdm.get_service_certificate(session_id)
    except InvalidSession:
        log.error_(
            f"Invalid Session ID '{session_id.hex()}', it may have expired.", debug=True
        )
        return web.json_response(
            {
                "status": 400,
                "message": f"Invalid Session ID '{session_id.hex()}', it may have expired.",
            },
            status=400,
        )

    if service_certificate:
        service_certificate = base64.b64encode(
            service_certificate.SerializeToString()
        ).decode()

    log.success_(f"Service Certificate: {service_certificate}")
    return web.json_response(
        {
            "status": 200,
            "message": "Successfully got the Service Certificate.",
            "data": {"service_certificate": service_certificate},
        }
    )


@routes.post("/{device}/get_license_challenge/{license_type}")
async def get_license_challenge(request: web.Request) -> web.Response:
    secret_key = request.headers["X-Secret-Key"]
    device_name = request.match_info["device"]
    license_type = request.match_info["license_type"]

    body = await request.json()
    for required_field in ("session_id", "init_data"):
        if not body.get(required_field):
            log.error_(
                f"Missing required field '{required_field}' in JSON body.", debug=True
            )
            return web.json_response(
                {
                    "status": 400,
                    "message": f"Missing required field '{required_field}' in JSON body.",
                },
                status=400,
            )

    # get session id
    session_id = bytes.fromhex(body["session_id"])

    # get privacy mode flag
    privacy_mode = body.get("privacy_mode", True)

    # get cdm
    cdm: Optional[Cdm] = request.app["cdms"].get((secret_key, device_name))
    if not cdm:
        log.error_(
            f"Was trying to close a Cdm session for {device_name!r} but it has not been opened yet",
            debug=True,
        )
        return web.json_response(
            {
                "status": 400,
                "message": f"No Cdm session for {device_name!r} has been opened yet. No session to use.",
            },
            status=400,
        )

    # enforce service certificate (opt-in)
    if request.app["config"].get("force_privacy_mode"):
        privacy_mode = True
        if not cdm.get_service_certificate(session_id):
            log.error_(
                "Is not using a Service Certificate while Privacy Mode is Enforced",
                debug=True,
            )
            return web.json_response(
                {
                    "status": 403,
                    "message": "No Service Certificate set but Privacy Mode is Enforced.",
                },
                status=403,
            )

    # get init data
    init_data = PSSH(body["init_data"])

    # get challenge
    try:
        license_request = cdm.get_license_challenge(
            session_id=session_id,
            pssh=init_data,
            type_=license_type,
            privacy_mode=privacy_mode,
        )
    except InvalidSession:
        log.warning_(
            f"Was trying to use an invalid Session Id '{session_id.hex()}', it may have expired."
        )
        return web.json_response(
            {
                "status": 400,
                "message": f"Invalid Session Id '{session_id.hex()}', it may have expired.",
            },
            status=400,
        )
    except InvalidInitData as e:
        # TODO: Test
        log.error_(f"Invalid Init Data; {e}", debug=True)
        return web.json_response(
            {"status": 400, "message": f"Invalid Init Data; {e}"}, status=400
        )
    except InvalidLicenseType:
        log.error_(f"Invalid License Type '{license_type}'")
        return web.json_response(
            {"status": 400, "message": f"Invalid License Type '{license_type}'"},
            status=400,
        )

    if not cdm.test_:
        log.success_(f"challenge_b64: {base64.b64encode(license_request).decode()}")
    else:
        log.success_("Cdm Test was succesful.")
    return web.json_response(
        {
            "status": 200,
            "message": "Success",
            "data": {"challenge_b64": base64.b64encode(license_request).decode()},
        },
        status=200,
    )


@routes.post("/{device}/parse_license")
async def parse_license(request: web.Request) -> web.Response:
    secret_key = request.headers["X-Secret-Key"]
    device_name = request.match_info["device"]

    body = await request.json()
    for required_field in ("session_id", "license_message"):
        if not body.get(required_field):
            log.error_(
                f"Missing required field '{required_field}' in JSON body.", debug=True
            )
            return web.json_response(
                {
                    "status": 400,
                    "message": f"Missing required field '{required_field}' in JSON body.",
                },
                status=400,
            )

    # get session id
    session_id = bytes.fromhex(body["session_id"])

    # get cdm
    cdm: Optional[Cdm] = request.app["cdms"].get((secret_key, device_name))
    if not cdm:
        log.error_(
            f"Was trying to close a Cdm session for {device_name!r} but it has not been opened yet",
            debug=True,
        )
        return web.json_response(
            {
                "status": 400,
                "message": f"No Cdm session for {device_name!r} has been opened yet. No session to use.",
            },
            status=400,
        )

    # parse the license message
    try:
        cdm.parse_license(session_id, body["license_message"])
    except InvalidSession:
        log.warning_(
            f"Was trying to use an invalid Session Id '{session_id.hex()}', it may have expired."
        )
        return web.json_response(
            {
                "status": 400,
                "message": f"Invalid Session Id '{session_id.hex()}', it may have expired.",
            },
            status=400,
        )
    except InvalidLicenseMessage as e:
        log.error_(f"Invalid License Message; {e}", debug=True)
        return web.json_response(
            {"status": 400, "message": f"Invalid License Message; {e}"}, status=400
        )
    except InvalidContext as e:
        log.error_(f"Invalid Context; {e}", debug=True)
        return web.json_response(
            {"status": 400, "message": f"Invalid Context; {e}"}, status=400
        )
    except SignatureMismatch:
        log.error_(
            "Signature Validation failed on the License Message, rejected.", debug=True
        )
        return web.json_response(
            {
                "status": 400,
                "message": "Signature Validation failed on the License Message, rejecting.",
            },
            status=400,
        )

    log.success_("Successfully parsed and loaded the Keys from the License message.")
    return web.json_response(
        {
            "status": 200,
            "message": "Successfully parsed and loaded the Keys from the License message.",
        }
    )


@routes.post("/{device}/get_keys/{key_type}")
async def get_keys(request: web.Request) -> web.Response:
    secret_key = request.headers["X-Secret-Key"]
    device_name = request.match_info["device"]

    body = await request.json()
    for required_field in ("session_id",):
        if not body.get(required_field):
            log.error_(
                f"Missing required field '{required_field}' in JSON body.", debug=True
            )
            return web.json_response(
                {
                    "status": 400,
                    "message": f"Missing required field '{required_field}' in JSON body.",
                },
                status=400,
            )

    # get session id
    session_id = bytes.fromhex(body["session_id"])

    # get key type
    key_type = request.match_info["key_type"]
    if key_type == "ALL":
        key_type = None

    # get cdm
    cdm = request.app["cdms"].get((secret_key, device_name))
    if not cdm:
        log.error_(
            f"Was trying to close a Cdm session for {device_name!r} but it has not been opened yet",
            debug=True,
        )
        return web.json_response(
            {
                "status": 400,
                "message": f"No Cdm session for {device_name!r} has been opened yet. No session to use.",
            },
            status=400,
        )

    # get keys
    try:
        keys = cdm.get_keys(session_id, key_type)
    except InvalidSession:
        log.warning_(
            f"Was trying to use an invalid Session Id '{session_id.hex()}', it may have expired."
        )
        return web.json_response(
            {
                "status": 400,
                "message": f"Invalid Session Id '{session_id.hex()}', it may have expired.",
            },
            status=400,
        )
    except ValueError as e:
        log.error_(f"The Key Type value '{key_type}' is invalid; {e}", debug=True)
        return web.json_response(
            {
                "status": 400,
                "message": f"The Key Type value '{key_type}' is invalid; {e}",
            },
            status=400,
        )

    # get the keys in json form
    keys_json = [
        {
            "key_id": key.kid.hex,
            "key": key.key.hex(),
            "type": key.type,
            "permissions": key.permissions,
        }
        for key in keys
        if not key_type or key.type == key_type
    ]

    log.success_(f"ContentKeys: {keys_json}")
    return web.json_response(
        {"status": 200, "message": "Success", "data": {"keys": keys_json}}
    )


@web.middleware
async def authentication(request: web.Request, handler) -> web.Response:
    response = None
    if request.path != "/":
        secret_key = request.headers.get("X-Secret-Key")
        if not secret_key:
            log.error_("Did not provide any Secret Key for authentication", debug=True)
            response = web.json_response(
                {"status": "401", "message": "Secret Key is missing."}, status=401
            )
        elif secret_key not in request.app["config"]["users"]:
            log.error_(
                f"Failed authenticating with Secret Key: '{secret_key}'", debug=True
            )
            response = web.json_response(
                {
                    "status": "401",
                    "message": "Provided Secret Key is invalid.",
                },
                status=401,
            )

    if response is None:
        try:
            response = await handler(request)
        except web.HTTPException as e:
            log.error_(f"An unexpected error has occurred; {e}", debug=True)
            response = web.json_response(
                {"status": 500, "message": e.reason}, status=500
            )

    response.headers.update(
        {
            "Server": f"https://github.com/Hollander-1908/pywidevinely serve v{__version__}"
        }
    )

    return response


def run(
    config: dict,
    host: Optional[Union[str, web.HostSequence]] = None,
    port: Optional[int] = None,
    privacy: Optional[bool] = False,
):
    global respect_privacy
    respect_privacy = privacy

    app = web.Application(middlewares=[authentication])
    app.on_startup.append(_startup)
    app.on_cleanup.append(_cleanup)
    app.add_routes(routes)
    app["config"] = config
    try:
        web.run_app(app, host=host, port=port)
    except RuntimeError:
        exit()
