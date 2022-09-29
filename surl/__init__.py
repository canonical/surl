import argparse
import base64
import datetime
import getpass
import json
import os
import socket
import sys

from collections import namedtuple

import macaroonbakery._utils as utils
import requests

from pymacaroons import Macaroon
from macaroonbakery import bakery, httpbakery

name = "surl"

__all__ = [
    "ClientConfig",
    "ConfigError",
    "CliError",
    "CliDone",
    "get_config_from_cli",
    "get_store_authorization",
    "get_authorization_header",
    "get_refreshed_discharge",
    "main",
]


DEFAULT_HEADERS = {
    "User-Agent": "surl/{}".format(os.environ.get("SNAP_VERSION", "devel")),
    "Accept": "application/json, application/hal+json",
    "Content-Type": "application/json",
    "Cache-Control": "no-cache",
}

CONSTANTS = {
    "local": {
        "sso_location": os.environ.get(
            "SURL_SSO_LOCATION", "login.staging.ubuntu.com"
        ),
        "sso_base_url": os.environ.get(
            "SURL_SSO_BASE_URL", "https://login.staging.ubuntu.com"
        ),
        "sca_base_url": os.environ.get(
            "SURL_SCA_BASE_URL", "http://0.0.0.0:8000"
        ),
        "api_base_url": os.environ.get(
            "SURL_API_BASE_URL", "http://0.0.0.0:8000"
        ),
    },
    "staging": {
        "sso_location": "login.staging.ubuntu.com",
        "sso_base_url": "https://login.staging.ubuntu.com",
        "sca_base_url": os.environ.get(
            "SURL_SCA_ROOT_URL", "https://dashboard.staging.snapcraft.io"
        ),
        "api_base_url": os.environ.get(
            "SURL_API_ROOT_URL", "https://api.staging.snapcraft.io"
        ),
    },
    "production": {
        "sso_location": "login.ubuntu.com",
        "sso_base_url": "https://login.ubuntu.com",
        "sca_base_url": "https://dashboard.snapcraft.io",
        "api_base_url": "https://api.snapcraft.io",
    },
}


class ConfigError(Exception):
    pass


class CliError(Exception):
    pass


class CliDone(Exception):
    pass


ClientConfig = namedtuple(
    "ClientConfig", ["root", "discharge", "store_env", "path"]
)


def load_config(path):
    with open(path) as fd:
        try:
            a = json.load(fd)
            root, discharge, store_env = (
                a["root"],
                a["discharge"],
                a["store"],
            )
        except json.decoder.JSONDecodeError:
            raise ConfigError()
    return ClientConfig(
        root=root, discharge=discharge, store_env=store_env, path=path
    )


def save_config(config):
    payload = {
        "root": config.root,
        "discharge": config.discharge,
        "store": config.store_env,
    }
    with open(config.path, "w") as fd:
        json.dump(payload, fd, indent=2)


def list_configs(path):
    candidates = [f for f in os.listdir(path) if f.endswith(".surl")]
    for f in candidates:
        try:
            config = load_config(os.path.join(path, f))
        except ConfigError:
            continue
        ident = f.replace(".surl", "")
        yield ident, config.store_env


def get_config_from_cli(parser, auth_dir):

    # Auxiliary options.
    parser.add_argument(
        "--version",
        action="version",
        version='surl "{}"'.format(os.environ.get("SNAP_VERSION", "devel")),
    )
    parser.add_argument(
        "-l",
        "--list-auth",
        action="store_true",
        help="List stored authorizations..",
    )

    # Credential options.
    parser.add_argument(
        "-a",
        "--auth",
        metavar="IDENT",
        help="Authorization identifier (saving or reading).",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force re-authorization and overrides saved information.",
    )
    # mutually exclusive: email CLI U1 SSO auth vs candid web login auth
    exclusive_group = parser.add_mutually_exclusive_group()
    exclusive_group.add_argument(
        "-e", "--email", default=os.environ.get("STORE_EMAIL")
    )
    exclusive_group.add_argument("--web-login", action="store_true")
    parser.add_argument(
        "-s",
        "--store",
        default=os.environ.get("STORE_ENV", "staging"),
        choices=["staging", "production", "local"],
    )

    # Macaroon restricting options.
    parser.add_argument(
        "-p",
        "--permission",
        action="append",
        dest="permissions",
        choices=[
            "edit_account",
            "modify_account_key",
            "package_access",
            "package_manage",
            "package_metrics",
            "package_push",
            "package_purchase",
            "package_register",
            "package_release",
            "package_update",
            "package_upload",
            "package_upload_request",
            "package_view_metadata",
            "store_admin",
            "store_review",
        ],
    )
    parser.add_argument(
        "-c",
        "--channel",
        action="append",
        dest="channels",
        choices=["stable", "candidate", "beta", "edge"],
    )
    parser.add_argument(
        "--allowed-store",
        action="append",
        dest="allowed_stores",
        help=(
            "Indicate the store id where the restricted auth can work. Can "
            "be used several times to indicate multiple stores."
        ),
    )
    parser.add_argument(
        "--snap",
        action="append",
        dest="snaps",
        help=(
            "Indicate the name of the snap on which the restricted auth "
            "can work. Can be used several times to indicate multiple "
            "snaps."
        ),
    )

    args, remainder = parser.parse_known_args()

    if args.list_auth:
        print("Available credentials:")
        for ident, store_env in list_configs(auth_dir):
            print("  {} ({})".format(ident, store_env))
        raise CliDone()

    if args.auth:
        auth_path = os.path.join(auth_dir, args.auth + ".surl")
        legacy_path = os.path.join(auth_dir, args.auth)
        if os.path.exists(legacy_path):
            os.rename(legacy_path, auth_path)
        auth_exists = os.path.exists(auth_path)
    else:
        auth_path = None
        auth_exists = False

    if auth_exists and not args.force:
        try:
            config = load_config(auth_path)
        except ConfigError:
            raise CliError(
                "** Deprecated or Broken authentication file, "
                "please delete it and login again:\n  $ rm {}".format(
                    auth_path
                )
            )

        return config, remainder

    store_env = args.store
    if not args.web_login and args.email is None:
        raise CliError('Needs "-e <email>" or $STORE_EMAIL.')

    try:
        root, discharge = get_store_authorization(
            args.email,
            permissions=args.permissions,
            channels=args.channels,
            allowed_stores=args.allowed_stores,
            snaps=args.snaps,
            web_login=args.web_login,
            store_env=store_env,
        )
    except CliError:
        raise
    except Exception as e:
        raise CliError(
            "Authorization failed! Double-check password and 2FA. (%s)" % e
        )

    config = ClientConfig(
        root=root, discharge=discharge, store_env=store_env, path=auth_path
    )

    if auth_path is not None:
        save_config(config)

    return config, remainder


def _get_authorization_payload(permissions, channels, snaps, allowed_stores):
    # Request a SCA root macaroon with hard expiration in 180 days.
    sca_data = {
        "permissions": permissions or ["package_access"],
        "expires": (
            datetime.date.today() + datetime.timedelta(days=180)
        ).strftime("%Y-%m-%d 00:00:00"),
    }
    if channels:
        sca_data["channels"] = channels
    if allowed_stores:
        sca_data["store_ids"] = allowed_stores
    if snaps:
        sca_data["packages"] = [{"name": snap} for snap in snaps]

    return sca_data


def _get_bakery_auth_header(root, discharge):
    macaroons = "[{}]".format(
        ",".join(map(utils.macaroon_to_json_string, [root, discharge]))
    )
    # serialize macaroons the bakery-way
    all_macaroons = base64.urlsafe_b64encode(utils.to_bytes(macaroons)).decode(
        "ascii"
    )
    return {"Macaroons": all_macaroons}


def _get_store_authorization_using_candid(
    permissions=None,
    channels=None,
    allowed_stores=None,
    snaps=None,
    store_env=None,
):
    """Return the serialised root and discharge macaroon.

    Get a permissions macaroon from SCA and discharge it via Candid.
    """
    headers = DEFAULT_HEADERS.copy()
    sca_data = _get_authorization_payload(
        permissions, channels, snaps, allowed_stores
    )
    # set additional macaroon description
    sca_data["description"] = "surl @ {}".format(socket.gethostname())

    response = requests.request(
        url="{}/api/v2/tokens".format(CONSTANTS[store_env]["sca_base_url"]),
        method="POST",
        json=sca_data,
        headers=headers,
    )
    if response.status_code != 200:
        error = response.json()["title"]
        raise CliError("Error {}: {}".format(response.status_code, error))
    serialized_root = json.loads(response.json()["macaroon"])

    # get discharge(s)
    client = httpbakery.Client()
    m = bakery.Macaroon.from_dict(serialized_root)
    root, discharge = bakery.discharge_all(m, client.acquire_discharge)

    # with the Candid-discharged pair, get the exchanged SnapStore macaroon
    auth_header = _get_bakery_auth_header(root, discharge)
    exchange_url = "{}/api/v2/tokens/exchange".format(
        CONSTANTS[store_env]["sca_base_url"]
    )
    r = client.request("POST", exchange_url, json={}, headers=auth_header)
    # get the (serialized) exchanged macaroon from the response
    macaroon = r.json()["macaroon"]

    return macaroon, None


def _get_store_authorization(
    email,
    permissions=None,
    channels=None,
    allowed_stores=None,
    snaps=None,
    store_env=None,
):
    """Return the serialised root and discharge macaroon.

    Get a permissions macaroon from SCA and discharge it in SSO.
    """
    headers = DEFAULT_HEADERS.copy()
    sca_data = _get_authorization_payload(
        permissions, channels, snaps, allowed_stores
    )

    response = requests.request(
        url="{}/dev/api/acl/".format(CONSTANTS[store_env]["sca_base_url"]),
        method="POST",
        json=sca_data,
        headers=headers,
    )
    if response.status_code != 200:
        error = response.json()["title"]
        raise CliError("Error {}: {}".format(response.status_code, error))
    root = response.json()["macaroon"]

    (caveat,) = [
        c
        for c in Macaroon.deserialize(root).third_party_caveats()
        if c.location == CONSTANTS[store_env]["sso_location"]
    ]
    # Request a SSO discharge macaroon.
    sso_data = {
        "email": email,
        "password": getpass.getpass("Password for {}: ".format(email)),
        "caveat_id": caveat.caveat_id,
    }
    response = requests.request(
        url="{}/api/v2/tokens/discharge".format(
            CONSTANTS[store_env]["sso_base_url"]
        ),
        method="POST",
        json=sso_data,
        headers=headers,
    )
    # OTP/2FA is optional.
    if (
        response.status_code == 401
        and response.json().get("code") == "TWOFACTOR_REQUIRED"
    ):
        sys.stderr.write("Second-factor auth for {}: ".format(store_env))
        sso_data.update({"otp": input()})
        response = requests.request(
            url="{}/api/v2/tokens/discharge".format(
                CONSTANTS[store_env]["sso_base_url"]
            ),
            method="POST",
            json=sso_data,
            headers=headers,
        )
    discharge = response.json()["discharge_macaroon"]

    return root, discharge


def get_store_authorization(
    email,
    permissions=None,
    channels=None,
    allowed_stores=None,
    snaps=None,
    web_login=False,
    store_env=None,
):
    """Return the authentication serialised root and discharge macaroons."""
    if web_login:
        root, discharge = _get_store_authorization_using_candid(
            permissions=permissions,
            channels=channels,
            allowed_stores=allowed_stores,
            snaps=snaps,
            store_env=store_env,
        )
    else:
        root, discharge = _get_store_authorization(
            email,
            permissions=permissions,
            channels=channels,
            allowed_stores=allowed_stores,
            snaps=snaps,
            store_env=store_env,
        )

    return root, discharge


def get_authorization_header(root, discharge, store_env=None):
    """Bind root and discharge returning the authorization header."""
    root = Macaroon.deserialize(root)
    if discharge is not None:
        discharge = Macaroon.deserialize(discharge)
        if discharge.location == CONSTANTS[store_env]["sso_location"]:
            # U1 SSO macaroons auth
            bound = root.prepare_for_request(discharge)
            authorization = "Macaroon root={}, discharge={}".format(
                root.serialize(), bound.serialize()
            )
            return {"Authorization": authorization}
        else:
            # to-be-deprecated: kept for backwards compatibility and
            # existing Candid macaroons
            return _get_bakery_auth_header(root, discharge)
    else:
        # snapstore-only macaroon auth
        authorization = "Macaroon {}".format(root.serialize())
        return {"Authorization": authorization}


def get_refreshed_discharge(discharge, store_env):
    headers = DEFAULT_HEADERS.copy()
    data = {"discharge_macaroon": discharge}
    response = requests.request(
        url="{}/api/v2/tokens/refresh".format(
            CONSTANTS[store_env]["sso_base_url"]
        ),
        method="POST",
        json=data,
        headers=headers,
    )
    return response.json()["discharge_macaroon"]


def store_request(config, **kwargs):
    r = requests.request(**kwargs)

    # Refresh discharge if necessary.
    # (only for U1 SSO macaroons for now, in practice)
    if r.headers.get("WWW-Authenticate") == "Macaroon needs_refresh=1":
        discharge = get_refreshed_discharge(config.discharge, config.store_env)
        config = ClientConfig(
            root=config.root,
            discharge=discharge,
            store_env=config.store_env,
            path=config.path,
        )
        save_config(config)
        headers = kwargs.get("headers", {})
        auth_header = get_authorization_header(
            config.root, config.discharge, store_env=config.store_env
        )
        headers.update(auth_header)
        r = requests.request(**kwargs)

    return r


def main():
    auth_dir = os.path.abspath(os.environ.get("SNAP_USER_COMMON", "."))

    parser = argparse.ArgumentParser(description="S(tore)URL ...")

    try:
        config, remainder = get_config_from_cli(parser, auth_dir)
    except CliError as e:
        print(e)
        return 1
    except CliDone:
        return 0

    # Extra CLI options
    parser.add_argument(
        "-v",
        "--debug",
        action="store_true",
        help="Prints request and response headers",
    )

    # Request options.
    parser.add_argument(
        "-H", "--header", action="append", default=[], dest="headers"
    )
    parser.add_argument(
        "-X",
        "--method",
        default="GET",
        choices=["GET", "PATCH", "POST", "PUT"],
    )
    parser.add_argument("-d", "--data")

    parser.add_argument("url", nargs="?")

    args = parser.parse_args(remainder)

    if args.debug:
        # # The http.client logger pollutes stdout.
        # from http.client import HTTPConnection
        # HTTPConnection.debuglevel = 1
        import logging

        handler = requests.packages.urllib3.add_stderr_logger()
        handler.setFormatter(logging.Formatter("\033[1m%(message)s\033[0m"))

    headers = DEFAULT_HEADERS.copy()
    if args.url is None:
        url = "{}/api/v2/tokens/whoami".format(
            CONSTANTS[config.store_env]["sca_base_url"]
        )
        method = "GET"
        data = None
    else:
        url = args.url
        if args.data is not None:
            if args.data.startswith("@"):
                with open(os.path.expanduser(args.data[1:])) as fd:
                    data = json.load(fd)
            else:
                data = json.loads(args.data)
            method = args.method
            if args.method == "GET":
                method = "POST"
        else:
            data = None
            method = args.method
    auth_header = get_authorization_header(
        config.root, config.discharge, store_env=config.store_env
    )
    headers.update(auth_header)
    for h in args.headers:
        try:
            k, v = [t.strip() for t in h.split(":")]
        except ValueError:
            print('Invalid header: "{}"'.format(h))
            return 1
        headers[k] = v

    if args.debug:
        print(
            "\033[1m******** request headers ********\033[0m",
            file=sys.stderr,
            flush=True,
        )
        for k, v in headers.items():
            print("{}: {}".format(k, v), file=sys.stderr, flush=True)
        print(
            "\033[1m**********************************\033[0m",
            file=sys.stderr,
            flush=True,
        )

    response = store_request(
        config, url=url, method=method, json=data, headers=headers, stream=True
    )

    if args.debug:
        print(
            "\033[1m******** response headers ********\033[0m",
            file=sys.stderr,
            flush=True,
        )
        print(
            "HTTP/1.1 {} {}".format(response.status_code, response.reason),
            file=sys.stderr,
            flush=True,
        )
        for k, v in response.headers.items():
            print("{}: {}".format(k, v), file=sys.stderr, flush=True)
        print(
            "\033[1m**********************************\033[0m",
            file=sys.stderr,
            flush=True,
        )

    for chunk in response.iter_content(chunk_size=1024 * 8):
        if chunk:
            sys.stdout.buffer.write(chunk)

    # Flush STDOUT carefully, because PIPE might be broken.
    def _noop(*args, **kwargs):
        pass

    try:
        sys.stdout.buffer.flush()
    except (BrokenPipeError, IOError):
        sys.stdout.write = _noop
        sys.stdout.flush = _noop
        return 1

    return 0
