import argparse
import base64
import datetime
import getpass
import json
import os
import socket
import sys

from collections import namedtuple
from getpass import getpass

import requests

from craft_store import endpoints, errors, StoreClient, UbuntuOneStoreClient
from pymacaroons import Macaroon

name = "surl"

# NOTE: current expiration is 180 days


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
        "sso_location": os.environ.get("SURL_SSO_LOCATION", "login.staging.ubuntu.com"),
        "sso_base_url": os.environ.get(
            "SURL_SSO_BASE_URL", "https://login.staging.ubuntu.com"
        ),
        "sca_base_url": os.environ.get("SURL_SCA_BASE_URL", "http://0.0.0.0:8000"),
        "api_base_url": os.environ.get("SURL_API_BASE_URL", "http://0.0.0.0:8000"),
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

SCA_PERMISSIONS = [
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
    "store_admin",
    "store_review",
]


class ConfigError(Exception):
    pass


class CliError(Exception):
    pass


class CliDone(Exception):
    pass


ClientConfig = namedtuple("ClientConfig", ["root", "discharge", "store_env", "path"])


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
    return ClientConfig(root=root, discharge=discharge, store_env=store_env, path=path)


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
        help="List stored authorizations.",
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
    exclusive_group.add_argument("-e", "--email", default=os.environ.get("STORE_EMAIL"))
    exclusive_group.add_argument("--web-login", action="store_true")

    # NOTE: surl will be smart enough to figure this out
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
        choices=SCA_PERMISSIONS,
    )
    parser.add_argument(
        "-c",
        "--channel",
        action="append",
        dest="channels",
        choices=["stable", "candidate", "beta", "edge"],
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
                "please delete it and login again:\n  $ rm {}".format(auth_path)
            )

        return config, remainder

    # TODO: change this to use either snap or charm based on URL
    packages = (
        [endpoints.Package(name, "snap") for name in args.snaps] if args.snaps else []
    )
    # NOTE: this will go away when we transition to click
    permissions = args.permissions or ["package_access"]

    # NOTE: surl will eventually figure this out based on the URL
    store_env = args.store

    credentials = None
    if not args.web_login and args.email is None:
        raise CliError('Needs "-e <email>" or $STORE_EMAIL.')
    try:
        password = None
        otp = None

        store_client = get_client(args.web_login, args.store)
        if not args.web_login:
            password = getpass(f"Password for {args.email}: ")
            if args.store == "production":
                otp = input(f"Second-factor auth for {args.store}: ")

        credentials = store_client.login(
            permissions=permissions,
            channels=args.channels,
            packages=packages,
            description="surl-client-login",
            ttl=15552000,  # 180 days
            email=args.email,
            password=password,
            otp=otp,
        )
    except CliError:
        raise
    except Exception as e:
        raise CliError("Authorization failed! Double-check password and 2FA. (%s)" % e)

    credentials = json.loads(base64.b64decode(credentials))
    if credentials["t"] == "macaroon":
        root = credentials["v"]
        discharge = None
    elif credentials["t"] == "u1-macaroon":
        root = credentials["v"]["r"]
        discharge = credentials["v"]["d"]

    config = ClientConfig(
        root=root, discharge=discharge, store_env=store_env, path=auth_path
    )

    if auth_path is not None:
        save_config(config)

    return config, remainder


# Note that store_env only exists to make surl_metrics (and possibly others) happy
def get_authorization_header(root, discharge, store_env=None):
    """Return the required authorization header, possibly binding the root and discharge"""
    root = Macaroon.deserialize(root)
    if discharge is not None:
        discharge = Macaroon.deserialize(discharge)
        bound = root.prepare_for_request(discharge)
        authorization = (
            f"macaroon root={root.serialize()}, discharge={bound.serialize()}"
        )
        return {"Authorization": authorization}
    else:
        authorization = f"macaroon {root.serialize()}"
        return {"Authorization": authorization}


def get_client(web_login, store):
    if web_login:
        return StoreClient(
            base_url=CONSTANTS[store]["sca_base_url"],
            storage_base_url="https://storage.staging.snapcraftcontent.com",
            endpoints=endpoints.SNAP_STORE,
            user_agent=DEFAULT_HEADERS["User-Agent"],
            application_name="surl",
            environment_auth="CREDENTIALS",
            ephemeral=True,
        )
    else:
        return UbuntuOneStoreClient(
            base_url=CONSTANTS[store]["sca_base_url"],
            storage_base_url="https://storage.staging.snapcraftcontent.com",
            auth_url=CONSTANTS[store]["sso_base_url"],
            endpoints=endpoints.U1_SNAP_STORE,
            user_agent=DEFAULT_HEADERS["User-Agent"],
            application_name="surl",
            environment_auth="CREDENTIALS",
            ephemeral=True,
        )


def store_request(config, **kwargs):
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
    parser.add_argument("-H", "--header", action="append", default=[], dest="headers")
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

    auth_header = get_authorization_header(config.root, config.discharge)
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
