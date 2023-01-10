import argparse
import base64
import getpass
import json
import os
import subprocess
import sys

from collections import namedtuple

import requests

from craft_store import endpoints, StoreClient, UbuntuOneStoreClient
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
    "user-agent": "surl/{}".format(os.environ.get("SNAP_VERSION", "devel")),
    "accept": "application/json, application/hal+json",
    "content-type": "application/json",
    "cache-control": "no-cache",
}

CONSTANTS = {
    "local": {
        "sso_location": os.environ.get("SURL_SSO_LOCATION", "login.staging.ubuntu.com"),
        "sso_base_url": os.environ.get(
            "SURL_SSO_BASE_URL", "https://login.staging.ubuntu.com"
        ),
        "sca_base_url": os.environ.get(
            "SURL_SCA_BASE_URL", "http://sca-focal.lxd:8000"
        ),
        "pubgw_base_url": os.environ.get(
            "SURL_PUBGW_BASE_URL", "http://publishergw-focal.lxd:8010"
        ),
        "api_base_url": os.environ.get(
            "SURL_API_BASE_URL", "http://sca-focal.lxd:8000"
        ),
    },
    "staging": {
        "sso_location": "login.staging.ubuntu.com",
        "sso_base_url": "https://login.staging.ubuntu.com",
        "sca_base_url": os.environ.get(
            "SURL_SCA_ROOT_URL", "https://dashboard.staging.snapcraft.io"
        ),
        "pubgw_base_url": os.environ.get(
            "SURL_PUBGW_ROOT_URL", "https://api.staging.charmhub.io"
        ),
        "api_base_url": os.environ.get(
            "SURL_API_ROOT_URL", "https://api.staging.snapcraft.io"
        ),
    },
    "production": {
        "sso_location": "login.ubuntu.com",
        "sso_base_url": "https://login.ubuntu.com",
        "sca_base_url": "https://dashboard.snapcraft.io",
        "pubgw_base_url": "https://api.charmhub.io",
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

CHARMHUB_PERMISSIONS = [
    "account-register-package",
    "account-view-packages",
    "package-manage",
    "package-manage-acl",
    "package-manage-metadata",
    "package-manage-releases",
    "package-manage-revisions",
    "package-view",
    "package-view-acl",
    "package-view-metadata",
    "package-view-metrics",
    "package-view-releases",
    "package-view-revisions",
]


class ConfigError(Exception):
    pass


class CliError(Exception):
    pass


class CliDone(Exception):
    pass


ClientConfig = namedtuple(
    "ClientConfig", ["root", "discharge", "store_env", "store_type", "path"]
)


def load_config(path):
    with open(path) as fd:
        try:
            a = json.load(fd)
            root, discharge, store_env, store_type = (
                a["root"],
                a["discharge"],
                a["store"],
                a.get("type", "snapcraft"),
            )
        except json.decoder.JSONDecodeError:
            raise ConfigError()
    return ClientConfig(
        root=root,
        discharge=discharge,
        store_env=store_env,
        store_type=store_type,
        path=path,
    )


def save_config(config):
    payload = {
        "root": config.root,
        "discharge": config.discharge,
        "store": config.store_env,
        "type": config.store_type,
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


def get_package_from_name(name):
    try:
        package_type, package_name = name.split(":")
        return endpoints.Package(package_name, package_type)
    except ValueError:
        return endpoints.Package(name, "snap")


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

    # Overrides the choice determined by the URL
    parser.add_argument(
        "-s",
        "--store",
        choices=["staging", "production", "local"],
    )
    parser.add_argument("-t", dest="type", choices=["charmhub", "snapcraft"])

    # Macaroon restricting options.
    parser.add_argument(
        "-p",
        "--permission",
        action="append",
        dest="permissions",
        choices=SCA_PERMISSIONS + CHARMHUB_PERMISSIONS,
    )
    parser.add_argument(
        "-c",
        "--channel",
        action="append",
        dest="channels",
        choices=["stable", "candidate", "beta", "edge"],
    )
    parser.add_argument(
        "--package",
        action="append",
        dest="packages",
        help=(
            "Indicate the name of the package on which the restricted auth "
            "can work. Can be used several times to indicate multiple "
            "packages."
        ),
    )

    parser.add_argument("url", nargs="?")

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

        return args.url, config, remainder

    store_env, store_type = get_environment_from_url(args.url)

    if args.store:
        store_env = args.store

    if args.type:
        store_type = args.type

    if store_type == "snapcraft":
        default_permission = "package_access"
    else:
        default_permission = "package-view"

    packages = (
        [get_package_from_name(name) for name in args.packages] if args.packages else []
    )

    permissions = args.permissions or [default_permission]

    credentials = None
    if not args.web_login and args.email is None:
        raise CliError('Needs "-e <email>" or $STORE_EMAIL.')
    if not args.web_login and store_type == "charmhub":
        raise CliError("Charmhub only supports web-login.")
    try:
        password = None
        otp = None

        store_client = get_client(args.web_login, store_env, store_type)
        if not args.web_login:
            password = getpass.getpass(f"Password for {args.email}: ")
            if store_env == "production":
                otp = input(f"Second-factor auth for {store_env}: ")

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

    decoded_credentials = base64.b64decode(credentials)
    try:
        credentials = json.loads(decoded_credentials)

        if credentials.get("t") == "macaroon":
            root = credentials["v"]
            discharge = None
        elif credentials.get("t") == "u1-macaroon":
            root = credentials["v"]["r"]
            discharge = credentials["v"]["d"]
        else:
            root = credentials["r"]
            discharge = credentials["d"]
    except json.decoder.JSONDecodeError:
        # Charmhub just returns the raw credentials, so attempting to parse it fails
        root = decoded_credentials.decode()
        discharge = None

    config = ClientConfig(
        root=root,
        discharge=discharge,
        store_env=store_env,
        store_type=store_type,
        path=auth_path,
    )

    if auth_path is not None:
        save_config(config)

    return args.url, config, remainder


def get_environment_from_url(url):
    # The assumption that localhost is SCA can be overriden by a command-line
    # argument.
    if ":8000" in url:
        return "local", "snapcraft"
    elif ":8010" in url:
        return "local", "charmhub"
    elif "staging.snapcraft" in url:
        return "staging", "snapcraft"
    elif "staging.charmhub" in url:
        return "staging", "charmhub"
    elif "dashboard.snapcraft" in url or "api.snapcraft" in url:
        return "production", "snapcraft"
    elif "api.charmhub" in url:
        return "production", "charmhub"
    else:
        return "staging", "snapcraft"


# Note that store_env only exists to make surl_metrics (and possibly others) happy
def get_authorization_header(root, discharge, store_env=None):
    """Return the required authorization header.

    This is done possibly binding the root and discharge"""
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


def get_client(web_login, store_env, store_type):
    common_args = dict(
        base_url=CONSTANTS[store_env]["sca_base_url"]
        if store_type == "snapcraft"
        else CONSTANTS[store_env]["pubgw_base_url"],
        storage_base_url="https://storage.staging.snapcraftcontent.com",
        user_agent=DEFAULT_HEADERS["user-agent"],
        application_name="surl",
        environment_auth="CREDENTIALS",
        ephemeral=True,
    )
    if web_login:
        return StoreClient(
            endpoints=endpoints.SNAP_STORE
            if store_type == "snapcraft"
            else endpoints.CHARMHUB,
            **common_args,
        )
    else:
        return UbuntuOneStoreClient(
            endpoints=endpoints.U1_SNAP_STORE,
            auth_url=CONSTANTS[store_env]["sso_base_url"],
            **common_args,
        )


def store_request(config, **kwargs):
    r = requests.request(**kwargs)

    return r


def main():
    auth_dir = os.path.abspath(os.environ.get("SNAP_USER_COMMON", "."))

    parser = argparse.ArgumentParser(description="S(tore)URL ...")

    try:
        url, config, remainder = get_config_from_cli(parser, auth_dir)
    except CliError as e:
        print(e)
        return 1
    except CliDone:
        return 0

    parser.add_argument("-H", "--header", action="append", default=[], dest="headers")

    args, remainder = parser.parse_known_args()

    headers = DEFAULT_HEADERS.copy()
    if url is None:
        if config.store_type == "snapcraft":
            url = "{}/api/v2/tokens/whoami".format(
                CONSTANTS[config.store_env]["sca_base_url"]
            )
        else:
            url = "{}/v1/tokens/whoami".format(
                CONSTANTS[config.store_env]["pubgw_base_url"]
            )

    auth_header = get_authorization_header(config.root, config.discharge)
    headers.update(auth_header)

    # -s hides progress bar and errors, -S brings the errors back, -L follows
    # redirects, and --output - prints binary output to terminal
    arguments = ["curl", "-sSL", "--output", "-"]

    for item in args.headers:
        try:
            k, v = [t.strip() for t in item.split(":")]
        except ValueError:
            print('Invalid header: "{}"'.format(item))
            return 1
        headers[k.lower()] = v

    for header, value in headers.items():
        arguments.append("-H")
        arguments.append(f"{header}: {value}")

    arguments.extend(remainder)
    arguments.append(url)

    result = subprocess.run(arguments, stderr=subprocess.STDOUT)

    # Flush STDOUT carefully, because PIPE might be broken.
    def _noop(*args, **kwargs):
        pass

    try:
        sys.stdout.buffer.flush()
    except (BrokenPipeError, IOError):
        sys.stdout.write = _noop
        sys.stdout.flush = _noop
        return 1

    return result.returncode
