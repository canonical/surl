#!/usr/bin/env python3

import argparse
import datetime
import logging
import os
import requests
import urllib
import sys
import surl
import json
import functools
import copy
from tenacity import retry, stop_after_attempt, retry_if_exception_type

# Schema:
# channelMapWithMetrics = {
#     'channelMap': [
#         {
#             'channel': {
#               'track': 'latest',
#               'risk': 'edge'
#             },
#             'weeklyActive1moDelta': 3,
#             'weeklyActive': 100,
#             'versions': [
#                 '1.3'
#             ]
#         }
#     ],
#     'weeklyActive1moDelta': 3,
#     'weeklyActive': 100,
# }
# snapName = 'package_name'
# snapIconURL = 'icon_url'
# snapStoreAccountID = 'developer_id'
# unused = 'snap_id'


logging.basicConfig(format="\033[3;1m%(message)s\033[0m")
logger = logging.getLogger()
logger.setLevel(logging.INFO)


class MarketoTokenExpired(Exception):
    pass


class MarketoSystemError(Exception):
    pass


class SnapNotFound(Exception):
    pass


@retry(
    reraise=True,
    stop=stop_after_attempt(3),
    retry=(retry_if_exception_type(requests.exceptions.HTTPError) | retry_if_exception_type(requests.exceptions.ConnectionError)),
)
def get_snap_info(snap_name, config):
    headers = surl.DEFAULT_HEADERS.copy()
    headers["Authorization"] = surl.get_authorization_header(
        config.root, config.discharge
    )
    headers["Snap-Device-Series"] = "16"

    url = "{}/v2/snaps/info/{}".format(
        surl.CONSTANTS[config.store_env]["api_base_url"], snap_name
    )
    r = requests.get(url=url, headers=headers)
    if r.status_code == 404:
        raise SnapNotFound()
    else:
        r.raise_for_status()
        return r.json()


def _get_channel_parts(channel):
    risks = ("stable", "candidate", "beta", "edge")
    parts = channel.split("/")
    count = len(parts)
    branch = ""

    if count == 1:
        track = "latest"
        risk = parts[0]
    elif count == 2 and parts[1] in risks:
        track = parts[0]
        risk = parts[1]
    elif count == 2 and parts[0] in risks:
        track = "latest"
        risk = parts[0]
        branch = parts[1]
    elif count == 3:
        track = parts[0]
        risk = parts[1]
        branch = parts[2]
    else:
        raise ValueError("Too many parts to channel: {}".format(channel))
    return (track, risk, branch)


def get_channel_metrics(snap_id, config):
    """
    channelMapWithMetrics = {
        'channelMap': [
            {
                'channel': {
                    'track': 'latest',
                    'risk': 'edge'
                },
                'weeklyActive1moDelta': 3,
                'weeklyActive': 100
            }
        ]
    }
    """

    headers = surl.DEFAULT_HEADERS.copy()
    headers["Authorization"] = surl.get_authorization_header(
        config.root, config.discharge
    )

    now = datetime.datetime.utcnow()
    # Account for time spent mining the metrics daily (~4h)
    yesterday = now - datetime.timedelta(days=1, hours=4)
    start = end = yesterday.date().isoformat()
    payload = {
        "filters": [
            {
                "metric_name": "weekly_installed_base_by_channel",
                "snap_id": snap_id,
                "start": start,
                "end": end,
            }
        ]
    }

    url = "{}/dev/api/snaps/metrics".format(
        surl.CONSTANTS[config.store_env]["sca_base_url"]
    )

    current = requests.post(url=url, json=payload, headers=headers)
    if current.status_code != requests.codes.ok:
        print(current.headers)
        print(current.text)
    current.raise_for_status()
    current = current.json()

    # FIXME this should be a month, not 30 days.
    month_prev = yesterday - datetime.timedelta(days=30)
    month_prev = month_prev.date().isoformat()
    payload["filters"][0]["start"] = month_prev
    payload["filters"][0]["end"] = month_prev
    old = requests.post(url=url, json=payload, headers=headers)
    old.raise_for_status()
    old = old.json()

    data = []
    for series_current in current["metrics"][0]["series"]:
        name = series_current["name"]
        weekly_active = series_current["values"][0]
        # If no data from the previous month, initialise to this month.
        delta = weekly_active
        for series_old in old["metrics"][0]["series"]:
            if series_old["name"] == name:
                delta = series_current["values"][0] - series_old["values"][0]
                break
        track, risk, branch = _get_channel_parts(name)
        channel = {"track": track, "risk": risk}
        if branch:
            channel["branch"] = branch
        data.append(
            {
                "channel": channel,
                "weeklyActive": weekly_active,
                "weeklyActive1moDelta": delta,
            }
        )

    return {"channelMap": data}


def add_weekly_active_totals(snaps):
    for snap in snaps:
        channel_map = snap["channelMapWithMetrics"]["channelMap"]

        delta = sum(channel["weeklyActive1moDelta"] for channel in channel_map)
        snap["channelMapWithMetrics"]["weeklyActive1moDelta"] = delta

        active = sum(channel["weeklyActive"] for channel in channel_map)
        snap["channelMapWithMetrics"]["weeklyActive"] = active


def add_missing_channels(snaps):
    """The metrics API will not return channels without subscribers.
       As not showing some channels may confuse readers, fill in the missing
       channels.
    """

    for snap in snaps:
        channel_map = snap["channelMapWithMetrics"]["channelMap"]
        for risk in ("stable", "candidate", "beta", "edge"):
            found = False
            for channel in channel_map:
                if channel["channel"]["track"] != "latest":
                    continue
                if channel["channel"]["risk"] != risk:
                    continue
                if channel["channel"].get("branch"):
                    continue

                found = True
                break

            if not found:
                channel_map.append(
                    {
                        "channel": {"track": "latest", "risk": risk},
                        "weeklyActive": 0,
                        "weeklyActive1moDelta": 0,
                    }
                )


def _channel_cmp(a, b):
    """Key function to sort channel names.

       Sorts as:
       latest/stable
       latest/stable/hotfix
       latest/candidate
       latest/beta
       latest/edge
       ingest/stable
       10/stable
       10/candidate
       9/stable
    """
    channels = {"stable": 4, "candidate": 3, "beta": 2, "edge": 1}
    if a == b:
        return 0

    if a["track"] == "latest" and b["track"] != "latest":
        return -1
    if a["track"] != "latest" and b["track"] == "latest":
        return 1
    if a["track"] > b["track"]:
        return -1
    if a["track"] < b["track"]:
        return 1
    if a["track"] == b["track"]:
        if a["risk"] != b["risk"]:
            return channels[b["risk"]] - channels[a["risk"]]
        else:
            if a.get("branch", "") > b.get("branch", ""):
                return 1
            else:
                return -1


def sort_metrics_by_channel(metrics):
    keyfunc = functools.cmp_to_key(
        lambda a, b: _channel_cmp(a["channel"], b["channel"])
    )
    return sorted(metrics, key=keyfunc)


def get_snaps(config):
    headers = surl.DEFAULT_HEADERS.copy()

    snaps = []
    url = (
        "{}/api/v1/snaps/search?size=250&scope=wide&"
        "confinement=strict,classic,devmode&"
        "fields=snap_id,developer_id,media".format(
            surl.CONSTANTS[config.store_env]["api_base_url"]
        )
    )

    while url is not None:
        r = requests.get(url=url, headers=headers)
        if r.status_code == 503:
            print("Headers: {}".format(r.headers))
            print("Response: {}".format(r.text))
        r.raise_for_status()
        payload = r.json()

        snaps.extend(payload["_embedded"]["clickindex:package"])

        _next = payload["_links"].get("next")
        url = _next["href"] if _next is not None else None

    return snaps


def add_toplevel_metadata(source, target):
    for snap in source:
        obj = {
            "snapName": snap["package_name"],
            "snapStoreAccountID": snap["developer_id"],
            "snapID": snap["snap_id"],
        }
        for media in snap["media"]:
            if media["type"] == "icon":
                obj["snapIconURL"] = media["url"]
                break
        target.append(obj)


def add_channel_map_metrics(snaps, config):
    """
    channelMapWithMetrics = {
        'channelMap': [
            {
                'channelName': 'latest/edge',
                'weeklyActive1moDelta': 3,
                'versions': [
                    '3.2.10'
                ]
            }
        ]
    }
    """
    for snap in snaps:
        snap_id = snap["snapID"]
        snap["channelMapWithMetrics"] = get_channel_metrics(snap_id, config)


def sort_channels(snaps):
    for snap in snaps:
        channel_metrics = snap["channelMapWithMetrics"]
        sorted_channels = sort_metrics_by_channel(channel_metrics["channelMap"])
        channel_metrics["channelMap"] = sorted_channels


def add_channel_map_versions(snaps, config) -> list:
    """
    channelMapWithMetrics = {
        'channelMap': [
            {
                'channel': {
                    'track': 'latest',
                    'risk': 'edge'
                },
                'versions': [
                    '1.3'
                ]
            }
        ]
    }
    """
    for snap in snaps:
        try:
            snap_info = get_snap_info(snap["snapName"], config)
        except SnapNotFound:
            # If a snap is set to only show in a specific territory (that this
            # code is not running in), a 404 error will be returned.
            continue
        channels = {}
        for c in snap_info["channel-map"]:
            name = "{}/{}".format(c["channel"]["track"], c["channel"]["risk"])
            version = c["version"]
            if name not in channels:
                channels[name] = []
            if version not in channels[name]:
                channels[name].append(version)

        for channel in channels:
            track, risk = channel.split("/")
            for c in snap["channelMapWithMetrics"]["channelMap"]:
                if c["channel"]["track"] == track and c["channel"]["risk"] == risk:
                    c["versions"] = channels[channel]
                    break


def _refresh_discharge(config):
    headers = surl.DEFAULT_HEADERS.copy()
    headers["Authorization"] = surl.get_authorization_header(
        config.root, config.discharge
    )

    url = "{}/dev/api/account".format(surl.CONSTANTS[config.store_env]["sca_base_url"])

    r = requests.get(url=url, headers=headers)
    if r.headers.get("WWW-Authenticate") == ("Macaroon needs_refresh=1"):
        discharge = surl.get_refreshed_discharge(config.discharge, config.store_env)
        config = surl.ClientConfig(
            root=config.root,
            discharge=discharge,
            store_env=config.store_env,
            path=config.path,
        )
        surl.save_config(config)

    return config


def _get_marketo_access_token(config):
    url = urllib.parse.urljoin(config.marketo_root, "/identity/oauth/token")
    params = {
        "grant_type": "client_credentials",
        "client_id": config.marketo_client_id,
        "client_secret": config.marketo_secret,
    }
    url += "?" + urllib.parse.urlencode(params)
    response = requests.get(url)
    response.raise_for_status()
    return response.json()["access_token"]


def _check_marketo_response(response):
    response.raise_for_status()
    response_json = response.json()
    if not response_json["success"]:
        if response_json["errors"][0]["code"] == "602":
            raise MarketoTokenExpired()
        elif response_json["errors"][0]["code"] == "611":
            raise MarketoSystemError()
        else:
            raise Exception(response.text)

    if response.request.method != "GET":
        result = response_json["result"][0]
        status = result.get("status")
        if status == "skipped":
            if result["reasons"][0]["message"] == "Lead not found":
                # We cannot update custom objects for leads that do not exist.
                return
        if status and status not in ("created", "updated", "deleted"):
            raise Exception(response.text)


@retry(
    reraise=True,
    stop=stop_after_attempt(3),
    retry=retry_if_exception_type(MarketoSystemError),
)
def post_to_marketo(snap, token, config):
    headers = {"Content-Type": "application/json; charset=UTF-8"}
    path = "/rest/v1/customobjects/snap_c.json"
    url = urllib.parse.urljoin(config.marketo_root, path)
    params = {"access_token": token}
    url += "?" + urllib.parse.urlencode(params)
    payload = {"input": [snap]}
    response = requests.post(url, json=payload, headers=headers)
    _check_marketo_response(response)


def update_marketo_objects(snaps, config):
    token = _get_marketo_access_token(config)
    for snap in snaps:
        try:
            post_to_marketo(snap, token, config)
        except MarketoTokenExpired:
            token = _get_marketo_access_token(config)
            post_to_marketo(snap, token, config)


def mangle_for_marketo(snaps, minimum=10):
    """Filter out snaps that are not released to any channel or have fewer
       installs than the specified minimum (setting their metrics to empty).
       Reformat data for Marketo as key/string pairs."""

    mangled = copy.deepcopy(snaps)
    for snap in mangled:
        metrics = snap["channelMapWithMetrics"]
        if metrics["channelMap"] and metrics["weeklyActive"] >= minimum:
            snap["channelMapWithMetrics"] = json.dumps(metrics)
        else:
            snap["channelMapWithMetrics"] = ""
        del snap["snapID"]
    return mangled


def main():
    parser = argparse.ArgumentParser(description="Month in snaps ...")
    auth_dir = os.path.abspath(os.environ.get("SNAP_USER_COMMON", "."))
    try:
        config, remainder = surl.get_config_from_cli(parser, auth_dir)
    except surl.CliError as e:
        print(e)
        return 1
    except surl.CliDone:
        return 0

    parser.add_argument("--marketo-root", required=False)
    parser.add_argument("--marketo-client-id", required=False)
    parser.add_argument("--snap-name", required=False)
    parser.add_argument("--snap-id", required=False)
    parser.add_argument("--developer-id", required=False)
    additional_config = parser.parse_args(remainder)
    if additional_config.marketo_root:
        try:
            additional_config.marketo_secret = os.environ["MARKETO_SECRET"]
        except KeyError:
            print("Set MARKETO_SECRET and try again.", file=sys.stderr)
            return 1

    config = _refresh_discharge(config)
    snaps = []
    logging.info("getting snaps")
    if (
        additional_config.snap_id
        and additional_config.snap_name
        and additional_config.developer_id
    ):
        logging.info("only updating {}".format(additional_config.snap_name))
        source_snaps = [
            {
                "package_name": additional_config.snap_name,
                "developer_id": additional_config.developer_id,
                "snap_id": additional_config.snap_id,
                "media": [],  # FIXME
            }
        ]
    else:
        source_snaps = get_snaps(config)
    add_toplevel_metadata(source_snaps, snaps)
    logging.info("getting metrics")
    add_channel_map_metrics(snaps, config)
    add_weekly_active_totals(snaps)
    add_missing_channels(snaps)
    sort_channels(snaps)
    logging.info("getting versions")
    add_channel_map_versions(snaps, config)
    if additional_config.marketo_secret:
        logging.info("updating marketo")
        update_marketo_objects(mangle_for_marketo(snaps), additional_config)
    else:
        import pprint
        pprint.pprint(json.dumps(snaps))
    return 0


if __name__ == "__main__":
    sys.exit(main())
