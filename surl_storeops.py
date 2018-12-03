#!/usr/bin/env python3

import argparse
import datetime
import iso8601
import json
import logging
import os
import requests
import sys

import surl


logging.basicConfig(format='\033[3;1m%(message)s\033[0m')
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def _make_partition(seq, size):
    for i in range(0, len(seq), size):
        yield seq[i:i+size]


def _get_search_results(config):
    headers = surl.DEFAULT_HEADERS.copy()
    headers['Authorization'] = surl.get_authorization_header(
        config.root, config.discharge)

    snaps = []
    url = (
        '{}/api/v1/snaps/search?size=250&scope=wide&arch=wide&'
        'confinement=strict,classic,devmode&'
        'fields=snap_id,channel,confinement,media,origin,developer_validation,'
         'date_published,last_updated,sections'
        .format(surl.CONSTANTS[config.store_env]['api_base_url']))

    while url is not None:
        r = surl.store_request(config, method='get', url=url, headers=headers)
        r.raise_for_status()
        payload = r.json()

        snaps.extend(payload['_embedded']['clickindex:package'])

        # XXX store is returning an 'http' (no 's').
        _next = payload['_links'].get('next')
        url = _next['href'] if _next is not None else None

    return snaps


def _get_snap_metrics(filters, config):
    headers = surl.DEFAULT_HEADERS.copy()
    headers['Authorization'] = surl.get_authorization_header(
        config.root, config.discharge)

    url = '{}/dev/api/snaps/metrics'.format(
        surl.CONSTANTS[config.store_env]['sca_base_url'])

    metrics = []
    for partition in _make_partition(filters, 400):
        payload = {"filters": partition}
        r = surl.store_request(config, method='post', url=url, json=payload, headers=headers)
        r.raise_for_status()
        metrics.extend(r.json()['metrics'])

    return metrics


def format_date(timestamp):
    return iso8601.parse_date(timestamp).date().isoformat()


def fetch_snaps(config):
    logger.info('Fetching snaps ...')
    snaps = _get_search_results(config)

    logger.info('Got {} snaps'.format(len(snaps)))

    snap_map = {
        s['snap_id']: {
            'snap_name': s['package_name'],
            'snap_id': s['snap_id'],
            'channel': s['channel'],
            'confinement': s['confinement'],
            'sections': [sec['name'] for sec in s['sections']],
            'media': s['media'],
            'created_at': format_date(s['date_published']),
            'last_uploaded_at': format_date(s['last_updated']),
            'developer_validation': s['developer_validation'],
            'developer_username': s['origin']
        } for s in snaps
    }

    yesterday = datetime.datetime.utcnow().date() - datetime.timedelta(1)
    start = end = yesterday.isoformat()
    filters = [{
        'metric_name': 'weekly_installed_base_by_channel',
        'snap_id': snap_id, "start": start, "end": end
    } for snap_id in snap_map.keys()]

    logger.info('Fetching metrics ...')
    metrics = _get_snap_metrics(filters, config)
    for m in metrics:
        snap_map[m['snap_id']].update({
            'installed_base': sum([sum(ch['values']) for ch in m['series']]),
        })

    return {
        'snaps': list(snap_map.values()),
    }


def main():
    parser = argparse.ArgumentParser(
        description='Snap store operations ...'
    )

    auth_dir = os.path.abspath(os.environ.get('SNAP_USER_COMMON', '.'))
    try:
        config, remainder = surl.get_config_from_cli(parser, auth_dir)
    except surl.CliError as e:
        print(e)
        return 1
    except surl.CliDone:
        return 0

    ACTIONS = {
        'snaps': fetch_snaps,
    }

    parser.add_argument(
        '-v', '--debug', action='store_true',
        help='Prints request and response headers')
    parser.add_argument(
        'action', nargs='?', default='snaps', choices=ACTIONS.keys())
    args = parser.parse_args(remainder)

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        requests_log = logging.getLogger("requests.packages.urllib3")
        requests_log.setLevel(logging.DEBUG)
        requests_log.propagate = True

    json.dump(ACTIONS[args.action](config), sys.stdout)

    # Flush STDOUT carefully, because PIPE might be broken.
    def _noop(*args, **kwargs):
        pass

    try:
        sys.stdout.buffer.flush()
    except (BrokenPipeError, IOError):
        sys.stdout.write = _noop
        sys.stdout.flush = _noop
        return 1


if __name__ == '__main__':
    sys.exit(main())
