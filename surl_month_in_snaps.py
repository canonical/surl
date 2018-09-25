#!/usr/bin/env python3

import argparse
import datetime
import logging
import os
import requests
import sys
import surl

# Schema:
# channelMapWithMetrics = {
#     'channelMap': [
#         {
#             'channelName': 'latest/edge',
#             'weeklyActive1moDelta': 3,
#             'weeklyActive': 100,
#             'versions': [
#                 {
#                     'version': '1.3',
#                     'architectures': ['i386', 'amd64']
#                 }
#             ]
#         }
#     ],
#     'weeklyActive1moDelta': 3,
#     'weeklyActive': 100,
# }
# snapName = 'package_name'
# snapIconUrl = 'icon_url'
# snapStoreAccountID = 'developer_id'
# unused = 'snap_id'


logging.basicConfig(format='\033[3;1m%(message)s\033[0m')
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def get_snap_info(snap_name, config):
    headers = surl.DEFAULT_HEADERS.copy()
    headers['Authorization'] = surl.get_authorization_header(
        config.root, config.discharge)
    headers['Snap-Device-Series'] = '16'

    url = '{}/v2/snaps/info/{}'.format(
        surl.CONSTANTS[config.store_env]['api_base_url'], snap_name)
    r = requests.get(url=url, headers=headers)
    r.raise_for_status()
    return r.json()

def _acceptable_channel_name(name):
    if name.count('/') > 1:
        # We don't want to show branches.
        return False
    risk_with_branch = (
        'stable/',
        'candidate/',
        'beta/',
        'edge/',
    )
    if any([name.startswith(x) for x in risk_with_branch]):
        # We don't want to show branches of the 'latest' track.
        return False
    
    return True


def get_channel_metrics(snap_id, config):
    '''
    channelMapWithMetrics = {
        'channelMap': [
            {
                'channelName': 'latest/edge',
                'weeklyActive1moDelta': 3,
                'weeklyActive': 100
            }
        ]
    }
    '''

    headers = surl.DEFAULT_HEADERS.copy()
    headers['Authorization'] = surl.get_authorization_header(
        config.root, config.discharge)

    now = datetime.datetime.utcnow()
    # Account for time spent mining the metrics daily (~4h)
    yesterday = now - datetime.timedelta(days=1, hours=4)
    start = end = yesterday.date().isoformat()
    payload = {
        'filters': [{
            'metric_name': 'weekly_installed_base_by_channel',
            'snap_id': snap_id,
            'start': start,
            'end': end
        }]
    }

    url = '{}/dev/api/snaps/metrics'.format(
        surl.CONSTANTS[config.store_env]['sca_base_url']
    )

    current = requests.post(url=url, json=payload, headers=headers)
    current.raise_for_status()
    current = current.json()

    month_prev = yesterday - datetime.timedelta(days=30)
    month_prev = month_prev.date().isoformat()
    payload['filters'][0]['start'] = month_prev
    payload['filters'][0]['end'] = month_prev
    old = requests.post(url=url, json=payload, headers=headers)
    old.raise_for_status()
    old = old.json()

    data = []
    for series_current in current['metrics'][0]['series']:
        name = series_current['name']
        if not _acceptable_channel_name(name):
            continue
        weekly_active = series_current['values'][0]
        # If no data from the previous month, initialise to this month.
        delta = weekly_active
        for series_old in old['metrics'][0]['series']:
            if series_old['name'] == name:
                delta = series_current['values'][0] - series_old['values'][0]
                break
        if '/' not in name:
            name = 'latest/{}'.format(name)
        data.append({
            'channelName': name,
            'weeklyActive': weekly_active,
            'weeklyActive1moDelta': delta,
        })
    
    return {
        'channelMap': data,
    }


def add_weekly_active_totals(snaps):
    for snap in snaps:
        channel_map = snap['channelMapWithMetrics']['channelMap']
        delta = sum(channel['weeklyActive1moDelta'] for channel in channel_map)
        snap['channelMapWithMetrics']['weeklyActive1moDelta'] = delta
        active = sum(channel['weeklyActive'] for channel in channel_map)
        snap['channelMapWithMetrics']['weeklyActive'] = active


def _channel_sort(channel):
    '''Key function to sort channel names.

       Sorts as:
       latest/stable
       latest/candidate
       latest/beta
       latest/edge
       ingest/stable
       10/stable
       10/candidate
       9/stable
    '''
    channels = {
        'stable': 1,
        'candidate': 2,
        'beta': 3,
        'edge': 4,
    }
    track, risk = channel.split('/')
    if track == 'latest':
        # Lowest ascii character
        track_weight = ' '
    else:
        track_weight = ''
    try:
        # 10/stable, 9/stable, 6/stable, ...
        track = '|{:3f}'.format(1/int(track))
    except ValueError:
        pass
    return '{}{}{}'.format(track_weight, track, channels[risk])


def sort_metrics_by_channel(metrics):
    return sorted(metrics, key=lambda obj: _channel_sort(obj['channelName']))


def get_snaps(config):
    headers = surl.DEFAULT_HEADERS.copy()

    snaps = []
    url = (
        '{}/api/v1/snaps/search?size=500&scope=wide&'
        'confinement=strict,classic,devmode&'
        'fields=snap_id,developer_id,media'
        .format(surl.CONSTANTS[config.store_env]['api_base_url']))

    while url is not None:
        r = requests.get(url=url, headers=headers)
        r.raise_for_status()
        payload = r.json()

        snaps.extend(payload['_embedded']['clickindex:package'])

        _next = payload['_links'].get('next')
        url = _next['href'] if _next is not None else None

    return snaps

def add_toplevel_metadata(source, target):
    for snap in source:
        obj = {
            'snapName': snap['package_name'],
            'snapStoreAccountID': snap['developer_id'],
            'snapID': snap['snap_id'],
        }
        for media in snap['media']:
            if media['type'] == 'icon':
                obj['snapIconUrl'] = media['url']
                break
        target.append(obj)


def add_channel_map_metrics(snaps, config):
    '''
    channelMapWithMetrics = {
        'channelMap': [
            {
                'channelName': 'latest/edge',
                'weeklyActive1moDelta': 3,
                'versions': [
                    {
                        'version': '3.2.10',
                        'architectures': [
                            'amd64'
                        ]
                    }
                ]
            }
        ]
    }
    '''
    for snap in snaps:
        snap_id = snap['snapID']
        channel_metrics = get_channel_metrics(snap_id, config)
        channel_map = channel_metrics['channelMap']
        try:
            channel_metrics['channelMap'] = sort_metrics_by_channel(channel_map)
        except Exception:
            print(channel_map)
            raise
        snap['channelMapWithMetrics'] = channel_metrics


def add_channel_map_versions(snaps, config):
    '''
    channelMapWithMetrics = {
        'channelMap': [
            {
                'channelName': 'latest/edge',
                'versions': [
                    {
                        'version': '1.3',
                        'architectures': ['i386', 'amd64']
                    }
                ]
            }
        ]
    }
    '''
    for snap in snaps:
        snap_info = get_snap_info(snap['snapName'], config)
        channels = {}
        for c in snap_info['channel-map']:
            name = '{}/{}'.format(c['channel']['track'], c['channel']['risk'])
            if name not in channels:
                channels[name] = {}
            version = c['version']
            arch = c['channel']['architecture']
            if version not in channels[name]:
                channels[name][version] = [arch]
            else:
                channels[name][version].append(arch)

        for c in snap['channelMapWithMetrics']['channelMap']:
            for channel in channels:
                if c['channelName'] == channel:
                    if 'versions' not in c:
                        c['versions'] = []
                    for version in channels[channel]:
                        c['versions'].append({
                            'version': version,
                            'architectures': channels[channel][version]
                        })
                    break
                    


def filter_snaps_without_metrics(snaps, minimum=10):
    '''Filter out snaps that are not released to any channel
       or have fewer installs than the specified minimum.
    '''
    return list(
        filter(
            lambda x: (x['channelMapWithMetrics']['channelMap'] and
                       x['channelMapWithMetrics']['weeklyActive'] >= minimum),
            snaps
        )
    )


def _refresh_discharge(config):
    headers = surl.DEFAULT_HEADERS.copy()
    headers['Authorization'] = surl.get_authorization_header(
        config.root, config.discharge)

    url = '{}/dev/api/account'.format(
        surl.CONSTANTS[config.store_env]['sca_base_url'])

    r = requests.get(url=url, headers=headers)
    if r.headers.get('WWW-Authenticate') == (
            'Macaroon needs_refresh=1'):
        discharge = surl.get_refreshed_discharge(
            config.discharge, config.store_env)
        config = surl.ClientConfig(
            root=config.root, discharge=discharge, store_env=config.store_env,
            path=config.path)
        surl.save_config(config)

    return config


def main():
    parser = argparse.ArgumentParser(
        description='Month in snaps ...'
    )
    auth_dir = os.path.abspath(os.environ.get('SNAP_USER_COMMON', '.'))
    try:
        config, _ = surl.get_config_from_cli(parser, auth_dir)
    except surl.CliError as e:
        print(e)
        return 1
    except surl.CliDone:
        return 0
    config = _refresh_discharge(config)
    snaps = []
    logging.info('getting snaps')
    source_snaps = get_snaps(config)[:500] # FIXME
    add_toplevel_metadata(source_snaps, snaps)
    logging.info('getting metrics')
    add_channel_map_metrics(snaps, config)
    add_weekly_active_totals(snaps)
    snaps = filter_snaps_without_metrics(snaps)
    logging.info('getting versions')
    add_channel_map_versions(snaps, config)
    
    import json
    print(json.dumps(snaps))
    return 0
    
if __name__ == '__main__':
    sys.exit(main())
