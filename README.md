# surl
Ubuntu Store API thin wrapper


## Installing

Use `snap`:

    $ snap install surl --channel edge --devmode

*still working to get out of devmode ...*

## Usage

Registering a snap name in staging:

    $ surl -e celso.providelo@canonical.com -s staging -p package_upload \
      -d'{"snap_name": "surl"}' \
      https://myapps.developer.staging.ubuntu.com/dev/api/register-name/
    {"snap_id": "wKFeK2U7Y2CB53vRJwg9MeR9bqfPvtZK"}
