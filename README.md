# surl [![Build Status](https://travis-ci.org/cprov/surl.svg?branch=master)](https://travis-ci.org/cprov/surl) [![Snap Status](https://build.snapcraft.io/badge/cprov/surl.svg)](https://build.snapcraft.io/user/cprov/surl)
Ubuntu Store API thin wrapper



## Installing

[![Get it from the Snap Store](https://snapcraft.io/static/images/badges/en/snap-store-black.svg)](https://snapcraft.io/surl)

Or simply use the `snap` CLI:

    $ snap install surl [--edge]


## Usage

Verifying credentials:

    $ surl -e celso.providelo@canonical.com -s staging
    Password for celso.providelo@canonical.com:
    2FA (if enabled): ******
    {"account": ..., "allowed": true, "permissions": ["package_access"], "channels": ["edge"]}

Storing authorization:

    $ surl -e celso.providelo@canonical.com -s staging \
      -p package_access -p package_register -a stg-reg
    Password for celso.providelo@canonical.com: ****
    Second-factor auth for staging: ****
    ...

Using stored authorizations:

    $ surl -a stg-reg | jq .
    {
      "account": {
        "openid": "******",
        "verified": true,
        "displayname": "Celso Providelo",
        "email": "celso.providelo@canonical.com"
      },
      "last_auth": "2016-08-11T19:12:42.034584",
      "refresh_required": false,
      "allowed": true,
      "permissions": [
        "package_access",
        "package_register"
      ]
    }

Registering a snap name in staging:

    $ surl -a stg-reg -d'{"snap_name": "surl"}' \
      https://dashboard.staging.snapcraft.io/dev/api/register-name/
    {"snap_id": "wKFeK2U7Y2CB53vRJwg9MeR9bqfPvtZK"}

Happy hacking!
