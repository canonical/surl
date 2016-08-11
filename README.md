# surl
Ubuntu Store API thin wrapper


## Installing

Use `snap`:

    $ snap install surl

Also create a snap `common` directory for saving authorizations.

    $ mkdir -p ~/snap/surl/common

Careful because that directory will contain ready-to-use authorization.

## Usage

Verifying credentials:

    $ surl -e celso.providelo@canonical.com -s staging
    Password for celso.providelo@canonical.com:
    2FA (if enabled): ******
    {"account": ..., "allowed": true, "permissions": ["package_access"]}

Storing authorization:

    $ surl -e celso.providelo@canonical.com -s staging \
      -p package_access package_upload -a cprov-staging-upload
    Password for celso.providelo@canonical.com:
    2FA (if enabled): ****
    ...

Using stored authorizations:

    $ surl -a cprov-staging-upload | jq .
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
        "package_upload"
      ]
    }

Registering a snap name in staging:

    $ surl -a cprov-staging-upload -d'{"snap_name": "surl"}' \
      https://myapps.developer.staging.ubuntu.com/dev/api/register-name/
    {"snap_id": "wKFeK2U7Y2CB53vRJwg9MeR9bqfPvtZK"}
