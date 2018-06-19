#!/usr/bin/env python3

"""
S(tore)URL ....

Authorising the client::

  $ surl -e foo@bar.com -s production surl -a foo-prod

  OR

  $ STORE_EMAIL=foo@bar.com STORE_ENV=production surl -a foo-prod
  Password for foo@bar.com: *****
  2FA (if enabled):
  ...

That will record authorization information in `$SNAP_USER_COMMON` if
it's a snap or local diretory if run from source.
(CAREFULL, IT WILL BE IN PLAINTEXT)

"""
import sys

from surl import main


if __name__ == '__main__':
    sys.exit(main())
