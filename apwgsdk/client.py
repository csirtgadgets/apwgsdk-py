#!/usr/bin/env python

from argparse import ArgumentParser
from argparse import RawDescriptionHelpFormatter
import logging
import textwrap
import os.path
import os
from datetime import datetime, timedelta
from pprint import pprint
import json
import requests
from . import VERSION
from csirtg_indicator import Indicator
from csirtg_indicator.format.ztable import get_lines

LOG_FORMAT = '%(asctime)s - %(levelname)s - %(name)s[%(lineno)s] - %(message)s'
LIMIT = 10000000
APWG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
REMOTE = "https://api.ecrimex.net/phish"
TOKEN = os.environ.get('APWG_TOKEN')
LAST_RUN_CACHE = os.environ.get('APWG_LAST_RUN_CACHE', '/tmp/.apwg_last_run')


logger = logging.getLogger(__name__)

class Client(object):

    def __init__(self, token=TOKEN, proxy=None, timeout=300, lastrun=LAST_RUN_CACHE, **kwargs):

        self.proxy = proxy
        self.timeout = timeout
        self.token = token
        self.last_run_file = lastrun

        self.session = requests.Session()
        self.session.headers['User-Agent'] = 'apwgsdk-py/{}'.format(VERSION)

        if not os.path.isdir(self.last_run_file):
            os.makedirs(self.last_run_file)

    def _get(self, uri, params={}):
        if not uri.startswith('http'):
            uri = self.remote + uri

        body = self.session.get(uri, params=params, verify=True)

        if body.status_code == 200:
            yield json.dumps(body.text.decode('utf-8'))

        if body.status_code == 401:
            raise RuntimeError('unauthorized')

    def _last_run(self, hours=None):
        end = datetime.utcnow()

        lastrun = os.path.join(self.last_run_file, "lastrun")

        if os.path.exists(lastrun):
            with open(lastrun) as f:
                start = f.read().strip("\n")
                start = datetime.strptime(start, '%Y-%m-%d %H:%M:%S.%f')
        else:
            hours = int(hours)
            start = end - timedelta(hours=hours, seconds=-1)

        logger.info("start:{0}".format(start))
        logger.info("end:{0}".format(end))

        return start, end

    def _update_last_run(self):
        start, end = self._last_run()

        with open(os.path.join(self.last_run_file, "lastrun"), "w") as f:
            f.write(str(end))

    def indicators(self, limit=None):
        start, end = self._last_run()

        uri = "{}?t={}&dd_date_start={}&dd_date_end={}&confidence_low=90&pretty_print".format(
            self.remote,
            self.token,
            start.strftime('%s'),
            end.strftime('%s')
        )

        body = self._get(uri)

        body = body['_embedded']['phish']

        for i in body:
            yield Indicator({
                "indicator": i["url"],
                "reporttime": datetime.fromtimestamp(i["modified"]).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "lasttime": datetime.fromtimestamp(i['date_discovered']).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "tags": 'phishing',
                "description": i["brand"].lower(),
                "confidence": i['confidence'],
                "itype": "url",
                "provider": "apwg.org",
                "application": ["http", "https"]
            })

            if limit is not None:
                limit -= 1
                if limit == 0:
                    break

        self._update_last_run()



def main():
    p = ArgumentParser(
        description=textwrap.dedent('''\
        example usage:
            $ apwg -v
        '''),
        formatter_class=RawDescriptionHelpFormatter,
        prog='apwg'
    )

    p.add_argument('-d', '--debug', dest='debug', action="store_true")

    p.add_argument("--token", dest="token", help="specify token")

    p.add_argument("--limit", dest="limit", help="limit the number of records processed")
    p.add_argument("--format", default="json")
    p.add_argument("--last-run-cache", default=LAST_RUN_CACHE)
    p.add_argument("--past-hours", help="number of hours to go back and retrieve", default=24)
    p.add_argument('--confidence', default=65)

    p.add_argument("--no-last-run", help="do not modify lastrun file", action="store_true")

    args = p.parse_args()

    loglevel = logging.INFO
    if args.debug:
        loglevel = logging.DEBUG

    console = logging.StreamHandler()
    logging.getLogger('').setLevel(loglevel)
    console.setFormatter(logging.Formatter(LOG_FORMAT))
    logging.getLogger('').addHandler(console)

    cli = Client()

    indicators = cli.indicators()
    print(get_lines(indicators))




if __name__ == "__main__":
    main()
