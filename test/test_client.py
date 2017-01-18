import py.test
from apwgsdk import Client


def test_client():
    cli = Client(hours=24)

    assert cli.hours == 24

    def _get(self):
        return {'_embedded': {'phish': [{
                          'brand': 'csirtg',
                          'confidence_level': 100,
                          'date_discovered': 1484748033,
                          'domain': 'blah.org',
                          'ip': '',
                          'status': '',
                          'url': 'http://blah.org/1234.htm'},
        ]}}

    cli._get = _get

    r = cli.indicators(5, no_last_run=True)
    r = list(r)

    assert r[0].itype == 'url'
    assert r[0].indicator == 'http://blah.org/1234.htm'