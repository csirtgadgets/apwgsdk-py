# the APWG Python Software Development Kit
# Features
  * Keeps track of last known run time (`/tmp/.apwg...`)
  * returns generator of csirtg_indicator.Indicator objects
  
# Getting Started
## Fetching the UBL
```bash
$ export APWG_TOKEN=1234
$ pip install apwgsdk
$ apwg -h
$ apwg -d
+----------------------------+-------------------------------+------------+----------------------------------+
|          lasttime          |            indicator          | confidence |           description            |
+----------------------------+-------------------------------+------------+----------------------------------+
| 2017-01-17T21:17:53.00000Z | https://example.com/1.html... |    100     |             example phish        |
| 2017-01-17T21:14:12.00000Z | https://example.com/2.html... |    100     |      example phish               |
| 2017-01-17T21:18:39.00000Z | https://example.com/3.html... |    100     |             example phish        |
| 2017-01-17T21:14:12.00000Z | https://example.com/4.html... |    100     |      example phish               |
....
```

## Submitting a URL
```bash
$ apwg --indicator-create http://example.phish.com/1.htm --description 'paypal' [--confidence 90 --lasttime 2017-01-17T21:14:12Z]

```

# Development
## Yielding csirtg_indicators
```python
from csirtg_indicator.format.ztable import get_lines
from apwgsdk.client import Client as apwgcli
cli = Client(hours=args.past_hours)

indicators = cli.indicators(no_last_run=args.no_last_run, limit=args.limit)

for s in get_lines(reversed(list(indicators)), cols=['lasttime', 'indicator', 'confidence', 'description']):
    print(s)
```
