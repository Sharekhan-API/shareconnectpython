# SHARECONNECT-PYTHON

Python client for the Sharekhan Trading API: login, orders, reports, holdings,
funds, scrip master, historical candles and websocket streaming.

> **What's new in 1.0.0.12:** correct dependencies (`cryptography`, `websocket-client`),
> no more "Incorrect padding" when generating a session, websocket `on_close`/`on_error`
> callbacks fixed and TLS verification enabled, new `cancelOrderById()` / `logout()`,
> `set_session_expiry_hook()`, and corrected examples (pass `access_token=` by keyword).

## Installation

```bash
# from this folder (use a virtual environment)
pip install -e .
# or just the dependencies
pip install requests six cryptography websocket-client
```

Do **not** install the packages `websocket` or `Crypto` — they are unrelated
projects that break this SDK. If you have them: `pip uninstall -y websocket crypto`.

## Prerequisites (Sharekhan dashboard)

1. Create an app at https://www.sharekhan.com/trading-api/dashboard → you get an
   **API key** and a 32-character **secret key**.
2. **Redirect URL** – e.g. `http://127.0.0.1` (exactly, no spaces).
3. **Static IP** – the public IP of the machine that will call the API. Calls from
   any other IP are rejected (SEBI retail-algo rules).

## Login (once per day – tokens are valid ~24h)

```python
from SharekhanApi import SharekhanConnect

api_key, secret_key = "YOUR_API_KEY", "YOUR_32_CHAR_SECRET"
login = SharekhanConnect(api_key)

# 1. open this URL in a browser, log in with user-id / password / TOTP
print(login.login_url(version_id=1005))

# 2. you are redirected to  http://127.0.0.1/?request_token=XXXX&state=12345
request_token = "XXXX"   # copy from the address bar

# 3. swap + exchange for an access token
session = login.generate_session(request_token, secret_key)     # version_id=1005
resp = login.get_access_token(api_key, session, 12345, versionId=1005)
access_token = resp["data"]["token"]
customer_id  = resp["data"]["customerId"]
```

If you logged in **without** `version_id`, use
`generate_session_without_versionId()` and omit `versionId`.

## Using the API

```python
# IMPORTANT: pass access_token by keyword. The 2nd positional parameter is `state`;
# SharekhanConnect(api_key, access_token) silently sends no token -> 403 Access Denied.
sk = SharekhanConnect(api_key, access_token=access_token)
sk.set_session_expiry_hook(lambda: print("token expired - log in again"))

sk.funds("NC", customer_id)            # limits / margin
sk.holdings(customer_id)               # demat holdings
sk.reports(customer_id)                # all orders today
sk.trades(customer_id)                 # positions today (netQty, mtm, ...)
sk.exchange("NC", customer_id, order_id)        # history of one order
sk.exchangetrades("NC", customer_id, order_id)  # trades of one order
sk.master("NC")                        # scrip master (scripCode <-> tradingSymbol)
sk.historicaldata("NC", 2885, "5minute")        # candles
sk.logout(customer_id)                 # end the API session
```

Exchanges: `NC` NSE cash, `BC` BSE cash, `NF` NSE F&O, `RN` NSE currency, `MX` MCX.
Intervals: `1minute 3minute 5minute 10minute 15minute 30minute 60minute 90minute
daily weekly monthly quarterly halfyearly yearly`.

### Orders

```python
order = {
    "customerId": customer_id, "channelUser": customer_id,   # channelUser = login id
    "scripCode": 2475, "tradingSymbol": "ONGC", "exchange": "NC",
    "transactionType": "B",          # B / S (BM, SM, SAM for special cases)
    "quantity": 1, "disclosedQty": 0,
    "price": "149.50",               # string; "0" = market
    "triggerPrice": "0",             # > 0 for stop-loss orders
    "rmsCode": "ANY",                # NEW: "ANY"; MODIFY/CANCEL: rmscode returned by placeOrder
    "afterHour": "N",                # "Y" = AMO
    "orderType": "NORMAL",
    "validity": "GFD",               # GFD / MyGTD / IOC
    "requestType": "NEW",            # NEW / MODIFY / CANCEL
    "productType": "INVESTMENT",     # INVESTMENT (INV) / BIGTRADE (BT) / BIGTRADEPLUS (BT+)
    # F&O only:
    # "instrumentType": "FS", "strikePrice": "-1", "optionType": "XX", "expiry": "31/03/2027",
}
r = sk.placeOrder(order)             # -> data.orderId, data.rmscode
sk.modifyOrder({**order, "orderId": r["data"]["orderId"], "rmsCode": r["data"]["rmscode"],
                "requestType": "MODIFY", "price": "149.00"})
sk.cancelOrder({**order, "orderId": r["data"]["orderId"], "rmsCode": r["data"]["rmscode"],
                "requestType": "CANCEL"})
sk.cancelOrderById(r["data"]["orderId"])
```

## Websocket streaming

```python
import json
from SharekhanApi import SharekhanWebSocket

sws = SharekhanWebSocket(access_token)          # api_key=... optional

def on_open(ws):
    sws.subscribe({"action": "subscribe", "key": ["feed", "ack"], "value": [""]})
    sws.fetchData({"action": "feed", "key": ["ltp"], "value": ["NC2885,NC22"]})   # or "depth"
    sws.fetchData({"action": "ack", "key": [""], "value": [str(customer_id)]})    # order updates

sws.on_open  = on_open
sws.on_data  = lambda ws, msg: print(json.loads(msg))
sws.on_error = lambda ws, err: print("error", err)
sws.on_close = lambda ws: print("closed")
sws.connect()        # blocks - run in a thread if your program does other work
```

Unsubscribe: `sws.unsubscribe({"action":"unsubscribe","key":["feed"],"value":["NC2885"]})`.

## Errors

Auth/RMS errors come back in the JSON body, e.g.
`{"status": 403, "message": "error", "errorType": "Access Denied"}`.
Codes: 400 bad input · 403 token expired/denied · 404 not found ·
429 rate-limited · 500 general · 502 RMS down. 204 = no records.
