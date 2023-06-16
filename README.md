# SHARECONNECT-PYTHON

    Sharekhan-Python is a Python library that provides a set of tools and functionalities for interacting with the Sharekhan trading platform. 
    With Sharekhan-Python, users can access a variety of trading-related information such as stock prices, market trends, historical data,
    stream live market data (WebSockets), and more.It also provides the ability to execute trades and orders in real time.

# Installation 
Use the package manager [pip](https://pip.pypa.io/en/stable/) to install shareconnectpython
```bash    
    pip install shareconnect
    pip install websocket
```
# Usage
```python    
    # package import statement
    from SharekhanApi.sharekhanConnect import SharekhanConnect
    
    # Make a object call
    
    api_key = "Your API-KEY"
    login = SharekhanConnect(api_key)
    vendor_key = "Vendor key" 
        """Pass the vendor key for vendor login otherwise keep it blank"""
    version_id = "Version Id"
        """Only null/1005/1006 version id is allowed to be passed"""
    state=12345
    url = login.login_url(vendor_key=vendor_key, version_id=version_id)
    """This will provide you the redirect login url which can be used to login in the sharekhan account"""
    print(url)

    
    """After Successfully Login You will receive the request token value then you have to decrypt the token value by using secret key and then swap the request token which is a combination of RequestId and CustomerId.Then after that decrypt the request token value."""
    
    request_token = "Valid Request Token Value"
    secret_key = "Your Secret Key value"

   """Use generate session method when you are passing version id """
    session=login.generate_session(request_token,secret_key)
    # Generating access token for version id and pass parameters as it is passed below 
    access_token=login.get_access_token(api_key,session,state,versionId=version_id)
    
    """Use generate session without version id method when you are not passing version id """
    sessionwithoutvesionId=login.generate_session_without_versionId(request_token,secret_key)
    # Generating access token for without version id 
    access_token=login.get_access_token(api_key,sessionwithoutvesionId,state)
    
    print(access_token)
    
    # Make a object for SharekhanConnect class
    """Here we are passing the api-key, access-token and vendor-key(when needed) as a request header parameters"""
    access_token = "Your access token value"
    sharekhan = SharekhanConnect(api_key,access_token)
    print(sharekhan.requestHeaders())       # for printing request headers
    
    # Place order history
    
     orderparams={
     "customerId": "XXXXXXX",
     "scripCode": 2475,
     "tradingSymbol": "ONGC",
     "exchange": "NC",
     "transactionType": "B",    --> (B, S, BM, SM, SAM)
     "quantity": 1,
     "disclosedQty": 0,
     "price": "149.5",
     "triggerPrice": "0",
     "rmsCode": "ANY",
     "afterHour": "N",
     "orderType": "NORMAL",
     "channelUser": "XXXXXXX",      (Use LoginId as ChannelUser)
     "validity": "GFD",
     "requestType": "NEW",
     "productType": "INVESTMENT"    --> (INVESTMENT or (INV), BIGTRADE or (BT), BIGTRADEPLUS or (BT+))
     #Below parameters need to be added for FNO trading
    "instrumentType": "FUTCUR";    --> (Future Stocks(FS)/ Future Index(FI)/ Option Index(OI)/ Option Stocks(OS)/ Future Currency(FUTCUR)/ Option Currency(OPTCUR))
    "strikePrice": "-1";
    "optionType": "XX";    --> (XX/PE/CE)
    "expiry": "31/03/2023";
    }
    
     order=sharekhan.placeOrder(orderparams)
     print("PlaceOrder: {}".format(order))

    # modify order

    orderparams={
     "orderId":"XXXXXXXXXXX",
       "customerId": "XXXXXXX",
     "scripCode": 2475,
     "tradingSymbol": "ONGC",
     "exchange": "NC",
     "transactionType": "B",    --> (B, S, BM, SM, SAM)
     "quantity": 1,
     "disclosedQty": 0,
     "price": "149.5",
     "triggerPrice": "0",
     "rmsCode": "ANY",
     "afterHour": "N",
     "orderType": "NORMAL",
     "channelUser": "XXXXXXX",      (Use LoginId as ChannelUser)
     "validity": "GFD",
     "requestType": "MODIFY",
     "productType": "INVESTMENT"    --> (INVESTMENT or (INV), BIGTRADE or (BT), BIGTRADEPLUS or (BT+))
     #Below parameters need to be added for FNO trading
    "instrumentType": "FUTCUR";    --> (Future Stocks(FS)/ Future Index(FI)/ Option Index(OI)/ Option Stocks(OS)/ Future Currency(FUTCUR)/ Option Currency(OPTCUR))
    "strikePrice": "-1";
    "optionType": "XX";    --> (XX/PE/CE)
    "expiry": "31/03/2023";
    }
    order=sharekhan.modifyOrder(orderparams)
    print("ModifyOrder: {}".format(order))
    
    # cancel  order
    
    orderparams={
     "orderId":"XXXXXXX",
     "customerId": "XXXXXXX",
     "scripCode": 2475,
     "tradingSymbol": "ONGC",
     "exchange": "NC",
     "transactionType": "B",    --> (B, S, BM, SM, SAM)
     "quantity": 1,
     "disclosedQty": 0,
     "price": "149.5",
     "triggerPrice": "0",
     "rmsCode": "ANY",
     "afterHour": "N",
     "orderType": "NORMAL",
     "channelUser": "XXXXXXX",      (Use LoginId as ChannelUser)
     "validity": "GFD",
     "requestType": "CANCEL",
     "productType": "INVESTMENT"    --> (INVESTMENT or (INV), BIGTRADE or (BT), BIGTRADEPLUS or (BT+))
     #Below parameters need to be added for FNO trading
    "instrumentType": "FUTCUR";    --> (Future Stocks(FS)/ Future Index(FI)/ Option Index(OI)/ Option Stocks(OS)/ Future Currency(FUTCUR)/ Option Currency(OPTCUR))
    "strikePrice": "-1";
    "optionType": "XX";    --> (XX/PE/CE)
    "expiry": "31/03/2023";
    }
    order=sharekhan.cancelOrder(orderparams)
    print("CancelOrder: {}".format(order))
    
    # Retrieves all positions
    
    customerId="customerId < int data type>"
    order=sharekhan.trades(customerId)
    print("Postion Reports: {}".format(order))
    
    # Retrieve history of an given order
    
    exchange="exchange value <string>"
    customerId="customerId <int data type>"
    orderId="orderId <int data type>"
    order=sharekhan.exchange(exchange, customerId, orderId)
    print("Order Details: {}".format(order))
    
    # Retrieves the trade  generated by an order
    
    exchange="exchange value <string>"
    customerId="customerId <int data type>"
    orderId="orderId <int data type>"
    order=sharekhan.exchangetrades(exchange, customerId, orderId)
    print("Trade Generated By an Order : {}".format(order))
    
    
    # services Holdings
    
    customerId="customerId <int data type>"
    order=sharekhan.holdings(customerId)
    print("Holdings : {}".format(order))
    
    # Script Master
    
    exchange="exchange value <string>"
    order=sharekhan.master(exchange)
    print("Script Master : {}".format(order))
    
    
    # Historical Data
    
    exchange="exchange value <string>"
    scripcode="Unique scripcode provided by the broker <int>"
    interval="Available Intervals <string>"
    order=sharekhan.historicaldata(exchange, scripcode, interval)
    print("Holdings Data: {}".format(order))
```

 # websocket Programming Testing
```python
    from SharekhanApi.sharekhanWebsocket import SharekhanWebSocket

    params = {
        "access_token": access_token
    }
    action = 1
    mode = 1
    
    token_list = {"action": "subscribe", "key": ["feed"], "value": [""]}
    feed = {"action": "feed", "key": ["depth"], "value": ["MX250715"]}
    unsubscribefeed = {"action":"unsubscribe","key":["feed"],"value":["NC22,NF37833,NF37834,MX253461,RN7719"]}
    
    sws = SharekhanWebSocket(access_token)
    
    
    def on_data(wsapp, message):
        print("Ticks: {}".format(message))
    
    
    def on_open(wsapp):
        print("on open")
        sws.subscribe(token_list)
        # sws.fetchData(feed)
        # sws.unsubscribe(unsubscribefeed)
        # sws.close_connection()
    
    
    def on_error(wsapp, error):
        print(error)
    
    
    def on_close(wsapp):
        print("Close")
    
    
    # Assign the callbacks.
    sws.on_open = on_open
    sws.on_data = on_data
    sws.on_error = on_error
    sws.on_close = on_close
    
    sws.connect()
```