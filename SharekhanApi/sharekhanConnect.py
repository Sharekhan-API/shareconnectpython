from six.moves.urllib.parse import urljoin
import re, uuid
import requests
from requests import get
import json
import logging

import SharekhanApi.sharekhanExceptions as ex

log = logging.getLogger(__name__)


class SharekhanConnect(object):
    _rootUrl = "https://api.sharekhan.com"  # prod endpoint

    _login_url = "https://api.sharekhan.com/skapi/auth/login.html"  # prod endpoint
    _default_timeout = 7  # In seconds
    _routes = {
        "api.access.token": "/skapi/services/access/token",

        "api.fund.details": "/skapi/services/limitstmt/{exchange}/{customerId}",

        "api.order.place": "/skapi/services/orders",
        "api.order.modify": "/skapi/services/orders",
        "api.order.cancel": "/skapi/services/orders",

        "api.reports.day": "/skapi/services/reports/{customerId}",

        "api.trades": "/skapi/services/trades/{customerId}",

        "api.reports.exchange": "/skapi/services/reports/{exchange}/{customerId}/{orderId}",
        "api.reports.exchange.trades": "/skapi/services/orders/{exchange}/{customerId}/{orderId}/trades",

        "api.holdings": "/skapi/services/holdings/{customerId}",

        "api.master": "/skapi/services/master/{exchange}",

        "api.historical.data": "/skapi/services/historical/{exchange}/{scripcode}/{interval}"
    }
    accept = "application/json"

    def __init__(self, api_key=None, state=None, vendor_key=None, access_token=None, refresh_token=None,
                 feed_token=None, userId=None, root=None,
                 debug=False, timeout=None, proxies=None, pool=None, disable_ssl=False, accept=None, userType=None,
                 sourceID=None, Authorization=None, clientPublicIP=None, clientMacAddress=None, clientLocalIP=None,
                 privateKey=None):
        self.refreshToken = None
        self.debug = debug
        self.api_key = api_key
        self.state = state
        self.vendor_key = vendor_key
        self.session_expiry_hook = None
        self.disable_ssl = disable_ssl
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.feed_token = feed_token
        self.userId = userId
        self.proxies = proxies if proxies else {}
        self.root = root or self._rootUrl
        self.timeout = timeout or self._default_timeout
        self.Authorization = None
        self.privateKey = api_key
        self.accept = self.accept

        if pool:
            self.reqsession = requests.Session()
            reqadapter = requests.adapters.HTTPAdapter(**pool)
            self.reqsession.mount("https://", reqadapter)
            print("in pool")
        else:
            self.reqsession = requests

        # disable requests SSL warning
        requests.packages.urllib3.disable_warnings()

    # setSessionExpiryHook takes a function as an argument and sets it as the session_expiry_hook attribute of the class instance

    def requestHeaders(self):
        headers = {
            "api-key": self.privateKey,
            "access-token": self.access_token,
            "Content-type": self.accept
        }

        if self.vendor_key:  # Only include "vendor" if it is not None or empty
            headers["vendor-key"] = self.vendor_key

        return headers

    def login_url(self, vendor_key=None, version_id=None):
        """Get the remote login URL to which a user should be redirected to initiate the login flow."""
        base_url = "{}?api_key={}".format(self._login_url, self.api_key)
        # Check if vendor_key is provided and add it to the URL if available
        if vendor_key:
            base_url += "&vendor_key={}".format(vendor_key)
        else:
            print("No Vendor Key")

        # state parameter in the URL is set to 12345
        base_url += "&state=12345"

        # Check if version_id is provided and add it to the URL if available
        if version_id:
            base_url += "&version_id={}".format(version_id)
        else:
            print("No Version Id")

        return base_url

    def _request(self, route, method, parameters=None):
        """Make an HTTP request."""
        params = parameters.copy() if parameters else {}
        uri = self._routes[route].format(**params)
        url = urljoin(self.root, uri)
        # Custom headers
        headers = self.requestHeaders()
        if self.access_token:
            # set authorization header
            auth_header = self.access_token
            headers["Authorization"] = "{}".format(auth_header)
        if self.debug:
            log.debug("Request: {method} {url} {params} {headers}".format(method=method, url=url, params=params,
                                                                          headers=headers))
        try:
            r = requests.request(method,
                                 url,
                                 data=json.dumps(params) if method in ["POST", "PUT"] else None,
                                 params=json.dumps(params) if method in ["GET", "DELETE"] else None,
                                 headers=headers,
                                 verify=not self.disable_ssl,
                                 allow_redirects=True,
                                 timeout=self.timeout,
                                 proxies=self.proxies)
        except Exception as e:
            raise e
        if self.debug:
            log.debug("Response: {code} {content}".format(code=r.status_code, content=r.content))
        # Validate the content type.
        if "json" in headers["Content-type"]:
            try:
                data = json.loads(r.content.decode("utf8"))
            except ValueError:
                raise ex.DataException("Couldn't parse the JSON response received from the server: {content}".format(
                    content=r.content))
            # api error
            if data.get("error_type"):
                # Call session hook if its registered and TokenException is raised
                if self.session_expiry_hook and r.status_code == 403 and data["error_type"] == "TokenException":
                    self.session_expiry_hook()
                # native errors
                exp = getattr(ex, data["error_type"], ex.GeneralException)
                raise exp(data["message"], code=r.status_code)
            return data
        elif "csv" in headers["Content-type"]:
            return r.content
        else:
            raise ex.DataException("Unknown Content-type ({content_type}) with response: ({content})".format(
                content_type=headers["Content-type"],
                content=r.content))

    def _deleteRequest(self, route, params=None):
        """Alias for sending a DELETE request."""
        return self._request(route, "DELETE", params)

    def _putRequest(self, route, params=None):
        """Alias for sending a PUT request."""
        return self._request(route, "PUT", params)

    def _postRequest(self, route, params=None):
        """Alias for sending a POST request."""
        return self._request(route, "POST", params)

    def _getRequest(self, route, params=None):
        """Alias for sending a GET request."""
        return self._request(route, "GET", params)

    def generate_session_without_versionId(self, request_token, secret_key):
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        import base64

        key = secret_key.encode('utf-8')
        iv = base64.b64decode("AAAAAAAAAAAAAAAAAAAAAA==")

        def encryptAPIString(plaintext):
            raw = plaintext.encode('utf-8')
            encryptor = Cipher(algorithms.AES(key), modes.GCM(iv, None, 16), default_backend()).encryptor()
            ciphertext = encryptor.update(raw) + encryptor.finalize()
            return base64Encode(ciphertext + encryptor.tag).decode('utf-8')

        def decryptAPIString(ciphertext):
            enc = base64Decode(ciphertext)[:-16]
            decryptor = Cipher(algorithms.AES(key), modes.GCM(iv), default_backend()).decryptor()
            return decryptor.update(enc)

        def base64Encode(data):
            return base64.b64encode(data)

        def base64Decode(base64String):
            return base64.b64decode(base64String)

        def decryption_method(key, encrypted_data):
            raw = key.encode('utf-8')
            if len(raw) != 32:
                raise ValueError("Invalid key size.")

            nonce = b'\x00' * 16
            skey_spec = AES.new(raw, AES.MODE_GCM, nonce=nonce)
            encrypted_data = base64.urlsafe_b64decode(encrypted_data)
            ciphertext = encrypted_data[:-16]
            received_mac_tag = encrypted_data[-16:]
            decrypted = skey_spec.decrypt_and_verify(ciphertext, received_mac_tag)
            return decrypted.decode('utf-8')

        def encryption_method(key, non_encrypted_data):
            raw = key.encode('utf-8')
            if len(raw) != 32:
                raise ValueError("Invalid key size.")
            nonce = b'\x00' * 16
            skey_spec = AES.new(raw, AES.MODE_GCM, nonce=nonce)
            ciphertext, mac_tag = skey_spec.encrypt_and_digest(pad(non_encrypted_data.encode('utf-8'), AES.block_size))
            encrypted = ciphertext + mac_tag
            return base64.urlsafe_b64encode(encrypted).decode('utf-8')

        decrypted_code = decryption_method(secret_key, request_token)
        # print(decrypted_code)
        result = decrypted_code.split('|')
        for s in result:
            s
            # print(s)
        manipulated_code = result[1] + '|' + result[0]
        # print(manipulated_code)
        msg = manipulated_code
        encStr = encryptAPIString(msg)
        # print("Encrypt :", encStr)
        return encStr

    def generate_session(self, request_token, secret_key):
        import base64
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from base64 import urlsafe_b64encode, urlsafe_b64decode
        import urllib.parse

        key = secret_key.encode('utf-8')
        iv = base64.b64decode("AAAAAAAAAAAAAAAAAAAAAA==")

        def encryptAPIString(plaintext):
            raw = plaintext.encode('utf-8')
            encryptor = Cipher(algorithms.AES(key), modes.GCM(iv, None, 16), default_backend()).encryptor()
            ciphertext = encryptor.update(raw) + encryptor.finalize()
            return base64UrlEncode(ciphertext + encryptor.tag).decode('utf-8')

        def decryptAPIString(ciphertext):
            enc = base64UrlDecode(ciphertext)[:-16]
            decryptor = Cipher(algorithms.AES(key), modes.GCM(iv), default_backend()).decryptor()
            decrypted_bytes = decryptor.update(enc)
            decrypted_string = decrypted_bytes.decode('utf-8')
            return decrypted_string

        def base64UrlEncode(data):
            return urlsafe_b64encode(data).rstrip(b'=')

        def base64UrlDecode(base64Url):
            padding = b'=' * (4 - (len(base64Url) % 4))
            return urlsafe_b64decode(base64Url + padding)

        def decryption_method(key, encrypted_data):
            raw = key.encode('utf-8')
            if len(raw) != 32:
                raise ValueError("Invalid key size.")

            nonce = b'\x00' * 16
            skey_spec = AES.new(raw, AES.MODE_GCM, nonce=nonce)
            encrypted_data = base64.urlsafe_b64decode(encrypted_data)
            ciphertext = encrypted_data[:-16]
            received_mac_tag = encrypted_data[-16:]
            decrypted = skey_spec.decrypt_and_verify(ciphertext, received_mac_tag)
            return decrypted.decode('utf-8')

        def encryption_method(key, non_encrypted_data):
            raw = key.encode('utf-8')
            if len(raw) != 32:
                raise ValueError("Invalid key size.")
            nonce = b'\x00' * 16
            skey_spec = AES.new(raw, AES.MODE_GCM, nonce=nonce)
            ciphertext, mac_tag = skey_spec.encrypt_and_digest(pad(non_encrypted_data.encode('utf-8'), AES.block_size))
            encrypted = ciphertext + mac_tag
            return base64.urlsafe_b64encode(encrypted).decode('utf-8')

        request_token = urllib.parse.unquote(request_token)  # decode URL-encoded string
        decrypted_code = decryption_method(secret_key, request_token)
        result = decrypted_code.split('|')
        manipulated_code = result[1] + '|' + result[0]
        msg = manipulated_code
        encStr = encryptAPIString(msg)
        # print("Encrypt :", encStr)
        return encStr

    def get_access_token(self, apiKey, encstr, state, vendorkey=None, versionId=None):
        url = f"{SharekhanConnect._rootUrl}{SharekhanConnect._routes['api.access.token']}"
        params = {
            'apiKey': apiKey,
            'requestToken': encstr,
            'state': state
        }
        if vendorkey is not None:
            params['vendorkey'] = vendorkey
        if versionId is not None:
            params['versionId'] = versionId
        response = self._postRequest("api.access.token", params)
        return response

    def funds(self, exchange, customerId):
        fundsResponse = self._getRequest("api.fund.details", {"exchange": exchange, "customerId": customerId})
        return fundsResponse

    def placeOrder(self, orderparams):
        if isinstance(orderparams, str):
            params = json.loads(orderparams)
        else:
            params = orderparams

        # params = orderparams

        for k in list(params.keys()):
            if params[k] is None:
                del (params[k])

        orderResponse = self._postRequest("api.order.place", params)

        return orderResponse

    def modifyOrder(self, orderparams):
        params = orderparams

        for k in list(params.keys()):
            if params[k] is None:
                del (params[k])

        orderResponse = self._postRequest("api.order.modify", params)
        return orderResponse

    def cancelOrder(self, orderparams):
        params = orderparams

        for k in list(params.keys()):
            if params[k] is None:
                del (params[k])

        orderResponse = self._postRequest("api.order.cancel", params)
        return orderResponse

    def reports(self, customerId):
        reportsResponse = self._getRequest("api.reports.day", {"customerId": customerId})
        return reportsResponse

    def trades(self, customerId):
        tradesResponse = self._getRequest("api.trades", {"customerId": customerId})
        return tradesResponse

    def exchange(self, exchange, customerId, orderId):
        exchangeResponse = self._getRequest("api.reports.exchange",
                                            {"exchange": exchange, "customerId": customerId, "orderId": orderId})
        return exchangeResponse

    def exchangetrades(self, exchange, customerId, orderId):
        exchangetradesResponse = self._getRequest("api.reports.exchange.trades",
                                                  {"exchange": exchange, "customerId": customerId, "orderId": orderId})
        return exchangetradesResponse

    def holdings(self, customerId):
        holdingsResponse = self._getRequest("api.holdings", {"customerId": customerId})
        return holdingsResponse

    def master(self, exchange):
        masterResponse = self._getRequest("api.master", {"exchange": exchange})
        return masterResponse

    def historicaldata(self, exchange, scripcode, interval):
        historicaldataResponse = self._getRequest("api.historical.data",
                                                  {"exchange": exchange, "scripcode": scripcode, "interval": interval})
        return historicaldataResponse

