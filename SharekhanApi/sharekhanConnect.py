from six.moves.urllib.parse import urljoin, unquote
import base64
import requests
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
        "api.order.cancel.byid": "/skapi/services/cancelOrder/{orderId}",

        "api.logout": "/skapi/services/logout/{customerId}",

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

    def set_session_expiry_hook(self, method):
        """Register a callable invoked when the API reports an expired/invalid token (403)."""
        if not callable(method):
            raise TypeError("Invalid input type. Only functions are accepted.")
        self.session_expiry_hook = method

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

        # state parameter in the URL is set to 12345
        base_url += "&state=12345"

        # Check if version_id is provided and add it to the URL if available.
        # Use version_id=1005 (URL-safe tokens) together with generate_session().
        if version_id:
            base_url += "&version_id={}".format(version_id)

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
            # Sharekhan reports auth failures in the body, e.g.
            # {"status": 403, "message": "error", "errorType": "Access Denied"}
            if self.session_expiry_hook and isinstance(data, dict) and data.get("status") == 403:
                self.session_expiry_hook()
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

    # ------------------------------------------------------------------ #
    # Request-token handling
    #
    # After login, Sharekhan redirects to your redirect URL with
    # ?request_token=<AES-256-GCM encrypted "RequestId|CustomerId">.
    # The token must be decrypted with your API secret, the two parts
    # swapped ("CustomerId|RequestId"), re-encrypted and sent to
    # /access/token.  Key = 32-char secret, IV = 16 zero bytes, 16-byte tag.
    #   version_id=1005 -> base64url (what generate_session() produces)
    #   no version_id   -> standard base64 (generate_session_without_versionId())
    # Decoding is tolerant: it accepts either alphabet, with or without
    # '=' padding, and URL-encoded tokens (fixes "Incorrect padding").
    # ------------------------------------------------------------------ #
    @staticmethod
    def _b64decode_any(value):
        s = value.strip().replace("-", "+").replace("_", "/")
        s += "=" * (-len(s) % 4)
        return base64.b64decode(s)

    @staticmethod
    def _swap_request_token(request_token, secret_key, url_safe):
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        key = secret_key.strip().encode("utf-8")
        if len(key) != 32:
            raise ValueError("Invalid secret key size: expected 32 characters, got {}.".format(len(key)))
        iv = b"\x00" * 16

        raw = SharekhanConnect._b64decode_any(unquote(request_token))
        if len(raw) <= 16:
            raise ValueError("Request token is too short to be valid.")
        decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, raw[-16:]), default_backend()).decryptor()
        plain = (decryptor.update(raw[:-16]) + decryptor.finalize()).decode("utf-8")

        parts = plain.split("|")
        if len(parts) < 2:
            raise ValueError("Decrypted request token has an unexpected format.")
        swapped = parts[1] + "|" + parts[0]

        encryptor = Cipher(algorithms.AES(key), modes.GCM(iv), default_backend()).encryptor()
        data = encryptor.update(swapped.encode("utf-8")) + encryptor.finalize() + encryptor.tag
        if url_safe:
            return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")
        return base64.b64encode(data).decode("utf-8")

    def generate_session_without_versionId(self, request_token, secret_key):
        """Use when the login URL had NO version_id. Returns the value for get_access_token()."""
        return self._swap_request_token(request_token, secret_key, url_safe=False)

    def generate_session(self, request_token, secret_key):
        """Use when the login URL had version_id=1005. Returns the value for get_access_token()."""
        return self._swap_request_token(request_token, secret_key, url_safe=True)

    def get_access_token(self, apiKey, encstr, state, vendorkey=None, versionId=None):
        """Exchange the swapped request token for an access token (valid ~24h).

        On success the token is also stored on this instance (self.access_token).
        """
        params = {
            'apiKey': apiKey,
            'requestToken': encstr,
            'state': state
        }
        if vendorkey:
            params['vendorkey'] = vendorkey
        if versionId:
            params['versionId'] = versionId
        response = self._postRequest("api.access.token", params)
        data = response.get("data") if isinstance(response, dict) else None
        if isinstance(data, dict) and data.get("token"):
            self.access_token = data["token"]
        return response

    def funds(self, exchange, customerId):
        fundsResponse = self._getRequest("api.fund.details", {"exchange": exchange, "customerId": customerId})
        return fundsResponse

    @staticmethod
    def _clean_order_params(orderparams):
        """Return a copy without None values (the caller's dict is not modified)."""
        params = json.loads(orderparams) if isinstance(orderparams, str) else dict(orderparams)
        return {k: v for k, v in params.items() if v is not None}

    def placeOrder(self, orderparams):
        return self._postRequest("api.order.place", self._clean_order_params(orderparams))

    def modifyOrder(self, orderparams):
        return self._postRequest("api.order.modify", self._clean_order_params(orderparams))

    def cancelOrder(self, orderparams):
        return self._postRequest("api.order.cancel", self._clean_order_params(orderparams))

    def cancelOrderById(self, orderId):
        """Cancel a pending order using only its order ID (GET /cancelOrder/{orderId})."""
        return self._getRequest("api.order.cancel.byid", {"orderId": orderId})

    def logout(self, customerId):
        """End the API session: GET /logout/{customerId} (documented endpoint).

        Known server-side issue (verified 2026-11-06 with a valid token): the server answers
        {"status": 403, "message": "error", "errorType": "Access Denied"} and the token stays
        valid. GET is the only method the route accepts (POST/PUT/DELETE return 405), so the
        client call is correct; this has been reported to Sharekhan support. Until it is fixed,
        the access token simply expires on its own (it was invalid by the next morning).
        Check the returned status instead of assuming the session ended.
        """
        return self._getRequest("api.logout", {"customerId": customerId})

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

