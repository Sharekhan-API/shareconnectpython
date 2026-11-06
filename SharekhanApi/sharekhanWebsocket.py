import json
import logging

try:
    import websocket  # provided by the "websocket-client" package
    if not hasattr(websocket, "WebSocketApp"):
        raise ImportError
except ImportError:  # pragma: no cover
    raise ImportError(
        "SharekhanWebSocket needs the 'websocket-client' package. "
        "Run: pip uninstall -y websocket && pip install websocket-client"
    )

log = logging.getLogger(__name__)


class SharekhanWebSocket(object):
    """Streaming client for wss://stream.sharekhan.com.

    Usage:
        sws = SharekhanWebSocket(access_token)            # api_key optional
        sws.on_open = lambda ws: sws.subscribe({"action": "subscribe", "key": ["feed"], "value": [""]})
        sws.on_data = lambda ws, msg: print(msg)
        sws.connect()                                      # blocks; run in a thread if needed

    Messages arrive as JSON text, e.g. {"status":100,"message":"feed","data":[...]}.
    """

    ROOT_URI = "wss://stream.sharekhan.com/skstream/api/stream"
    HEART_BEAT_MESSAGE = "ping"
    HEAR_BEAT_INTERVAL = 30

    def __init__(self, access_token, api_key=None):
        if not access_token:
            raise ValueError("access_token is required")
        self.access_token = access_token
        self.api_key = api_key
        self.root = "{}?ACCESS_TOKEN={}".format(self.ROOT_URI, access_token)
        if api_key:
            self.root += "&API_KEY={}".format(api_key)
        self.wsapp = None
        self.RESUBSCRIBE_FLAG = False

    # ------------------------------------------------------------------ #
    # Requests
    # ------------------------------------------------------------------ #
    def _send(self, payload):
        if self.wsapp is None:
            raise RuntimeError("Not connected; call connect() first")
        self.wsapp.send(json.dumps(payload))

    def subscribe(self, json_req):
        """Subscribe to modules, e.g. {"action":"subscribe","key":["feed","ack"],"value":[""]}"""
        req = dict(json_req)
        req.setdefault('action', 'subscribe')
        req.setdefault('key', ['feed', 'ack'])
        req.setdefault('value', [''])
        self._send(req)

    def fetchData(self, json_req):
        """Request data, e.g. {"action":"feed","key":["ltp"],"value":["NC2885,NC22"]}
        or order acks: {"action":"ack","key":[""],"value":["<customerId>"]}"""
        self._send({'action': json_req.get('action', 'fetch'),
                    'key': json_req.get('key', []),
                    'value': json_req.get('value', [''])})

    def unsubscribe(self, json_req):
        """e.g. {"action":"unsubscribe","key":["feed"],"value":["NC2885"]}"""
        self._send(json_req)

    def send_heart_beat(self):
        self.wsapp.send(self.HEART_BEAT_MESSAGE)

    # ------------------------------------------------------------------ #
    # Connection
    # ------------------------------------------------------------------ #
    def connect(self):
        """Open the connection and block until it closes."""
        self.wsapp = websocket.WebSocketApp(self.root,
                                            on_open=self._on_open,
                                            on_message=self._on_message,
                                            on_error=self._on_error,
                                            on_close=self._on_close)
        # TLS certificates are verified (the original SDK disabled verification).
        self.wsapp.run_forever(ping_interval=self.HEAR_BEAT_INTERVAL,
                               ping_payload=self.HEART_BEAT_MESSAGE)

    def close_connection(self):
        if self.wsapp is not None:
            self.wsapp.close()

    # ------------------------------------------------------------------ #
    # Internal callbacks -> user callbacks
    # ------------------------------------------------------------------ #
    def _on_open(self, wsapp):
        if self.RESUBSCRIBE_FLAG:
            self.resubscribe()
        else:
            self.RESUBSCRIBE_FLAG = True
            self.on_open(wsapp)

    def _on_message(self, wsapp, message):
        if isinstance(message, bytes):
            message = self._parse_binary_data(message)
        self.on_data(wsapp, message)

    def _on_error(self, wsapp, error):
        self.on_error(wsapp, error)

    def _on_close(self, wsapp, *args):
        # websocket-client >= 1.0 passes (ws, close_status_code, close_msg)
        self.on_close(wsapp)

    # Override these (or assign functions to them) ------------------------
    def on_open(self, wsapp):
        pass

    def on_data(self, wsapp, data):
        pass

    def on_message(self, wsapp, message):  # kept for backward compatibility
        pass

    def on_error(self, wsapp, error):
        log.error("Sharekhan websocket error: %s", error)

    def on_close(self, wsapp):
        pass

    def _parse_binary_data(self, data):
        return data.decode("utf-8", errors="replace")

    def resubscribe(self):
        pass
