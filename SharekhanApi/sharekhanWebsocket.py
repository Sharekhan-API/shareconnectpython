# import threading
# import time
import ssl
import json
import websocket

class SharekhanWebSocket(object):
    ROOT_URI = "wss://stream.sharekhan.com/skstream/api/stream"
    HEART_BEAT_MESSAGE = "ping"
    HEAR_BEAT_INTERVAL = 30
    LITTLE_ENDIAN_BYTE_ORDER = "<"
    RESUBSCRIBE_FLAG = False
    # HB_THREAD_FLAG = True
    MAX_RETRY_ATTEMPT = 1

    wsapp = None
    input_request_dict = {}
    current_retry_attempt = 0

    def __init__(self, access_token):
                try:
                    self.root = f"{self.ROOT_URI}?ACCESS_TOKEN={access_token}"
                    self.access_token = access_token
                    # self.api_key = api_key
                    # print(self.root)
                    if  self.access_token == None:
                        return "access_token  is missing"
                except Exception as e:
                    print("****error***",e)


    def _on_message(self, wsapp, message):
        print("message--->", message)
        if message != "pong":
            parsed_message = self._parse_binary_data(message)
            self.on_message(wsapp, parsed_message)
        else:
            self.on_message(wsapp, message)

    def _on_data(self, wsapp, data, data_type, continue_flag):

        if data_type == 2:
            parsed_message = self._parse_binary_data(data)
            self.on_data(wsapp, parsed_message)
        else:
            self.on_data(wsapp, data)

    def _on_open(self, wsapp):
        # self.HB_THREAD_FLAG = True
        # thread = threading.Thread(target=self.run, args=())
        # thread.daemon = True
        # thread.start()

        if self.RESUBSCRIBE_FLAG:
            self.resubscribe()
        else:
            self.RESUBSCRIBE_FLAG = True
            self.on_open(wsapp)

    def _on_pong(self, wsapp, data):
        print("In on pong function==> ", data)

    def _on_ping(self, wsapp, data):
        print("In on ping function==> ", data)

    def subscribe(self,json_req):
        """Subscribe the feed request"""
        json_req['action'] = json_req.get('action', 'subscribe')
        json_req['key'] = json_req.get('key', ['feed', 'ack'])
        json_req['value'] = json_req.get('value', [''])
        self.wsapp.send(json.dumps(json_req))

    def fetchData(self,json_req):
        """Retrieve the data """
        action = json_req.get('action', 'fetch')
        key = json_req.get('key', [])
        value = json_req.get('value', [''])

        message = {'action': action, 'key': key, 'value': value}
        self.wsapp.send(json.dumps(message))

    def unsubscribe(self, json_req):
        """
        Unsubscribes the specified feed
        """
        self.wsapp.send(json.dumps(json_req))

    def connect(self):
        """
            Make the web socket connection with the server
        """
        headers = {}
        try:
            self.wsapp = websocket.WebSocketApp(self.root, header=headers, on_open=self._on_open,
                                                on_error=self._on_error, on_close=self._on_close, on_data=self._on_data,
                                                on_ping=self._on_ping, on_pong=self._on_pong)
            self.wsapp.run_forever(sslopt={"cert_reqs": ssl.CERT_NONE}, ping_interval=self.HEAR_BEAT_INTERVAL,
                                   ping_payload=self.HEART_BEAT_MESSAGE)
        except Exception as e:
            raise e

    def close_connection(self):
        """
            Closes the connection
        """
        print("Connection Closed")
        # self.RESUBSCRIBE_FLAG = False
        # self.HB_THREAD_FLAG = False
        self.wsapp.close()

    # def disconnect_websocket(ROOT_URI, access_token):
    #     wsapp = websocket.WebSocket()
    #     wsapp.connect(ROOT_URI + access_token)
    #     wsapp.close()

    # def run(self):
    #     while True:
    #         if not self.HB_THREAD_FLAG:
    #             break
    #         self.send_heart_beat()
    #         time.sleep(self.HEAR_BEAT_INTERVAL)

    def send_heart_beat(self):
        try:
            self.wsapp.send(self.HEART_BEAT_MESSAGE)
        except Exception as e:
            raise e

    def _on_error(self, wsapp, error):
        self.HB_THREAD_FLAG = False
        # self.RESUBSCRIBE_FLAG = True
    #     if self.current_retry_attempt < self.MAX_RETRY_ATTEMPT:
    #         print("Attempting to resubscribe/reconnect...")
    #         self.current_retry_attempt += 1
    #         self.connect()

    def _on_close(self, wsapp):
        # self.HB_THREAD_FLAG = False
        # print(self.wsapp.close_frame)
        self.on_close(wsapp)


    def on_message(self, wsapp, message):
        print(message)

    def on_data(self, wsapp, data):
        pass

    def on_close(self, wsapp):
        pass

    def on_open(self, wsapp):
        pass

    def on_error(self):
        pass

    def _parse_binary_data(self, data):
        pass

    def resubscribe(self):
        pass
