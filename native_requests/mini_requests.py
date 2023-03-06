import copy
import http
import json
import logging
import ssl
from http.client import HTTPSConnection
from typing import TypedDict
from urllib.parse import urlparse, ParseResultBytes


class MiniResponse(TypedDict):
    headers: dict
    status_code: int
    body: str
    json: str



def response_from_connection(conn: HTTPSConnection) -> MiniResponse:
    resp = conn.getresponse()
    headers = dict(resp.getheaders())
    status_code = resp.status
    body = resp.read().decode("utf-8")
    response = MiniResponse(headers=headers, body=body, status_code=status_code)
    if maby_json(body):
        try:
            response["json"] = json.dumps(body)
        except json.JSONDecodeError as e:
            logging.error(f"response {body} can't be parsed to json with error {e}")
    return object

    return response


"""
todo:

1. persist session (connection with base url) ?



"""


class MiniRequests:
    def __init__(self, context: ssl.SSLContext = None, headers: dict = None, token: str = None):
        self.ctx = context or ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE
        self.headers = headers or {
            'Content-Type': 'application/json',
        }

        if token:
            headers['Authorization'] = f'Bearer {token}'

    def _send(self, method: str, conn: HTTPSConnection, headers: dict, url: str, body: str = ""):

        response = None
        try:
            conn.request(method=method, url=url, body=body, headers=headers)
            response = response_from_connection(conn=conn)

        except Exception as e:
            logging.error(e)

        finally:
            return response

    def _request(self, url, token: str = None, headers: dict = None) -> (HTTPSConnection, ParseResultBytes):
        request_headers = copy.deepcopy(self.headers)
        if headers:
            request_headers.update(headers)
        if token:
            request_headers['Authorization'] = f'Bearer {token}'

        parsed_url: ParseResultBytes = urlparse(url)
        netloc = str(parsed_url.netloc)
        conn = http.client.HTTPSConnection(netloc)
        return conn, parsed_url

    def get(self, url: str, token: str = None, headers: dict = None) -> MiniResponse:
        conn, parsed_url = self._request(url=url, token=token, headers=headers)
        path = str(parsed_url.path)
        query = parsed_url.query
        if query:
            query = str(query)

        url = f"{path}/?"
        if query:
            url = url + query

        return self._send(conn=conn, method="GET", headers=headers, url=url)

    def post(self, url, data, headers=None,token = None):
        conn, parsed_url = self._request(url=url, token=token, headers=headers)
        path = str(parsed_url.path)
        query = parsed_url.query
        if query:
            query = str(query)

        url = f"{path}/?"
        if query:
            url = url + query

        return self._send(conn=conn, method="POST", headers=headers, url=url,body=data)


def sendPOSTRequestXMLAutoDiscover(url, body):
    client = MiniRequests()
    headers = {
        "Content-Type": "text/xml; charset=utf-8",
        "SOAPAction": '"http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation"',
        "User-Agent": "AutodiscoverClient"
    }
    if type(body) != str:
        body = body.encode('utf-8')
    return client.post(headers=headers,url=url,data=body)




#
# def sendPOSTRequestSprayMSOL(url, user, pwd, resourceMgmt):
#     object = {}
#     o = urlparse(url)
#     ctx = ssl.create_default_context()
#     ctx.check_hostname = False
#     ctx.verify_mode = ssl.CERT_NONE
#     conn = http.client.HTTPSConnection(o.netloc)
#     headers = {
#         'Accept': 'application/json',
#         'Content-Type': 'application/x-www-form-urlencoded'
#     }
#     data = {
#         'client_id': '1b730954-1685-4b74-9bfd-dac224a7b894',
#         'client_info': '1',
#         'grant_type': 'password',
#         'username': user,
#         'password': pwd,
#         'scope': 'openid'
#     }
#     if resourceMgmt:
#         data['resource'] = 'https://management.azure.com/'
#     else:
#         data['resource'] = 'https://graph.windows.net'
#     qs = urllib.parse.urlencode(data)
#     conn.request("POST", str(o.path) + "/?" + str(o.query), qs, headers)
#     res = conn.getresponse()
#     object["headers"] = dict(res.getheaders())
#     object["status_code"] = int(res.status)
#     object["response"] = str(res.read().decode("utf-8"))
#     try:
#         object["json"] = json.loads(object["response"])
#     except json.JSONDecodeError:
#         pass
#     return object
#
#
# def sendPOSTRequestRefreshToken(tenantId, token):
#     object = {}
#     o = urlparse("https://login.microsoftonline.com/" + str(tenantId) + "/oauth2/v2.0/token")
#     ctx = ssl.create_default_context()
#     ctx.check_hostname = False
#     ctx.verify_mode = ssl.CERT_NONE
#     conn = http.client.HTTPSConnection(o.netloc)
#     headers = {
#         'Content-Type': 'application/x-www-form-urlencoded'
#     }
#     data = {
#         'grant_type': 'refresh_token',
#         'refresh_token': token,
#     }
#     qs = urllib.parse.urlencode(data)
#     conn.request("POST", str(o.path), qs, headers)
#     res = conn.getresponse()
#     object["headers"] = dict(res.getheaders())
#     object["status_code"] = int(res.status)
#     object["response"] = str(res.read().decode("utf-8"))
#     try:
#         object["json"] = json.loads(object["response"])
#     except json.JSONDecodeError:
#         pass
#     return object
#
#
# def sendPOSTRequestSPToken(tenantId, clientId, secretToken):
#     object = {}
#     o = urlparse("https://login.microsoftonline.com/" + str(tenantId) + "/oauth2/v2.0/token")
#     ctx = ssl.create_default_context()
#     ctx.check_hostname = False
#     ctx.verify_mode = ssl.CERT_NONE
#     conn = http.client.HTTPSConnection(o.netloc)
#     headers = {
#         'Content-Type': 'application/x-www-form-urlencoded'
#     }
#     data = {
#         'grant_type': 'client_credentials',
#         'client_id': clientId,
#         'scope': '.default',
#         'client_secret': secretToken,
#     }
#     qs = urllib.parse.urlencode(data)
#     conn.request("POST", str(o.path), qs, headers)
#     res = conn.getresponse()
#     object["headers"] = dict(res.getheaders())
#     object["status_code"] = int(res.status)
#     object["response"] = str(res.read().decode("utf-8"))
#     try:
#         object["json"] = json.loads(object["response"])
#     except json.JSONDecodeError:
#         pass
#     return object
