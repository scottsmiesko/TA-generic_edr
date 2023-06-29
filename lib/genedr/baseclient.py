import json
from typing import Self
from datetime import datetime
from requests import Session, request
from dateutil import parser


class BaseClient:
    """
    A base client object used by the Generic EDR library.
    """

    def __init__(self, host: str, creds: dict, proxies: dict = None, validate_tls: bool | str = True) -> None:
        """
        Initialize the client to begin interacting with the Generic EDR API.  This client only supports TLS-secured
         connections by design.  All timestamps are in UTC and printed as ISO timestamp
        :param host: str, the EDR host to connect to - must be running REST API.
        :param creds: dict, contains the entries "username" and "password" for use in authentication.
        :param proxies: dict|bool, a list of proxy servers to use.  Currently only supports unauthenticated proxies.
            e.g.: {"http": "http://proxy.domain.com", "https": "https://proxy.domain.com:443"}
        :param validate_tls: bool|str, validate TLS or not, or point to a ca-cert bundle/c_rehash-processed directory
            for certificate validation instead of the default system ca-cert bundle or what the certifi python library
            comes bundled with. Useful for handling TLS MITM devices, proxy servers, self-signed certificates, etc.
        """
        self.client = Session()
        self.client.proxies.update(proxies)
        self.client.verify = validate_tls
        self.creds = creds

        self.token = {
            "secret": None,
            "expiry": datetime.min.isoformat()
        }
        self.url = f"https://{host}/api"
        self._connect()._login()

    def _connect(self) -> Self:
        """
        Try and connect to the EDR server, ad-hoc.
        :return: self, to chain calls if you like.
        """
        try:
            request("HEAD", self.url).raise_for_status()
            return self
        except Exception as e:
            raise ValueError(f"could not connect: {str(e)}")

    def _login(self) -> Self:
        """
        Login and store the bearer token for future request authentication and authorization.  Re-authenticates
         when the expiry date is before the current time.
        :return: self, to chain calls if you like.
        :throws: an Exception if the request could not be completed for any reason.
        """
        if parser.parse(self.token.get("expiry")) > datetime.utcnow():
            return self

        endpoint = "/v1/authenticate/simple"
        body = {
            "username": self.creds.get("username"),
            "password": self.creds.get("password"),
        }
        try:
            with self.request("POST", endpoint, data=body) as response:
                self.token = {
                    "secret": response.get("secret"),
                    "expiry": response.get("expiry")
                }
                self.client.headers.update({"Authorization": f"bearer {self.token.get('secret')}"})
        except Exception as e:
            raise ValueError(f"could not login: {str(e)}")
        return self

    def __del__(self):
        """
        destructor call to quit method
        """
        self._quit()

    def _quit(self):
        """
        Leave no session left unclosed.
        :return: nothing, it's over.
        """
        self.client.close()

    def request(self, *args: any, **kwargs: any) -> dict:
        """
        Wrapper to the client that ensures our auth token is valid.
        :param args: the individual arguments to be passed to the client (method, url)
        :param kwargs: the keyword arguments to be passed to the client as-is (body, url params, etc.)
        :return: a Response object if the request was successful.
        :throws: an Exception if the request could not be completed for any reason.
        """
        self._login()
        try:
            (r := self.client.request(*args, **kwargs)).raise_for_status()
            return json.loads(r.json())
        except Exception as e:
            raise Exception(f"client could not complete request: {str(e)}")
