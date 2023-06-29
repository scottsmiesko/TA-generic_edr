import json
from datetime import datetime, timedelta
from .base import Base
from .types import Alert, Alerts

UPPER_RESULT_LIMIT = 1000


class API(Base):
    """
    A class to handle Generic EDR requests and responses.
    """

    def __init__(self, host: str, creds: dict, proxies: bool | dict = None, validate_tls: bool | str = True) -> None:
        """
        This will just pass everything as-is into the superclass, creating our session.
        :param host:
        :param creds:
        :param proxies:
        :param validate_tls:
        """
        super().__init__(host, creds, proxies, validate_tls)

    def get_alerts_count(self, since: datetime = None, until: datetime = None) -> int:
        """
        Helper method to get the count of alerts retrieved with a given query.  Default will retrieve all alerts since
         the beginning of time.
        :param since: lower limit on alerts within until-since delta.
        :param until: upper limit on alerts within until-since delta.
        :return: an int, the count of events found
        """
        query = {
            "take": 0,
            "startDate": since or datetime.min.isoformat(),
            "endDate": until or datetime.utcnow().isoformat()
        }
        check = self.get_alerts(query)
        return check.count

    def get_alerts(self, query: dict = None) -> Alerts:
        """
        Get EDR alerts.  Default query parameters will retrieve the last 15 minutes of alerts.
         The expectation is that the callee will implement the pagination handling.
        :param query: a dict with the query parameters for pulling alerts.
        :return: Alerts container, a list of individual Alert objects.
        """
        endpoint = f"/v1/alerts"
        query = {
            "skip": 0,
            "take": 50,
            "sort": "insertion_date",
            "order": "desc",
            "startDate": datetime.utcnow() - timedelta(minutes=15),
            "endDate": datetime.utcnow()
        }
        if query["take"] > UPPER_RESULT_LIMIT:
            raise ValueError(f"result amount {query['take']} exceeds the upper result limit of "
                             f"{UPPER_RESULT_LIMIT}")
        # Wow, would be nice to have imo
        # https://datatracker.ietf.org/doc/draft-ietf-httpbis-safe-method-w-body/
        # Sure, why not... it's imaginary anyways.
        with self._call("QUERY", endpoint, data=query) as response:
            results = json.loads(response.json())

            # pseudocode for DTO of response of alerts

        return alerts
