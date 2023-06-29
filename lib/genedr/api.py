from datetime import datetime
from .baseclient import BaseClient
from .types import Alert, Alerts, Query

UPPER_RESULT_LIMIT = 1000


class API(BaseClient):
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

    def get_alerts_count(self, since: datetime = None, before: datetime = None) -> int:
        """
        Helper method to get the count of alerts retrieved with a given query.  Default will retrieve the total count
         of alerts since the beginning of time.
        :param since: lower limit on alerts within until-since delta.
        :param before: upper limit on alerts within until-since delta.
        :return: an int, the count of events found
        """
        query = Query(take=0, since=since, before=before)
        check = self.get_alerts(query)
        return check.count

    def get_alerts(self, query: Query) -> Alerts:
        """
        Get EDR alerts.  Default query parameters will retrieve the last 15 minutes of alerts.
         The expectation is that the callee will implement the pagination handling.
        :param query: a dict with the query parameters for pulling alerts.
        :return: Alerts container, a list of individual Alert objects.
        """
        endpoint = f"/v1/alerts"
        if query.take > UPPER_RESULT_LIMIT:
            raise ValueError(f"result amount {query.take} exceeds the upper result limit of "
                             f"{UPPER_RESULT_LIMIT}")
        # Wow, would be nice to have imo
        # https://datatracker.ietf.org/doc/draft-ietf-httpbis-safe-method-w-body/
        # Sure, why not... it's imaginary anyways.
        with self.request("QUERY", endpoint, data=query.json()) as response:
            alerts = Alerts()
            for alert in response:
                alerts.entries += Alert(**alert.json())
        return alerts
