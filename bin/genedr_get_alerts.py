#!/usr/bin/env python
import json
import os
import sys
import socket
from math import floor
from datetime import datetime

try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
    from splunklib.modularinput import Script, Scheme, Argument, ValidationDefinition, InputDefinition, EventWriter, \
        Event
    from solnlib.modular_input import checkpointer
    from solnlib import log
    from IPy import IP
    from dateutil import parser
    from genedr import API, Query
except ImportError as err:
    raise Exception(f"FATAL: unable to import local library: {str(err)}")

ADD_ON_NAME = "TA-generic_edr"
CHECKPOINT_TABLE_NAME = f"{ADD_ON_NAME}_checkpoints"
log.Logs.set_context(**{"namespace": ADD_ON_NAME})


class GetAlerts(Script):
    logger = log.Logs().get_logger('GetAlerts')

    def get_scheme(self) -> Scheme:
        scheme = Scheme("Generic EDR Alerts")
        scheme.description = "Retrieves alerts from Generic EDR for use as notable events in Splunk (ES)"
        scheme.use_external_validation = True
        scheme.use_single_instance = False

        edr_host = Argument("edr_host")
        edr_host.title = "EDR FQDN"
        edr_host.data_type = Argument.data_type_string
        edr_host.description = "The FQDN of the Generic EDR host to pull alerts from."
        edr_host.required_on_create = True
        scheme.add_argument(edr_host)

        username = Argument("username")
        username.title = "Username"
        username.data_type = Argument.data_type_string
        username.description = "The username to login with."
        username.required_on_create = True
        scheme.add_argument(username)

        password = Argument("password")
        password.title = "Password"
        password.data_type = Argument.data_type_string
        password.description = "The password for the aforementioned user."
        password.required_on_create = True
        scheme.add_argument(password)

        return scheme

    def validate_input(self, definition: ValidationDefinition) -> None:
        """
        Try a connection to the EDR host
        :param definition: the "definition" of the modular input (its `config` in a way)
        :return: None
        """
        edr_host = definition.parameters["edr_host"]
        try:
            if IP(edr_host):
                socket.gethostbyaddr(edr_host)
            else:
                socket.gethostbyname(edr_host)
        except socket.error:
            raise ValueError(f"Could not connect to EDR server. Please double-check the network "
                             f"connection is up and the destination is online and accepting connections.")
        # TODO: test login is successful with given creds

    def stream_events(self, inputs: InputDefinition, ew: EventWriter) -> None:
        for input_name, input_item in list(inputs.inputs.items()):
            hostname = input_item["edr_host"]
            creds = {
                "username": input_item["username"],
                "password": input_item["password"]
            }
            retrieved_ids = []

            try:
                client = API(hostname, creds)
                now = datetime.utcnow()
                checkpoint = checkpointer.KVStoreCheckpointer(
                    CHECKPOINT_TABLE_NAME,
                    self.service.token,
                    ADD_ON_NAME
                )

                """
                TODO: first-run checkpointing, configurable skip/take, since/during, etc.
                Currently, FTR pulls everything since the beginning of time.  Subsequent runs
                 will use the checkpoint made during FTR for `since`.
                """
                since = checkpoint.get(input_name).get("timestamp") or datetime.min
                checkpoint.update(input_name, {"timestamp": now, "last_run_timestamp": since})
                total = client.get_alerts_count(since=since, before=now)

                pos = 0
                chunk = 500
                pages = floor(total - 1 / chunk)  # given total=10345, pages=20 [floor(20.688)]

                query = Query(since=parser.parse(since), before=now, take=chunk, skip=pos)
                while True:
                    if pos > pages:
                        break
                    alerts = client.get_alerts(query)
                    retrieved_ids = [alert.alert_id for alert in alerts.entries]
                    event = Event(stanza=input_name, data=json.dumps(alerts.entries))
                    ew.write_event(event)
                    pos += 1
                    break

            except Exception as e:
                print(f"Something crashed... \n{str(e)}")
                exit(1)

            # Everything worked?
            self.logger.debug(f"alerts retrieved: {retrieved_ids}")
        return


if __name__ == "__main__":
    sys.exit(GetAlerts().run(sys.argv))
