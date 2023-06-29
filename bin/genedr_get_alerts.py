#!/usr/bin/env python

import os
import sys
import socket
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

from splunklib.modularinput import Script, Scheme, Argument, ValidationDefinition, InputDefinition, EventWriter
from IPy import IP
from genedr import API


class GetAlerts(Script):
    """asdf
    """

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

        username = Argument("username")
        username.title = "Username"
        username.data_type = Argument.data_type_string
        username.description = "The username to login with."
        username.required_on_create = True

        password = Argument("password")
        password.title = "Password"
        password.data_type = Argument.data_type_string
        password.description = "The password for the aforementioned user."
        password.required_on_create = True

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
        # TODO: test username/password work and login was successful?

    def stream_events(self, inputs: InputDefinition, ew: EventWriter) -> None:
        for input_name, input_item in list(inputs.inputs.items()):
            hostname = input["edr_host"]
            creds = {
                "username": input["username"],
                "password": input["password"]
            }
            client = API(hostname, creds)
        return
