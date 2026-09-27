"""Independent consumer: credentials arrive only through stdin, never argv/environment."""

import json
import sys

from cigar_sdk import LocalBrokerConnection, LocalContextClient

config = json.load(sys.stdin)
client = LocalContextClient(LocalBrokerConnection.from_config(config["connection"]))
json.dump(client.compile(config["request"]), sys.stdout)
