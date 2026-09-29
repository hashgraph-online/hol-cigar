"""Independent consumer: credentials arrive only through stdin, never argv/environment."""

import json
import sys

from cigar_sdk import LocalBrokerConnection, LocalContextClient

config = json.load(sys.stdin)
client = LocalContextClient(LocalBrokerConnection.from_config(config["connection"]))
context = client.compile(config["request"])
trace = client.explain(context["ticket"])
snapshot = context["context"]["snapshot"]
assert trace["snapshot_id"] == snapshot["id"]
selected = {citation["node_id"] for block in snapshot["blocks"] for citation in block["citations"]}
traced = [node for step in trace["steps"] for node in step["added_ids"]]
assert set(traced) == selected and len(traced) == len(selected)
json.dump(context, sys.stdout)
