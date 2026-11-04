"""Splunk field adaptation, keeping the original result in the raw store."""

from hashlib import sha256
from proofshield.normalisation.base import BaseNormaliser


class SplunkNormaliser(BaseNormaliser):
    def can_handle(self, raw_event):
        return raw_event.source_format == "splunk"

    def normalize(self, raw_event):
        from proofshield.connectors.splunk import _result_source, _nested
        from proofshield.normalisation.ecs import ECSNormaliser
        source = _result_source(raw_event.raw_payload)
        payload = dict(source)
        host = _nested(source, "host.name", "host.hostname", "host", "dest", "ComputerName")
        if not isinstance(host, str) or not host:
            raise ValueError("Splunk telemetry lacks an observed host")
        payload["host.name"] = host
        payload["@timestamp"] = raw_event.source_timestamp.isoformat()
        payload["event.id"] = raw_event.source_event_id
        mappings = {
            "process.name": ("process.name", "process_name"),
            "process.command_line": ("process.command_line", "CommandLine", "command_line"),
            "process.executable": ("process.executable", "Image", "process_path"),
            "user.name": ("user.name", "user", "User"),
            "destination.ip": ("destination.ip", "dest_ip", "DestinationIp"),
            "destination.port": ("destination.port", "dest_port", "DestinationPort"),
            "file.path": ("file.path", "file_path", "TargetFilename"),
        }
        for field, aliases in mappings.items():
            value = _nested(source, *aliases)
            if value is not None:
                payload[field] = value
        if not _nested(payload, "event.category"):
            code = str(_nested(source, "EventCode", "EventID") or "")
            category = {"1": "process", "3": "network", "11": "file"}.get(code)
            if not category:
                raise ValueError("Splunk telemetry requires event.category or a supported observed EventCode")
            payload["event.category"] = category
        adapted = raw_event.model_copy(update={"source_format": "elastic_ecs", "raw_payload": payload})
        event = ECSNormaliser().normalize(adapted)
        event.normalized_event_id = "NORM-SPLUNK-" + sha256(raw_event.raw_event_id.encode()).hexdigest()[:24]
        return event
