"""Raw and normalised security telemetry event schemas."""

from datetime import datetime
from typing import Any, Dict, Literal, Optional
from pydantic import Field
from proofshield.schemas.common import (
    EventCategory,
    ProofshieldBaseModel,
)


class RawTelemetryEventV1(ProofshieldBaseModel):
    """Raw evidence record (Schema Version 1).

    Maintains raw, unaltered telemetry evidence received from source loggers,
    EDR agents, or SIEM forwarders.
    """

    schema_version: Literal["v1"] = "v1"
    raw_event_id: str = Field(
        ...,
        min_length=3,
        description="Unique identifier assigned to the raw event record in PROOFSHIELD",
    )
    source_event_id: str = Field(
        ...,
        min_length=1,
        description="Original identifier from the source logger/EDR (e.g. Sysmon Record ID, EventRecordID, UUID)",
    )
    source_format: str = Field(
        ...,
        min_length=1,
        description="Logger format descriptor (e.g. 'sysmon', 'edr_generic', 'auditd')",
    )
    source_timestamp: datetime = Field(
        ...,
        description="Original event creation timestamp as reported by the source endpoint",
    )
    ingested_at: datetime = Field(
        ...,
        description="Timestamp (UTC) when PROOFSHIELD ingested the event",
    )
    raw_payload: Dict[str, Any] = Field(
        ...,
        description="Unaltered raw payload dictionary from the source logger",
    )


class NormalizedTelemetryEventV1(ProofshieldBaseModel):
    """Standardised security event record (Schema Version 1).

    Canonical schema produced by the normalisation layer.
    Preserves source-event identifiers, source timestamps, and maps
    endpoint activity into deterministic fields.
    """

    schema_version: Literal["v1"] = "v1"
    normalized_event_id: str = Field(
        ...,
        min_length=3,
        description="Unique identifier for the normalised record",
    )
    raw_event_id: str = Field(
        ...,
        min_length=3,
        description="Foreign reference back to the immutable raw event record",
    )
    source_event_id: str = Field(
        ...,
        min_length=1,
        description="Preserved source event identifier from the original logger",
    )
    source_timestamp: datetime = Field(
        ...,
        description="Preserved original source timestamp from the source logger",
    )
    normalized_timestamp: datetime = Field(
        ...,
        description="Standardised UTC timestamp for chronological indexing",
    )
    event_category: EventCategory = Field(
        ...,
        description="Standardised category of the event",
    )
    host: str = Field(
        ...,
        min_length=1,
        description="Target host name, FQDN, or endpoint ID",
    )
    user: Optional[str] = Field(
        None,
        description="User account, domain\\user, or UID that initiated the activity",
    )
    process_name: Optional[str] = Field(
        None,
        description="Filename of the executed image (e.g. powershell.exe)",
    )
    process_path: Optional[str] = Field(
        None,
        description="Full path to the process executable",
    )
    command_line: Optional[str] = Field(
        None,
        description="Complete command line invocation including arguments",
    )
    parent_process_name: Optional[str] = Field(
        None,
        description="Name of the parent process",
    )
    parent_command_line: Optional[str] = Field(
        None,
        description="Command line of the parent process",
    )
    hashes: Dict[str, str] = Field(
        default_factory=dict,
        description="Cryptographic file hashes (e.g. sha256, md5, impash)",
    )
    network_destination_ip: Optional[str] = Field(
        None,
        description="Destination IP address for network connection events",
    )
    network_destination_port: Optional[int] = Field(
        None,
        ge=0,
        le=65535,
        description="Destination network port",
    )
    execution_token: Optional[str] = Field(
        None,
        description="Optional execution token extracted from telemetry or provided for causal attribution",
    )
    extra_attributes: Dict[str, Any] = Field(
        default_factory=dict,
        description="Preserved provider-specific attributes that do not map to canonical fields",
    )
