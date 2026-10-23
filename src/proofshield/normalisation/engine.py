"""Deterministic telemetry normalisation engine and provider implementations."""

from datetime import datetime, timezone
import os
import re
from typing import Any, Dict, List, Optional, Sequence
import uuid
from dateutil import parser as date_parser

from proofshield.normalisation.base import BaseNormaliser
from proofshield.schemas.common import EventCategory
from proofshield.schemas.telemetry import (
    NormalizedTelemetryEventV1,
    RawTelemetryEventV1,
)


TOKEN_STRUCTURED_KEYS: Sequence[str] = (
    "execution_token",
    "executiontoken",
    "execution_token_id",
    "proofshield_token",
    "proofshieldtoken",
    "test_token",
    "testtoken",
    "run_token",
    "runtoken",
    "token",
    "token_id",
)

TOKEN_UNSTRUCTURED_PATTERNS = [
    # Flags: --execution-token=abc, --token abc, -token:abc, /execution_token:abc
    re.compile(r'(?:--?|/)(?:execution[-_]token|proofshield[-_]token|test[-_]token|token)[=:\s]+(["\']?)([a-zA-Z0-9_\-\.]+)\1', re.IGNORECASE),
    # Brackets: [TOKEN:abc], [EXECUTION_TOKEN:abc]
    re.compile(r'\[(?:EXECUTION[-_]TOKEN|PROOFSHIELD[-_]TOKEN|TEST[-_]TOKEN|TOKEN)[:\s]+(["\']?)([a-zA-Z0-9_\-\.]+)\1\]', re.IGNORECASE),
    # Key-value: execution_token=abc, token=abc, TOKEN:abc
    re.compile(r'\b(?:execution[-_]token|proofshield[-_]token|test[-_]token|token)[=:\s]+(["\']?)([a-zA-Z0-9_\-\.]+)\1', re.IGNORECASE),
    # Prefix: TOKEN=abc
    re.compile(r'\bTOKEN=([a-zA-Z0-9_\-\.]+)', re.IGNORECASE),
]

_TOKEN_IGNORE_VALUES = {"none", "null", "nil", "undefined", "false", "true", "empty"}


def extract_execution_token(
    payload: Optional[Dict[str, Any]] = None,
    explicit_token: Optional[str] = None,
    text_fields: Optional[Sequence[Optional[str]]] = None,
) -> Optional[str]:
    """Extract an execution token prioritizing structured fields with conflict detection.

    Rules:
    1. If explicit_token or structured token is "CONFLICT", returns "CONFLICT".
    2. Check structured fields in payload (case-insensitive keys). If explicit_token and
       structured payload token both exist and differ, returns "CONFLICT".
    3. Extract candidate tokens from unstructured text_fields via standard token patterns.
       If multiple distinct tokens are found across text fields, returns "CONFLICT".
    4. If structured token exists and extracted unstructured token exists:
       - If they match, returns the structured token.
       - If they conflict, returns "CONFLICT" (never verified).
    5. If only structured token exists, returns it.
    6. If only extracted unstructured token exists, returns it.
    7. Otherwise, returns None.
    """
    if explicit_token is not None:
        explicit_token = explicit_token.strip()
        if explicit_token == "CONFLICT":
            return "CONFLICT"

    structured_token: Optional[str] = explicit_token
    p = payload or {}

    # Check structured payload keys
    for k, v in p.items():
        if k.strip().lower() in TOKEN_STRUCTURED_KEYS and v is not None:
            val = str(v).strip()
            if not val or val.lower() in _TOKEN_IGNORE_VALUES:
                continue
            if val == "CONFLICT":
                return "CONFLICT"
            if structured_token is not None and structured_token != val:
                return "CONFLICT"
            structured_token = val

    # Check unstructured text fields
    extracted_tokens: List[str] = []
    if text_fields:
        for text in text_fields:
            if not text or not isinstance(text, str):
                continue
            for pattern in TOKEN_UNSTRUCTURED_PATTERNS:
                for match in pattern.finditer(text):
                    # group 2 for patterns with quotes group 1, or group 1 for TOKEN=...
                    tok = match.group(2) if match.lastindex and match.lastindex >= 2 else match.group(1)
                    if tok:
                        tok_str = tok.strip()
                        if tok_str and tok_str.lower() not in _TOKEN_IGNORE_VALUES:
                            if tok_str not in extracted_tokens:
                                extracted_tokens.append(tok_str)

    if len(extracted_tokens) > 1:
        # Multiple differing tokens in text fields -> conflict
        return "CONFLICT"

    unstructured_token = extracted_tokens[0] if extracted_tokens else None

    if structured_token is not None and unstructured_token is not None:
        if structured_token != unstructured_token:
            return "CONFLICT"
        return structured_token

    if structured_token is not None:
        return structured_token

    if unstructured_token is not None:
        return unstructured_token

    return None


_HASH_IGNORE_VALUES = {"none", "null", "nil", "undefined", "false", "true", "empty"}


def _ensure_utc(dt: datetime) -> datetime:
    """Ensure datetime has UTC timezone."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _clean_str(val: Any) -> Optional[str]:
    """Clean scalar string value, returning None if empty, whitespace, or non-scalar."""
    if val is None or isinstance(val, bool):
        return None
    if isinstance(val, (str, int, float)):
        s = str(val).strip()
        return s if s else None
    return None


def _clean_path(val: Any) -> Optional[str]:
    """Clean path value, returning None if not a non-empty string."""
    if isinstance(val, str):
        s = val.strip()
        return s if s else None
    return None


def _extract_basename(path_val: Any) -> Optional[str]:
    """Extract executable basename safely across Windows and POSIX path representations."""
    if not path_val or not isinstance(path_val, str):
        return None
    cleaned = path_val.strip().replace("\\", "/")
    base = cleaned.rstrip("/").split("/")[-1]
    return base if base else None


def _parse_port(raw_port: Any) -> Optional[int]:
    """Parse port into valid integer [0, 65535] or return None."""
    if raw_port is None or isinstance(raw_port, bool):
        return None
    try:
        if isinstance(raw_port, (int, str)):
            s = str(raw_port).strip()
            if s.isdigit():
                port = int(s)
                if 0 <= port <= 65535:
                    return port
    except (ValueError, TypeError):
        pass
    return None


def _parse_hashes(hash_input: Any) -> Dict[str, str]:
    """Parse Sysmon / EDR hash string or structured dictionary into a clean {algo: hex} map.

    Guarantees:
    - Never raises on unexpected types (int, list, dict, bool, None).
    - Rejects empty algorithms, empty hash values, and placeholder values ('none', 'null').
    - Supports comma/semicolon delimited 'ALGO=hash' strings and structured dicts.
    - Normalizes algorithm names and hash values to lowercase.
    """
    if not hash_input or isinstance(hash_input, bool):
        return {}

    results: Dict[str, str] = {}

    if isinstance(hash_input, dict):
        for k, v in hash_input.items():
            if not k or isinstance(k, bool) or not isinstance(k, (str, int)):
                continue
            algo = str(k).strip().lower()
            if len(algo) < 2 or not re.match(r"^[a-z0-9_\-]+$", algo):
                continue
            if isinstance(v, (str, int)) and not isinstance(v, bool):
                val = str(v).strip().lower()
                if val and val not in _HASH_IGNORE_VALUES and "\\" not in val and " " not in val:
                    results[algo] = val
        return results

    if isinstance(hash_input, (list, tuple)):
        items = hash_input
    elif isinstance(hash_input, str):
        items = re.split(r"[,;]", hash_input)
    else:
        return {}

    for item in items:
        if not isinstance(item, str):
            continue
        part = item.strip()
        if "=" in part:
            algo, val = part.split("=", 1)
        elif ":" in part and not part.startswith(("http:", "https:")):
            algo, val = part.split(":", 1)
        else:
            continue
        algo = algo.strip().lower()
        val = val.strip().lower()
        if len(algo) >= 2 and re.match(r"^[a-z0-9_\-]+$", algo):
            if val and val not in _HASH_IGNORE_VALUES and "\\" not in val and " " not in val:
                results[algo] = val

    return results


class SysmonNormaliser(BaseNormaliser):
    """Normalises Microsoft Sysmon JSON telemetry events."""

    SYSMON_FORMATS = {"sysmon", "microsoft-windows-sysmon", "sysmon_json"}

    EVENT_ID_MAP = {
        1: EventCategory.PROCESS_CREATION,
        3: EventCategory.NETWORK_CONNECTION,
        11: EventCategory.FILE_EVENT,
        12: EventCategory.REGISTRY_EVENT,
        13: EventCategory.REGISTRY_EVENT,
        14: EventCategory.REGISTRY_EVENT,
    }

    def can_handle(self, raw_event: RawTelemetryEventV1) -> bool:
        fmt = raw_event.source_format.strip().lower()
        if fmt in self.SYSMON_FORMATS:
            return True
        payload = raw_event.raw_payload
        # Heuristic check for Sysmon keys
        return "EventID" in payload and ("Image" in payload or "DestinationIp" in payload)

    def normalize(self, raw_event: RawTelemetryEventV1) -> NormalizedTelemetryEventV1:
        p = raw_event.raw_payload
        raw_event_id_str = str(p.get("EventID", "")).strip()
        event_id = int(raw_event_id_str) if raw_event_id_str.isdigit() else 0
        category = self.EVENT_ID_MAP.get(event_id, EventCategory.OTHER)

        # Preserve source event identifier
        # If payload provides a specific record ID, prefer that or fallback to raw_event.source_event_id
        src_id = (
            _clean_str(p.get("RecordId"))
            or _clean_str(p.get("EventRecordID"))
            or _clean_str(raw_event.source_event_id)
            or "unknown_event"
        )

        # Standardise timestamps
        src_ts = _ensure_utc(raw_event.source_timestamp)
        norm_ts = src_ts

        # Host extraction
        host = (
            _clean_str(p.get("Computer"))
            or _clean_str(p.get("host"))
            or _clean_str(p.get("Host"))
            or "unknown_host"
        )

        # Process details
        image_path = _clean_path(p.get("Image"))
        process_name = _extract_basename(image_path)
        cmd_line = _clean_str(p.get("CommandLine"))
        parent_image = _clean_path(p.get("ParentImage"))
        parent_name = _extract_basename(parent_image)
        parent_cmd = _clean_str(p.get("ParentCommandLine"))
        user = _clean_str(p.get("User"))

        # Hashes
        hashes = _parse_hashes(p.get("Hashes"))
        if p.get("hashes"):
            for k, v in _parse_hashes(p.get("hashes")).items():
                if k not in hashes:
                    hashes[k] = v
        if "sha256" not in hashes and p.get("Sha256"):
            sha_val = _clean_str(p.get("Sha256"))
            if sha_val and sha_val.lower() not in _HASH_IGNORE_VALUES:
                hashes["sha256"] = sha_val.lower()

        # Network details
        dest_ip = _clean_str(p.get("DestinationIp"))
        dest_port = _parse_port(p.get("DestinationPort"))

        # Extra attributes: collect fields not directly mapped
        known_keys = {
            "EventID", "RecordId", "EventRecordID", "Computer", "host", "Host",
            "Image", "CommandLine", "ParentImage", "ParentCommandLine", "User",
            "Hashes", "hashes", "Sha256", "DestinationIp", "DestinationPort", "UtcTime",
            "execution_token", "ExecutionToken", "token", "Token", "proofshield_token",
        }
        extra = {k: v for k, v in p.items() if k not in known_keys}

        # Token extraction (structured-first with conflict detection)
        token = extract_execution_token(p, text_fields=[cmd_line, image_path])

        return NormalizedTelemetryEventV1(
            normalized_event_id=f"NORM-{uuid.uuid4().hex[:12].upper()}",
            raw_event_id=raw_event.raw_event_id,
            source_event_id=src_id,
            source_timestamp=src_ts,
            normalized_timestamp=norm_ts,
            event_category=category,
            host=host,
            user=user,
            process_name=process_name,
            process_path=image_path,
            command_line=cmd_line,
            parent_process_name=parent_name,
            parent_command_line=parent_cmd,
            hashes=hashes,
            network_destination_ip=dest_ip,
            network_destination_port=dest_port,
            execution_token=token,
            extra_attributes=extra,
        )


class GenericEDRNormaliser(BaseNormaliser):
    """Normalises common EDR and SIEM JSON telemetry events."""

    EDR_FORMATS = {"edr", "generic_edr", "crowdstrike", "sentinelone", "defender", "carbonblack"}

    CATEGORY_MAPPING = {
        "process": EventCategory.PROCESS_CREATION,
        "process_create": EventCategory.PROCESS_CREATION,
        "process_creation": EventCategory.PROCESS_CREATION,
        "exec": EventCategory.PROCESS_CREATION,
        "network": EventCategory.NETWORK_CONNECTION,
        "net_connect": EventCategory.NETWORK_CONNECTION,
        "file": EventCategory.FILE_EVENT,
        "file_create": EventCategory.FILE_EVENT,
        "file_modify": EventCategory.FILE_EVENT,
        "registry": EventCategory.REGISTRY_EVENT,
        "auth": EventCategory.AUTHENTICATION,
        "logon": EventCategory.AUTHENTICATION,
    }

    def can_handle(self, raw_event: RawTelemetryEventV1) -> bool:
        fmt = (raw_event.source_format or "").strip().lower()
        if fmt in self.EDR_FORMATS:
            return True
        if fmt in {"auditd", "linux_audit", "audit", "audit_log", "sysmon", "microsoft-windows-sysmon", "sysmon_json"}:
            return False
        payload = raw_event.raw_payload
        if "EventID" in payload or "syscall" in payload or "audit_id" in payload:
            return False
        return any(k in payload for k in ("event_type", "action", "process_name", "cmdline"))

    def normalize(self, raw_event: RawTelemetryEventV1) -> NormalizedTelemetryEventV1:
        p = raw_event.raw_payload
        raw_cat = str(p.get("event_type") or p.get("action") or p.get("type") or "").strip().lower()
        category = self.CATEGORY_MAPPING.get(raw_cat, EventCategory.OTHER)

        src_id = (
            _clean_str(p.get("event_id"))
            or _clean_str(p.get("id"))
            or _clean_str(raw_event.source_event_id)
            or "unknown_event"
        )
        src_ts = _ensure_utc(raw_event.source_timestamp)

        # Host and user
        host = (
            _clean_str(p.get("hostname"))
            or _clean_str(p.get("host"))
            or _clean_str(p.get("endpoint_id"))
            or _clean_str(p.get("device_name"))
            or "unknown_host"
        )
        user = (
            _clean_str(p.get("username"))
            or _clean_str(p.get("user"))
            or _clean_str(p.get("account"))
        )

        # Process info
        process_path = (
            _clean_path(p.get("process_path"))
            or _clean_path(p.get("binary_path"))
            or _clean_path(p.get("image"))
        )
        process_name = _clean_str(p.get("process_name")) or _extract_basename(process_path)
        cmd_line = (
            _clean_str(p.get("command_line"))
            or _clean_str(p.get("cmdline"))
            or _clean_str(p.get("command"))
        )
        parent_name = (
            _clean_str(p.get("parent_process_name"))
            or _clean_str(p.get("parent_name"))
        )
        if not parent_name:
            parent_name = _extract_basename(
                _clean_path(p.get("parent_path")) or _clean_path(p.get("parent_image"))
            )
        parent_cmd = (
            _clean_str(p.get("parent_command_line"))
            or _clean_str(p.get("parent_cmdline"))
        )

        # Hashes
        hashes = _parse_hashes(p.get("hashes"))
        if p.get("Hashes"):
            for k, v in _parse_hashes(p.get("Hashes")).items():
                if k not in hashes:
                    hashes[k] = v
        for hash_field in ("sha256", "md5", "sha1"):
            if hash_field not in hashes and hash_field in p:
                field_val = _clean_str(p.get(hash_field))
                if field_val and field_val.lower() not in _HASH_IGNORE_VALUES:
                    hashes[hash_field] = field_val.lower()

        # Network
        dest_ip = (
            _clean_str(p.get("destination_ip"))
            or _clean_str(p.get("dst_ip"))
            or _clean_str(p.get("remote_ip"))
        )
        dest_port = None
        for port_key in ("destination_port", "dst_port", "remote_port"):
            if port_key in p:
                parsed_port = _parse_port(p[port_key])
                if parsed_port is not None:
                    dest_port = parsed_port
                    break

        known_keys = {
            "event_type", "action", "type", "event_id", "id", "hostname", "host",
            "endpoint_id", "device_name", "username", "user", "account",
            "process_path", "binary_path", "image", "process_name", "command_line",
            "cmdline", "command", "parent_process_name", "parent_name", "parent_path", "parent_image",
            "parent_command_line", "parent_cmdline", "hashes", "Hashes", "sha256", "md5",
            "sha1", "destination_ip", "dst_ip", "remote_ip", "destination_port",
            "dst_port", "remote_port", "timestamp", "execution_token", "token", "proofshield_token",
        }
        extra = {k: v for k, v in p.items() if k not in known_keys}

        token = extract_execution_token(p, text_fields=[cmd_line, process_path])

        return NormalizedTelemetryEventV1(
            normalized_event_id=f"NORM-{uuid.uuid4().hex[:12].upper()}",
            raw_event_id=raw_event.raw_event_id,
            source_event_id=src_id,
            source_timestamp=src_ts,
            normalized_timestamp=src_ts,
            event_category=category,
            host=host,
            user=user,
            process_name=process_name,
            process_path=process_path,
            command_line=cmd_line,
            parent_process_name=parent_name,
            parent_command_line=parent_cmd,
            hashes=hashes,
            network_destination_ip=dest_ip,
            network_destination_port=dest_port,
            execution_token=token,
            extra_attributes=extra,
        )


def _parse_auditd_sockaddr(saddr: Any) -> tuple[Optional[str], Optional[int]]:
    """Parse Linux auditd hex-encoded sockaddr struct (AF_INET IPv4).

    Format: 32 hex chars.
    Bytes 0-1: family (0200 = AF_INET little-endian).
    Bytes 2-3: port (network byte order / big endian).
    Bytes 4-7: IPv4 address (network byte order).
    """
    if not isinstance(saddr, str):
        return None, None
    s = saddr.strip()
    if len(s) == 32 and s[:4].lower() == "0200":
        try:
            port = int(s[4:8], 16)
            b0 = int(s[8:10], 16)
            b1 = int(s[10:12], 16)
            b2 = int(s[12:14], 16)
            b3 = int(s[14:16], 16)
            if 0 <= port <= 65535 and all(0 <= b <= 255 for b in (b0, b1, b2, b3)):
                return f"{b0}.{b1}.{b2}.{b3}", port
        except ValueError:
            return None, None
    return None, None


class AuditdNormaliser(BaseNormaliser):
    """Normalises Linux auditd telemetry events into canonical events.

    Adheres strictly to evidence sufficiency:
    - Multi-record and fragmented records (e.g. CWD, PATH, PROCTITLE) without
      process creation or network evidence map to EventCategory.OTHER.
    - PROCESS_CREATION requires an execution syscall (execve/execveat),
      success != false, and executable path or process name evidence.
    - NETWORK_CONNECTION requires socket record/syscall with valid dest IP/port.
    - AUTHENTICATION is mapped for USER_AUTH, USER_LOGIN, and LOGIN records.
    - All unmapped attributes are safely preserved in extra_attributes.
    """

    AUDITD_FORMATS = {"auditd", "linux_audit", "audit", "audit_log"}

    def can_handle(self, raw_event: RawTelemetryEventV1) -> bool:
        fmt = (raw_event.source_format or "").strip().lower()
        if fmt in self.AUDITD_FORMATS:
            return True
        p = raw_event.raw_payload
        # Detect auditd record markers if source_format is not explicitly set
        if any(k in p for k in ("syscall", "audit_id", "record_type", "ses", "auid")) and (
            p.get("type") in {"SYSCALL", "EXECVE", "SOCKADDR", "USER_AUTH", "USER_LOGIN", "CWD", "PATH", "PROCTITLE"}
            or "syscall" in p
        ):
            return True
        return False

    def normalize(self, raw_event: RawTelemetryEventV1) -> NormalizedTelemetryEventV1:
        p = raw_event.raw_payload
        src_id = (
            _clean_str(p.get("audit_id"))
            or _clean_str(p.get("serial"))
            or _clean_str(raw_event.source_event_id)
            or "unknown_event"
        )
        src_ts = _ensure_utc(raw_event.source_timestamp)

        # Host
        host = (
            _clean_str(p.get("node"))
            or _clean_str(p.get("host"))
            or _clean_str(p.get("hostname"))
            or _clean_str(p.get("computer"))
            or "unknown_host"
        )

        # User
        user = (
            _clean_str(p.get("user"))
            or _clean_str(p.get("acct"))
            or _clean_str(p.get("username"))
            or _clean_str(p.get("account"))
        )
        if not user and p.get("uid") is not None:
            user = f"uid:{p['uid']}"

        # Process Path and Name
        proc_path = _clean_path(p.get("exe") or p.get("process_path") or p.get("binary_path"))
        proc_name = _clean_str(p.get("comm") or p.get("process_name"))
        if not proc_name and proc_path:
            proc_name = _extract_basename(proc_path)
        if not proc_path and not proc_name and "a0" in p:
            a0_str = _clean_path(p.get("a0"))
            if a0_str:
                proc_path = a0_str
                proc_name = _extract_basename(a0_str)

        # Command Line
        cmd_line = _clean_str(p.get("command_line") or p.get("cmdline") or p.get("proctitle"))
        if not cmd_line:
            args_field = p.get("args")
            if isinstance(args_field, (list, tuple)):
                cmd_line = " ".join(str(a) for a in args_field if a is not None).strip() or None
            elif isinstance(args_field, str):
                cmd_line = args_field.strip() or None
        if not cmd_line:
            collected_args = []
            i = 0
            while f"a{i}" in p:
                val = p[f"a{i}"]
                if val is not None:
                    collected_args.append(str(val))
                i += 1
            if collected_args:
                cmd_line = " ".join(collected_args).strip() or None

        # Parent process
        parent_name = _clean_str(p.get("parent_name") or p.get("parent_comm") or p.get("parent_process_name"))
        parent_path = _clean_path(p.get("parent_exe") or p.get("parent_path"))
        if not parent_name and parent_path:
            parent_name = _extract_basename(parent_path)
        parent_cmd = _clean_str(p.get("parent_cmdline") or p.get("parent_cmd"))

        # Hashes
        hashes = _parse_hashes(p.get("hashes"))
        for hash_field in ("sha256", "md5", "sha1"):
            if hash_field not in hashes and hash_field in p:
                field_val = _clean_str(p.get(hash_field))
                if field_val and field_val.lower() not in _HASH_IGNORE_VALUES:
                    hashes[hash_field] = field_val.lower()

        # Network
        sock_ip, sock_port = _parse_auditd_sockaddr(p.get("saddr"))
        dest_ip = sock_ip or _clean_str(p.get("destination_ip") or p.get("dst_ip") or p.get("remote_ip"))
        dest_port = sock_port
        if dest_port is None:
            for port_key in ("destination_port", "dst_port", "remote_port", "port"):
                if port_key in p:
                    parsed_port = _parse_port(p[port_key])
                    if parsed_port is not None:
                        dest_port = parsed_port
                        break

        # Category determination
        rec_type = (_clean_str(p.get("type") or p.get("record_type")) or "").upper()
        syscall = (_clean_str(p.get("syscall")) or "").lower()

        # Check execution success
        success_val = p.get("success")
        is_success = True
        if success_val is not None:
            if isinstance(success_val, bool):
                is_success = success_val
            elif isinstance(success_val, (int, float)):
                is_success = bool(success_val)
            elif isinstance(success_val, str):
                is_success = success_val.strip().lower() not in {"no", "false", "0", "fail", "failed"}
        exit_val = p.get("exit")
        if exit_val is not None:
            try:
                if int(exit_val) < 0:
                    is_success = False
            except (ValueError, TypeError):
                pass

        category = EventCategory.OTHER
        exec_syscalls = {"execve", "execveat", "59", "322", "11", "358", "221", "281"}
        net_syscalls = {"connect", "accept", "accept4", "42", "43", "288", "202", "203", "242", "102"}
        is_exec_call = syscall in exec_syscalls or rec_type == "EXECVE"

        if is_exec_call and is_success and (proc_path or proc_name):
            category = EventCategory.PROCESS_CREATION
        elif rec_type == "SOCKADDR" or syscall in net_syscalls:
            if dest_ip or dest_port is not None:
                category = EventCategory.NETWORK_CONNECTION
        elif rec_type in {"USER_AUTH", "USER_LOGIN", "LOGIN", "CRED_ACQ", "CRED_DISP"}:
            category = EventCategory.AUTHENTICATION
        elif rec_type in {"PATH", "FILE"} and (
            str(p.get("nametype") or "").strip().upper() in {"CREATE", "DELETE"} or syscall in {"unlink", "unlinkat", "rmdir", "rename", "renameat", "renameat2"}
        ):
            category = EventCategory.FILE_EVENT

        # Strictly gate destination IP and port to NETWORK_CONNECTION events
        if category != EventCategory.NETWORK_CONNECTION:
            dest_ip = None
            dest_port = None

        known_keys = {
            "type", "record_type", "syscall", "audit_id", "serial", "node", "host",
            "hostname", "computer", "user", "acct", "username", "account", "uid",
            "exe", "process_path", "binary_path", "comm", "process_name", "command_line",
            "cmdline", "proctitle", "args", "parent_name", "parent_comm", "parent_process_name",
            "parent_exe", "parent_path", "parent_cmdline", "parent_cmd", "hashes", "sha256",
            "md5", "sha1", "saddr", "destination_ip", "dst_ip", "remote_ip",
            "destination_port", "dst_port", "remote_port", "port", "success", "execution_token",
            "token", "proofshield_token",
        }
        extra = {k: v for k, v in p.items() if k not in known_keys and not (k.startswith("a") and k[1:].isdigit())}

        token = extract_execution_token(p, text_fields=[cmd_line, proc_path, p.get("proctitle")])

        return NormalizedTelemetryEventV1(
            normalized_event_id=f"NORM-{uuid.uuid4().hex[:12].upper()}",
            raw_event_id=raw_event.raw_event_id,
            source_event_id=src_id,
            source_timestamp=src_ts,
            normalized_timestamp=src_ts,
            event_category=category,
            host=host,
            user=user,
            process_name=proc_name,
            process_path=proc_path,
            command_line=cmd_line,
            parent_process_name=parent_name,
            parent_command_line=parent_cmd,
            hashes=hashes,
            network_destination_ip=dest_ip,
            network_destination_port=dest_port,
            execution_token=token,
            extra_attributes=extra,
        )


class FallbackNormaliser(BaseNormaliser):
    """Guaranteed fallback normaliser for unknown telemetry schemas.

    Strictly preserves source event identifiers, source timestamps, and
    captures all payload fields in extra_attributes without losing data.
    """

    def can_handle(self, raw_event: RawTelemetryEventV1) -> bool:
        return True  # Catch-all

    def normalize(self, raw_event: RawTelemetryEventV1) -> NormalizedTelemetryEventV1:
        p = raw_event.raw_payload
        src_id = _clean_str(raw_event.source_event_id) or "unknown_event"
        src_ts = _ensure_utc(raw_event.source_timestamp)

        # Try best-effort case-insensitive field discovery
        flat_lower = {k.lower(): (k, v) for k, v in p.items()}

        def find_val(*candidates: str) -> Optional[Any]:
            for c in candidates:
                if c.lower() in flat_lower:
                    orig_key, val = flat_lower[c.lower()]
                    if val is not None:
                        if isinstance(val, str) and not val.strip():
                            continue
                        return val
            return None

        host = _clean_str(find_val("host", "hostname", "computer", "device", "endpoint")) or "unknown_host"
        user = _clean_str(find_val("user", "username", "account"))
        cmd_line = _clean_str(find_val("command_line", "cmdline", "command", "process.command_line"))
        proc_path = _clean_path(find_val("process_path", "image_path", "path"))
        proc_name = _clean_path(find_val("process_name", "process", "image", "file_name"))
        if proc_name:
            proc_name = _extract_basename(proc_name)
        elif proc_path:
            proc_name = _extract_basename(proc_path)

        hashes = _parse_hashes(find_val("hashes", "hash"))
        for hash_field in ("sha256", "md5", "sha1"):
            if hash_field not in hashes:
                h_val = _clean_str(find_val(hash_field))
                if h_val and h_val.lower() not in _HASH_IGNORE_VALUES:
                    hashes[hash_field] = h_val.lower()

        token = extract_execution_token(p, text_fields=[cmd_line, proc_path])

        return NormalizedTelemetryEventV1(
            normalized_event_id=f"NORM-{uuid.uuid4().hex[:12].upper()}",
            raw_event_id=raw_event.raw_event_id,
            source_event_id=src_id,
            source_timestamp=src_ts,
            normalized_timestamp=src_ts,
            event_category=EventCategory.OTHER,
            host=host,
            user=user,
            process_name=proc_name,
            process_path=proc_path,
            command_line=cmd_line,
            hashes=hashes,
            execution_token=token,
            extra_attributes=dict(p),
        )


class NormalisationEngine:
    """Central engine that registers and invokes normalisers in priority order."""

    def __init__(self, normalisers: Optional[List[BaseNormaliser]] = None):
        self.normalisers: List[BaseNormaliser] = normalisers or [
            SysmonNormaliser(),
            AuditdNormaliser(),
            GenericEDRNormaliser(),
            FallbackNormaliser(),
        ]

    def normalize(self, raw_event: RawTelemetryEventV1) -> NormalizedTelemetryEventV1:
        """Normalize a single raw event through the first matching normaliser."""
        for normaliser in self.normalisers:
            if normaliser.can_handle(raw_event):
                return normaliser.normalize(raw_event)
        # Should not be reached because FallbackNormaliser always accepts
        raise ValueError(f"No suitable normaliser found for format '{raw_event.source_format}'")

    def normalize_batch(
        self, raw_events: Sequence[RawTelemetryEventV1]
    ) -> List[NormalizedTelemetryEventV1]:
        """Normalize a sequence of raw telemetry events."""
        return [self.normalize(event) for event in raw_events]
