"""Streaming JSONL import, serialization, and schema validation."""

import json
from pathlib import Path
from typing import Any, Dict, Generic, Iterable, List, Optional, TextIO, Type, TypeVar, Union
from pydantic import BaseModel, ValidationError

T = TypeVar("T", bound=BaseModel)


class JSONLLineError(BaseModel):
    """Details of a failed record validation during JSONL processing."""
    line_number: int
    raw_content: str
    error_type: str
    error_message: str


class JSONLValidationReport(BaseModel, Generic[T]):
    """Aggregated report of JSONL file or stream validation."""
    total_lines: int = 0
    valid_count: int = 0
    error_count: int = 0
    errors: List[JSONLLineError] = []
    records: List[T] = []
    record_line_numbers: List[int] = []

    @property
    def is_valid(self) -> bool:
        """True if all non-empty lines were successfully validated with zero errors."""
        return self.error_count == 0 and self.valid_count > 0


def load_jsonl_raw(source: Union[str, Path, TextIO]) -> List[Dict[str, Any]]:
    """Load JSONL lines as raw dictionaries, skipping malformed lines.

    Malformed JSON lines are silently skipped so that a single corrupted
    record cannot abort ingestion of the remaining valid records.  This
    is consistent with the fault-isolation guarantee already provided by
    :func:`validate_jsonl_stream`.

    Args:
        source: File path or open text stream.

    Returns:
        List of parsed JSON dictionaries (one per successfully decoded line).
    """
    records: List[Dict[str, Any]] = []

    if isinstance(source, (str, Path)):
        with open(source, "r", encoding="utf-8") as f:
            lines = f.readlines()
    else:
        lines = source.readlines()

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        try:
            records.append(json.loads(stripped))
        except json.JSONDecodeError:
            # Skip malformed lines; partial import is preferred over full abort.
            continue

    return records


def validate_jsonl_stream(
    lines: Iterable[str],
    schema_cls: Type[T],
) -> JSONLValidationReport[T]:
    """Validate a sequence of lines against a Pydantic schema model.

    Errors are collected per line with line numbers and messages, without
    failing the entire ingestion process.

    Args:
        lines: Sequence of string lines.
        schema_cls: Pydantic model class to validate against.

    Returns:
        JSONLValidationReport containing parsed records and collected errors.
    """
    report = JSONLValidationReport[T]()

    for idx, raw_line in enumerate(lines, start=1):
        report.total_lines += 1
        line = raw_line.strip()
        if not line:
            # Cleanly skip empty lines without counting as errors
            continue

        try:
            data = json.loads(line)
        except json.JSONDecodeError as exc:
            report.error_count += 1
            report.errors.append(
                JSONLLineError(
                    line_number=idx,
                    raw_content=line[:200],
                    error_type="JSONDecodeError",
                    error_message=f"Invalid JSON syntax: {str(exc)}",
                )
            )
            continue

        if not isinstance(data, dict):
            report.error_count += 1
            report.errors.append(
                JSONLLineError(
                    line_number=idx,
                    raw_content=line[:200],
                    error_type="InvalidRecordFormat",
                    error_message="JSONL line must be a JSON object (dictionary)",
                )
            )
            continue

        try:
            record = schema_cls.model_validate(data)
            report.records.append(record)
            report.record_line_numbers.append(idx)
            report.valid_count += 1
        except ValidationError as exc:
            report.error_count += 1
            report.errors.append(
                JSONLLineError(
                    line_number=idx,
                    raw_content=line[:200],
                    error_type="ValidationError",
                    error_message=str(exc),
                )
            )

    return report


def validate_jsonl_file(
    filepath: Union[str, Path],
    schema_cls: Type[T],
) -> JSONLValidationReport[T]:
    """Validate a JSONL file on disk against a Pydantic schema model."""
    path = Path(filepath)
    if not path.is_file():
        raise FileNotFoundError(f"JSONL file not found at: {filepath}")

    with open(path, "r", encoding="utf-8") as f:
        return validate_jsonl_stream(f, schema_cls)


def write_jsonl(
    records: Iterable[Union[BaseModel, Dict[str, Any]]],
    filepath: Union[str, Path],
) -> int:
    """Serialize a sequence of Pydantic models or dicts to a JSONL file.

    Args:
        records: Iterable of models or dicts.
        filepath: Destination file path.

    Returns:
        Number of records written.
    """
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)

    count = 0
    with open(path, "w", encoding="utf-8") as f:
        for item in records:
            if isinstance(item, BaseModel):
                json_str = item.model_dump_json()
            else:
                json_str = json.dumps(item, default=str)
            f.write(json_str + "\n")
            count += 1

    return count
