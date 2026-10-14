"""Base abstraction for telemetry event normalisation."""

from abc import ABC, abstractmethod
from proofshield.schemas.telemetry import (
    NormalizedTelemetryEventV1,
    RawTelemetryEventV1,
)


class BaseNormaliser(ABC):
    """Abstract base class for telemetry provider normalisers."""

    @abstractmethod
    def can_handle(self, raw_event: RawTelemetryEventV1) -> bool:
        """Return True if this normaliser can process the raw event."""
        pass

    @abstractmethod
    def normalize(self, raw_event: RawTelemetryEventV1) -> NormalizedTelemetryEventV1:
        """Transform raw telemetry into a canonical NormalizedTelemetryEventV1.

        Must guarantee preservation of source_event_id and source_timestamp.
        """
        pass
