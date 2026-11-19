"""Bounded trajectory surface backed by the canonical observability recorder."""

from collections.abc import Mapping
from typing import Any

from webpent.shared.evaluation import ObservabilityRecorder


class TrajectoryStore:
    """Store only redacted, bounded run events; never raw credentials or prompts."""

    def __init__(self, *, max_events: int = 2000) -> None:
        self._recorder = ObservabilityRecorder(max_events=max_events)

    def append(
        self,
        event_type: str,
        *,
        run_id: str = "",
        engagement_id: str = "",
        trace_id: str = "",
        **payload: Any,
    ) -> None:
        self._recorder.emit(
            event_type,
            run_id=run_id,
            engagement_id=engagement_id,
            trace_id=trace_id,
            **payload,
        )

    def snapshot(self) -> tuple[Mapping[str, Any], ...]:
        return self._recorder.snapshot()


__all__ = ["TrajectoryStore"]
