"""Additive canonical adapters for existing WebPent tool wrappers.

The wrappers remain unchanged and keep their historical return types.  The
facade records execution metadata and converts heterogeneous outputs into
``Observation`` objects.  Raw commands and raw output are represented by
fingerprints/references only, so this layer is safe to persist in checkpoint
state and reports.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any

from webpent.models.evidence import (
    AdapterResult,
    EvidenceRef,
    Observation,
    ScopeDecision,
    ToolExecution,
    command_fingerprint,
    make_evidence_ref,
    redact_sensitive,
)
from webpent.shared.exceptions import (
    MissingToolInputError,
    ToolExecutionError,
    ToolNotFoundError,
)

logger = logging.getLogger(__name__)

Runner = Callable[..., Any]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _records(result: Any) -> list[Any]:
    if result is None:
        return []
    if isinstance(result, (list, tuple, set)):
        return list(result)
    return [result]


def _redaction_status(changed: bool) -> str:
    return "redacted" if changed else "clean"


def _safe_error(exc: BaseException) -> str:
    clean, _ = redact_sensitive(str(exc))
    return str(clean)[:500]


class ToolAdapter:
    """Execute one existing wrapper and emit a canonical ``AdapterResult``.

    ``runner`` is deliberately injected, which makes this facade easy to test
    with deterministic fakes and avoids changing any agent call site until a
    later rollout phase enables it behind feature flags.
    """

    def __init__(
        self,
        *,
        name: str,
        runner: Runner,
        category: str,
        version: str = "unknown",
    ) -> None:
        self.name = name
        self.runner = runner
        self.category = category
        self.version = version

    def run(
        self,
        target: str,
        *args: Any,
        asset: str | None = None,
        endpoint: str | None = None,
        method: str | None = None,
        parameters: dict[str, Any] | None = None,
        scope_decision: ScopeDecision = "not_checked",
        command: Sequence[str] | None = None,
        timeout_seconds: float | None = None,
        **kwargs: Any,
    ) -> AdapterResult:
        """Run the legacy wrapper and normalize success/failure metadata."""
        started = _now()
        clean_parameters, parameter_redacted = redact_sensitive(parameters or {})
        status = "success"
        return_code: int | None = 0
        error_class: str | None = None
        error_message: str | None = None
        raw_output: Any = None

        try:
            raw_output = self.runner(target, *args, **kwargs)
        except ToolExecutionError as exc:
            raw_output = exc.stdout or None
            return_code = exc.returncode
            status = "partial" if exc.stdout else "failed"
            error_class = exc.__class__.__name__
            error_message = _safe_error(exc)
        except (MissingToolInputError, ToolNotFoundError) as exc:
            status = "not_run"
            return_code = None
            error_class = exc.__class__.__name__
            error_message = _safe_error(exc)
        except Exception as exc:  # adapter boundary must not hide runner bugs
            status = "failed"
            return_code = None
            error_class = exc.__class__.__name__
            error_message = _safe_error(exc)
            logger.exception("Canonical adapter %s failed", self.name)

        finished = _now()
        records = _records(raw_output)
        if status == "success" and not records:
            status = "empty"

        output_ref: EvidenceRef | None = None
        raw_bytes: int | None = None
        output_redacted = False
        if raw_output is not None:
            output_ref = make_evidence_ref(
                raw_output,
                locator=f"tool://{self.name}/{started.isoformat()}",
            )
            clean_output, output_redacted = redact_sensitive(raw_output)
            raw_bytes = len(str(clean_output).encode("utf-8"))

        redacted = parameter_redacted or output_redacted
        execution = ToolExecution(
            tool_name=self.name,
            tool_version=self.version,
            target=target,
            asset=asset,
            parameters=clean_parameters,
            command_fingerprint=command_fingerprint(command),
            started_at=started,
            finished_at=finished,
            status=status,
            return_code=return_code,
            timeout_seconds=timeout_seconds,
            raw_output_ref=output_ref,
            raw_output_bytes=raw_bytes,
            scope_decision=scope_decision,
            redaction_status=_redaction_status(redacted),
            error_class=error_class,
        )

        observations: list[Observation] = []
        for index, record in enumerate(records):
            clean_record, record_redacted = redact_sensitive(record)
            ref = make_evidence_ref(
                record,
                locator=f"tool://{self.name}/{started.isoformat()}/observation/{index}",
                kind="observation_value",
            )
            observations.append(
                Observation(
                    id=f"obs_{self.name}_{index}_{ref.digest[-16:]}",
                    target=target,
                    asset=asset,
                    endpoint=endpoint,
                    method=method,
                    parameters=clean_parameters,
                    observed_at=finished,
                    tool_name=self.name,
                    tool_version=self.version,
                    status="partial" if status == "partial" else "success",
                    value=clean_record,
                    confidence=0.75 if isinstance(record, dict) else 0.6,
                    scope_decision=scope_decision,
                    redaction_status=_redaction_status(record_redacted or redacted),
                    evidence_refs=[ref.id],
                    metadata={"category": self.category, "sequence": index},
                )
            )

        return AdapterResult(
            execution=execution,
            observations=observations,
            error=error_message,
        )


def _httpx_target_runner(target: str, *args: Any, **kwargs: Any) -> Any:
    from webpent.tools.recon.httpx import run_httpx

    return run_httpx([target], *args, **kwargs)


def _katana_target_runner(target: str, *args: Any, **kwargs: Any) -> Any:
    from webpent.tools.recon.katana import run_katana

    return run_katana(target, *args, **kwargs)


def _nuclei_target_runner(target: str, *args: Any, **kwargs: Any) -> Any:
    from webpent.tools.recon.nuclei import run_nuclei

    return run_nuclei(target, *args, **kwargs)


def _subfinder_target_runner(target: str, *args: Any, **kwargs: Any) -> Any:
    from webpent.tools.recon.subfinder import run_subfinder

    return run_subfinder(target, *args, **kwargs)


def _ffuf_target_runner(target: str, *args: Any, **kwargs: Any) -> Any:
    from webpent.tools.recon.ffuf import run_ffuf

    wordlist_path = kwargs.get("wordlist_path")
    if not isinstance(wordlist_path, str) or not wordlist_path.strip():
        raise MissingToolInputError("ffuf", "wordlist_path")
    forwarded = dict(kwargs)
    forwarded.pop("wordlist_path", None)
    return run_ffuf(target, wordlist_path, *args, **forwarded)


def _arjun_target_runner(target: str, *args: Any, **kwargs: Any) -> Any:
    from webpent.tools.recon.arjun import run_arjun

    return run_arjun(target, *args, **kwargs)


def _dalfox_target_runner(target: str, *args: Any, **kwargs: Any) -> Any:
    from webpent.tools.exploitation.dalfox import run_dalfox

    return run_dalfox(target, *args, **kwargs)


def _sqlmap_target_runner(target: str, *args: Any, **kwargs: Any) -> Any:
    from webpent.tools.exploitation.sqlmap import run_sqlmap

    return run_sqlmap(target, *args, **kwargs)


@lru_cache(maxsize=1)
def builtin_adapters() -> dict[str, ToolAdapter]:
    """Return lazy wrappers for one representative tool per recon family."""
    return {
        "httpx": ToolAdapter(
            name="httpx",
            runner=_httpx_target_runner,
            category="recon",
        ),
        "katana": ToolAdapter(
            name="katana",
            runner=_katana_target_runner,
            category="recon",
        ),
        "nuclei": ToolAdapter(
            name="nuclei",
            runner=_nuclei_target_runner,
            category="recon",
        ),
        "subfinder": ToolAdapter(
            name="subfinder",
            runner=_subfinder_target_runner,
            category="recon",
        ),
        "ffuf": ToolAdapter(
            name="ffuf",
            runner=_ffuf_target_runner,
            category="recon",
        ),
        "arjun": ToolAdapter(
            name="arjun",
            runner=_arjun_target_runner,
            category="recon",
        ),
        "dalfox": ToolAdapter(
            name="dalfox",
            runner=_dalfox_target_runner,
            category="exploitation",
        ),
        "sqlmap": ToolAdapter(
            name="sqlmap",
            runner=_sqlmap_target_runner,
            category="exploitation",
        ),
    }


def get_tool_adapter(name: str) -> ToolAdapter:
    """Resolve a builtin adapter without altering the legacy registry."""
    try:
        return builtin_adapters()[name.strip().lower()]
    except KeyError as exc:
        raise KeyError(f"No canonical adapter registered for {name!r}") from exc


def adapt_result(
    *,
    tool_name: str,
    target: str,
    result: Any,
    asset: str | None = None,
    endpoint: str | None = None,
    method: str | None = None,
    parameters: dict[str, Any] | None = None,
    scope_decision: ScopeDecision = "not_checked",
    tool_version: str = "unknown",
) -> AdapterResult:
    """Normalize an already-returned legacy result without re-running a tool."""
    adapter = ToolAdapter(
        name=tool_name,
        runner=lambda _target: result,
        category="legacy_result",
        version=tool_version,
    )
    return adapter.run(
        target,
        asset=asset,
        endpoint=endpoint,
        method=method,
        parameters=parameters,
        scope_decision=scope_decision,
    )
