"""UM-DR-44 B9 (part 2) — doctor probe slugs must match the router.

``scripts/doctor.py`` documents the contract itself: "The doctor and
the real router MUST stay in sync — if a slug is ever bumped here,
bump it in llm.py too (and vice versa), otherwise the doctor can
report a provider as ACTIVE while the real router 404s."  No gate
enforced it, and the drift re-appeared:

* router (``_TASK_PREFERENCE_ORDER``):  openrouter
  ``google/gemma-4-31b-it:free``, gemini ``gemini-2.5-flash``;
* doctor (``_PROBE_MODELS``): openrouter
  ``meta-llama/llama-3.3-70b-instruct:free``, gemini ``gemini-2.0-flash``.

Fix contract:

* for every provider present in BOTH the doctor's ``_PROBE_MODELS``
  and the router's preference chains, the doctor slug must EQUAL the
  router slug (the router is the source of truth — the doctor probes
  what the router would actually call);
* a structural test (not value-copy) so future slug bumps stay honest.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_doctor():
    spec = importlib.util.spec_from_file_location(
        "doctor_script", REPO_ROOT / "scripts" / "doctor.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _router_models_by_provider() -> dict[str, str]:
    from webpent.shared.llm import _TASK_PREFERENCE_ORDER

    models: dict[str, str] = {}
    for chain in _TASK_PREFERENCE_ORDER.values():
        for provider, model in chain:
            models.setdefault(provider, model)
    return models


class TestDoctorSlugSync:
    def test_openrouter_slug_matches_router(self) -> None:
        doctor = _load_doctor()
        router = _router_models_by_provider()
        assert (
            doctor._PROBE_MODELS["openrouter"] == router["openrouter"]
        ), "doctor openrouter slug drifted from the router chain"

    def test_gemini_slug_matches_router(self) -> None:
        doctor = _load_doctor()
        router = _router_models_by_provider()
        assert (
            doctor._PROBE_MODELS["gemini"] == router["gemini"]
        ), "doctor gemini slug drifted from the router chain"

    def test_every_shared_provider_matches(self) -> None:
        """Full structural contract: no shared provider may drift."""
        doctor = _load_doctor()
        router = _router_models_by_provider()
        shared = set(doctor._PROBE_MODELS) & set(router)
        assert shared, "contract became vacuous — no shared providers"
        drifted = {
            p: (doctor._PROBE_MODELS[p], router[p])
            for p in sorted(shared)
            if doctor._PROBE_MODELS[p] != router[p]
        }
        assert not drifted, f"doctor/router slug drift: {drifted}"
