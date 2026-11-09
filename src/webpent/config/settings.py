# src/webpent/config/settings.py
"""webpent.config.settings

Global configuration for the WebPent Framework V2.

Loads environment variables via pydantic-settings and exposes a cached
``Settings`` singleton. All values have sensible defaults so the framework
can boot in development without an explicit ``.env`` file.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import AliasChoices, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class LLMProvider(str, Enum):
    """Supported LLM backend providers (legacy single-provider selector)."""

    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GROQ = "groq"
    LOCAL = "local"


class LogLevel(str, Enum):
    """Standard Python logging levels."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class ScanMode(str, Enum):
    """Runtime authority profile for autonomous behavior."""

    LEGACY = "legacy"
    SAFE_SMART = "safe-smart"
    AUTHORIZED_ACTIVE = "authorized-active"


class ScanProfile(str, Enum):
    """User-facing composition profile layered over the authority mode."""

    LEGACY = "legacy"
    SMART = "smart"
    SMART_OBSERVE = "smart-observe"
    SINGLE_TARGET_SAFE = "single-target-safe"
    AUTHENTICATED_SINGLE_TARGET = "authenticated-single-target"
    AUTHORIZED_ACTIVE = "authorized-active"
    VIP_QUALIFICATION = "vip-qualification"


_PROFILE_TO_SCAN_MODE: dict[ScanProfile, ScanMode] = {
    ScanProfile.LEGACY: ScanMode.LEGACY,
    ScanProfile.SMART: ScanMode.SAFE_SMART,
    ScanProfile.SMART_OBSERVE: ScanMode.SAFE_SMART,
    ScanProfile.SINGLE_TARGET_SAFE: ScanMode.SAFE_SMART,
    ScanProfile.AUTHENTICATED_SINGLE_TARGET: ScanMode.SAFE_SMART,
    ScanProfile.AUTHORIZED_ACTIVE: ScanMode.AUTHORIZED_ACTIVE,
    ScanProfile.VIP_QUALIFICATION: ScanMode.AUTHORIZED_ACTIVE,
}


def resolve_scan_profile(value: str | ScanProfile | None) -> tuple[ScanProfile, ScanMode]:
    """Resolve a public profile into its authority mode without enabling risk implicitly."""
    if value is None:
        return ScanProfile.LEGACY, ScanMode.LEGACY
    try:
        profile = (
            value
            if isinstance(value, ScanProfile)
            else ScanProfile(str(value).strip().lower())
        )
    except ValueError as exc:
        allowed = ", ".join(item.value for item in ScanProfile)
        raise ValueError(f"unsupported scan profile; choose one of: {allowed}") from exc
    return profile, _PROFILE_TO_SCAN_MODE[profile]


def profile_requires_proof_bundle(value: str | ScanProfile | None) -> bool:
    """Return whether a public scan profile requires sealed proof for promotion."""
    if value is None:
        return False
    profile, _ = resolve_scan_profile(value)
    return profile is ScanProfile.VIP_QUALIFICATION


def deployment_requires_proof_bundle(value: str | EnvironmentProfile | None) -> bool:
    """Require sealed proof in non-lab deployments, regardless of opt-in flags."""
    if value is None:
        return False
    try:
        profile = (
            value
            if isinstance(value, EnvironmentProfile)
            else EnvironmentProfile(str(value).strip().lower())
        )
    except ValueError:
        return True
    return profile in {
        EnvironmentProfile.QUALIFICATION,
        EnvironmentProfile.STAGING,
        EnvironmentProfile.PRODUCTION,
    }


class EnvironmentProfile(str, Enum):
    """Deployment posture used by startup security gates."""

    DEV = "dev"
    LAB = "lab"
    QUALIFICATION = "qualification"
    STAGING = "staging"
    PRODUCTION = "production"


class Settings(BaseSettings):
    """Framework-wide settings.

    All fields map 1:1 to environment variables (case-insensitive). Secret
    values (``*_API_KEY``) should be supplied via ``.env`` or the process
    environment — never committed to source control.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        # RUNTIME-INTEGRATION FIX (RIT-1): accept keyword arguments by field
        # name as well as validation_alias. Without this, programmatic
        # construction like ``Settings(llm_enabled=False)`` was silently
        # DROPPED for every field that declares a validation_alias (the
        # field name is not a valid alias target unless populate_by_name is
        # set), so the fail-closed switch defaulted back to ``True``.
        populate_by_name=True,
    )

    _PROVIDER_KEY_FIELDS = frozenset(
        {
            "openai_api_key", "anthropic_api_key", "groq_api_key", "zai_api_key",
            "openrouter_api_key", "cerebras_api_key", "github_api_key", "mistral_api_key",
            "gemini_api_key", "cohere_api_key", "cloudflare_api_key", "local_llm_api_key",
        }
    )

    _explicit_construction: bool = False

    def __init__(self, **values: object) -> None:
        """Keep explicit Settings construction isolated from ambient secrets.

        ``Settings()`` remains environment-backed for the application singleton.
        ``Settings(llm_enabled=True)`` and other programmatic configurations are
        testable and deterministic: only provider keys explicitly supplied in
        that constructor participate in routing.
        """
        explicit = bool(values)
        super().__init__(**values)
        object.__setattr__(self, "_explicit_construction", explicit)
        if explicit:
            for field_name in self._PROVIDER_KEY_FIELDS:
                if field_name not in values:
                    object.__setattr__(self, field_name, None)

    # -- LLM API keys (legacy providers) ------------------------------------
    openai_api_key: str | None = Field(default=None, description="OpenAI API key.")
    # UNIFIED MERGE (2026-11-02, Phase 2 P2-2): flag-gate fields the
    # merged-in v4 modules read (webpent.learning.feedback_loop,
    # webpent.scheduler.campaign_scheduler) but the 0.34.0 Settings
    # class dropped. Fail-closed defaults: gates OFF, paths empty —
    # the modules themselves refuse to run on the defaults.
    enable_feedback_loop: bool = Field(
        default=False,
        description="Operator gate for the market feedback loop "
        "(fail-closed; also requires feedback_outcomes_path).",
    )
    feedback_outcomes_path: str = Field(
        default="",
        description="Local append-only JSONL sink for feedback "
        "outcomes; empty disables the loop regardless of the flag.",
    )
    enable_scheduler: bool = Field(
        default=False,
        description="Operator gate for the campaign scheduler "
        "(fail-closed).",
    )
    scheduler_state_path: str = Field(
        default="",
        description="Directory for per-campaign scheduler state; "
        "empty refuses to run regardless of the flag.",
    )
    openai_base_url: str = Field(
        default="https://api.openai.com/v1",
        validation_alias=AliasChoices("OPENAI_BASE_URL", "OPENAI_API_BASE"),
        description="OpenAI or compatible endpoint base URL.",
    )
    openai_model: str | None = Field(
        default=None,
        description="Optional model override for the OpenAI-compatible provider.",
    )
    anthropic_api_key: str | None = Field(default=None, description="Anthropic API key.")
    groq_api_key: str | None = Field(default=None, description="Groq API key.")
    local_llm_url: str = Field(
        default="http://localhost:11434/v1",
        description="Base URL for a local OpenAI-compatible LLM endpoint.",
    )
    local_llm_api_key: str | None = Field(
        default=None, description="Optional API key for the local LLM endpoint."
    )
    local_llm_enabled: bool = Field(
        default=False,
        description="Allow the local OpenAI-compatible endpoint into router fallback chains.",
    )
    local_llm_model: str = Field(
        default="llama3.1:8b",
        description="Model identifier served by the local endpoint.",
    )

    # -- LLM API keys (task-based router providers) -------------------------
    zai_api_key: str | None = Field(default=None, description="Z.AI API key.")
    openrouter_api_key: str | None = Field(default=None, description="OpenRouter API key.")
    cerebras_api_key: str | None = Field(default=None, description="Cerebras API key.")
    github_api_key: str | None = Field(default=None, description="GitHub Models API key.")
    mistral_api_key: str | None = Field(default=None, description="Mistral API key.")
    gemini_api_key: str | None = Field(default=None, description="Google Gemini API key.")
    cohere_api_key: str | None = Field(default=None, description="Cohere API key.")
    cloudflare_api_key: str | None = Field(
        default=None, description="Cloudflare Workers AI API key."
    )
    cloudflare_account_id: str | None = Field(
        default=None, description="Cloudflare account ID required for Workers AI routing."
    )

    # -- Provider-specific model overrides -----------------------------------
    # These remain optional so the bounded task preference chains stay the
    # default. Operators can pin a currently available model without editing
    # source code or changing the safety/evidence kernel.
    groq_model: str | None = Field(default=None, validation_alias="GROQ_MODEL")
    openrouter_model: str | None = Field(default=None, validation_alias="OPENROUTER_MODEL")
    cerebras_model: str | None = Field(default=None, validation_alias="CEREBRAS_MODEL")
    github_model: str | None = Field(default=None, validation_alias="GITHUB_MODEL")
    zai_model: str | None = Field(default=None, validation_alias="ZAI_MODEL")
    mistral_model: str | None = Field(default=None, validation_alias="MISTRAL_MODEL")
    gemini_model: str | None = Field(default=None, validation_alias="GEMINI_MODEL")
    cohere_model: str | None = Field(default=None, validation_alias="COHERE_MODEL")
    cloudflare_model: str | None = Field(default=None, validation_alias="CLOUDFLARE_MODEL")

    # -- LLM selection / generation -----------------------------------------
    default_llm_provider: LLMProvider = Field(
        default=LLMProvider.ANTHROPIC,
        description="Default LLM provider used by legacy code paths.",
    )
    default_llm_model: str = Field(
        default="claude-sonnet-5",
        description="Default model identifier for the selected provider.",
    )
    llm_temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    llm_max_tokens: int = Field(default=4096, gt=0)
    llm_request_timeout: int = Field(default=60, gt=0)
    cheap_model: str | None = Field(
        default=None,
        validation_alias=AliasChoices("CHEAP_MODEL", "WEBPENT_CHEAP_MODEL"),
        description=(
            "Optional model name for short classify/sort prompts. The provider is "
            "selected from the normal configured fallback chain."
        ),
    )
    prompt_cache_enabled: bool = Field(
        default=True,
        validation_alias=AliasChoices("PROMPT_CACHE_ENABLED", "WEBPENT_PROMPT_CACHE_ENABLED"),
        description="Enable bounded cache-control metadata on repeated fixed-context prompts.",
    )
    llm_max_calls_per_run: int = Field(
        default=32,
        ge=1,
        le=10000,
        validation_alias=AliasChoices(
            "LLM_MAX_CALLS_PER_RUN", "WEBPENT_LLM_MAX_CALLS_PER_RUN"
        ),
        description=(
            "Hard upper bound on provider attempts in one managed graph run. "
            "Fallback attempts count; no provider request is made after exhaustion."
        ),
    )
    llm_warning_tokens_per_run: int = Field(
        default=100000,
        ge=0,
        le=100000000,
        validation_alias=AliasChoices(
            "LLM_WARNING_TOKENS_PER_RUN", "WEBPENT_LLM_WARNING_TOKENS_PER_RUN"
        ),
        description=(
            "Redaction-safe advisory warning threshold for reported tokens in one run. "
            "It is not a price estimate and never guesses provider pricing."
        ),
    )
    llm_enabled: bool = Field(
        default=True,
        validation_alias=AliasChoices("LLM_ENABLED", "WEBPENT_LLM_ENABLED"),
        description=(
            "Allow AI-assisted reasoning nodes to call configured providers. "
            "Set LLM_ENABLED=false (or WEBPENT_LLM_ENABLED=false) for "
            "deterministic offline runs; nodes then use bounded fallbacks."
        ),
    )

    # -- Framework behaviour -------------------------------------------------
    debug: bool = Field(default=False, description="Enable verbose debug logging.")
    environment_profile: EnvironmentProfile = Field(
        default=EnvironmentProfile.LAB,
        validation_alias=AliasChoices(
            "environment_profile",
            "ENVIRONMENT_PROFILE",
            "WEBPENT_ENVIRONMENT_PROFILE",
        ),
        description=(
            "Explicit deployment posture. lab preserves local loopback compatibility; "
            "staging and production require authentication and secure transport posture."
        ),
    )
    scan_mode: ScanMode = Field(
        default=ScanMode.LEGACY,
        validation_alias=AliasChoices(
            "scan_mode",
            "SCAN_MODE",
            "WEBPENT_SCAN_MODE",
            "SCAN_PROFILE",
        ),
        description=(
            "Authority profile. legacy preserves the existing path; safe-smart is "
            "read-only and evidence-first; authorized-active permits only policy-checked "
            "active workflows."
        ),
    )
    smart_max_actions: int = Field(
        default=100,
        gt=0,
        le=10000,
        validation_alias=AliasChoices(
            "smart_max_actions", "SMART_MAX_ACTIONS", "WEBPENT_SMART_MAX_ACTIONS"
        ),
        description="Hard upper bound on autonomous actions in one engagement.",
    )
    smart_action_budget: float = Field(
        default=100.0,
        gt=0.0,
        le=100000.0,
        validation_alias=AliasChoices(
            "smart_action_budget", "SMART_ACTION_BUDGET", "WEBPENT_SMART_ACTION_BUDGET"
        ),
        description="Bounded cost budget for policy-authorized autonomous actions.",
    )
    smart_auto_approve: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "smart_auto_approve", "SMART_AUTO_APPROVE", "WEBPENT_SMART_AUTO_APPROVE"
        ),
        description="Explicit operator approval shortcut; never bypasses scope or risk gates.",
    )
    smart_require_idempotency: bool = Field(
        default=True,
        validation_alias=AliasChoices(
            "smart_require_idempotency",
            "SMART_REQUIRE_IDEMPOTENCY",
            "WEBPENT_SMART_REQUIRE_IDEMPOTENCY",
        ),
        description="Require an idempotency key for every policy-authorized action.",
    )
    # Addendum: Gmail-backed test identity provisioning is opt-in and bounded.
    identity_provisioning_enabled: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "identity_provisioning_enabled",
            "IDENTITY_PROVISIONING_ENABLED",
            "WEBPENT_IDENTITY_PROVISIONING_ENABLED",
        ),
        description="Enable dedicated test-mailbox identity provisioning; default OFF.",
    )
    identity_mailbox_provider: str = Field(
        default="gmail_api",
        validation_alias=AliasChoices(
            "identity_mailbox_provider",
            "IDENTITY_MAILBOX_PROVIDER",
            "WEBPENT_IDENTITY_MAILBOX_PROVIDER",
        ),
        description="Mailbox backend: gmail_api or imap; no browser Gmail login.",
    )
    identity_mailbox_credentials_ref: str | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "identity_mailbox_credentials_ref",
            "IDENTITY_MAILBOX_CREDENTIALS_REF",
            "WEBPENT_IDENTITY_MAILBOX_CREDENTIALS_REF",
        ),
        description="Opaque secret-manager reference; inline mailbox credentials are denied.",
    )
    identity_verification_timeout_seconds: int = Field(
        default=120,
        ge=1,
        le=600,
        validation_alias=AliasChoices(
            "identity_verification_timeout_seconds",
            "IDENTITY_VERIFICATION_TIMEOUT_SECONDS",
            "WEBPENT_IDENTITY_VERIFICATION_TIMEOUT_SECONDS",
        ),
    )
    identity_max_signups_per_engagement: int = Field(
        default=5,
        ge=0,
        le=50,
        validation_alias=AliasChoices(
            "identity_max_signups_per_engagement",
            "IDENTITY_MAX_SIGNUPS_PER_ENGAGEMENT",
            "WEBPENT_IDENTITY_MAX_SIGNUPS_PER_ENGAGEMENT",
        ),
    )

    # -- bbscout provider-source bridge ---------------------------------------
    # bbscout may supply an advisory Target Package v2, but it cannot grant
    # action authority. Browser/signup/provider-submission paths are explicitly
    # denied here and require a separate reviewed implementation if ever added.
    bbscout_enabled: bool = Field(
        default=False,
        validation_alias=AliasChoices("bbscout_enabled", "BBSCOUT_ENABLED"),
        description="Enable local bbscout package admission; default is disabled.",
    )
    bbscout_package_path: str = Field(
        default="",
        validation_alias=AliasChoices("bbscout_package_path", "BBSCOUT_PACKAGE_PATH"),
        description="Optional local Target Package v2 JSON path; never a credential path.",
    )
    bbscout_mode: str = Field(
        default="offline",
        validation_alias=AliasChoices("bbscout_mode", "BBSCOUT_MODE"),
        description="bbscout bridge mode: offline or live; live requires verified signature.",
    )
    bbscout_require_verified_signature: bool = Field(
        default=True,
        validation_alias=AliasChoices(
            "bbscout_require_verified_signature", "BBSCOUT_REQUIRE_VERIFIED_SIGNATURE"
        ),
        description="Keep detached signature verification mandatory for any live handoff.",
    )
    bbscout_allowed_provider_ids: str = Field(
        default="",
        validation_alias=AliasChoices(
            "bbscout_allowed_provider_ids", "BBSCOUT_ALLOWED_PROVIDER_IDS"
        ),
        description="Comma-separated provider IDs allowlisted by the operator.",
    )
    bbscout_allowed_program_ids: str = Field(
        default="",
        validation_alias=AliasChoices("bbscout_allowed_program_ids", "BBSCOUT_ALLOWED_PROGRAM_IDS"),
        description="Comma-separated program IDs allowlisted by the operator.",
    )
    bbscout_browser_enabled: bool = Field(
        default=False,
        validation_alias=AliasChoices("bbscout_browser_enabled", "BBSCOUT_BROWSER_ENABLED"),
        description="Browser handoff switch; remains disabled by default.",
    )
    bbscout_browser_read_only: bool = Field(
        default=True,
        validation_alias=AliasChoices("bbscout_browser_read_only", "BBSCOUT_BROWSER_READ_ONLY"),
        description="Browser handoff must be read-only and cannot submit forms.",
    )
    bbscout_signup_enabled: bool = Field(
        default=False,
        validation_alias=AliasChoices("bbscout_signup_enabled", "BBSCOUT_SIGNUP_ENABLED"),
        description="Blocked policy flag; automatic account creation is not supported.",
    )
    bbscout_provider_submission_enabled: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "bbscout_provider_submission_enabled", "BBSCOUT_PROVIDER_SUBMISSION_ENABLED"
        ),
        description="Blocked policy flag; automatic bounty-platform submission is not supported.",
    )
    bbscout_credentials_ref: str | None = Field(
        default=None,
        validation_alias=AliasChoices("bbscout_credentials_ref", "BBSCOUT_CREDENTIALS_REF"),
        description="Opaque secret-manager reference only; raw credentials/cookies are denied.",
    )

    smart_require_proof_bundle: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "smart_require_proof_bundle",
            "SMART_REQUIRE_PROOF_BUNDLE",
            "WEBPENT_SMART_REQUIRE_PROOF_BUNDLE",
        ),
        description=(
            "Require sealed replayable proof bundles for strict Tool-Confirmed exports."
        ),
    )
    smart_max_replan_rounds: int = Field(
        default=3,
        ge=0,
        le=10,
        validation_alias=AliasChoices(
            "smart_max_replan_rounds",
            "SMART_MAX_REPLAN_ROUNDS",
            "WEBPENT_SMART_MAX_REPLAN_ROUNDS",
        ),
        description="Bounded number of smart campaign replanning rounds per engagement.",
    )
    smart_campaign_task_cap: int = Field(
        default=6,
        gt=0,
        le=10,
        validation_alias=AliasChoices(
            "smart_campaign_task_cap",
            "SMART_CAMPAIGN_TASK_CAP",
            "WEBPENT_SMART_CAMPAIGN_TASK_CAP",
        ),
        description=(
            "Bounded active smart-campaign tasks per pass. "
            "Safe-smart remains capped at three."
        ),
    )
    log_level: LogLevel = Field(default=LogLevel.INFO)
    max_graph_steps: int = Field(default=50, gt=0)
    playwright_adapter_enabled: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "playwright_adapter_enabled",
            "PLAYWRIGHT_ADAPTER_ENABLED",
            "WEBPENT_PLAYWRIGHT_ADAPTER_ENABLED",
        ),
        description=(
            "Explicitly enable the typed, observation-only Playwright transport. "
            "It remains disabled unless Playwright preflight also succeeds."
        ),
    )
    playwright_browser_timeout_ms: int = Field(
        default=15_000,
        ge=100,
        le=120_000,
        validation_alias=AliasChoices(
            "playwright_browser_timeout_ms",
            "PLAYWRIGHT_BROWSER_TIMEOUT_MS",
            "WEBPENT_PLAYWRIGHT_BROWSER_TIMEOUT_MS",
        ),
        description="Bounded timeout for one typed browser observation.",
    )

    # -- V55 additive architecture feature flags ----------------------------
    # These switches are intentionally disabled by default so the existing
    # linear scan graph remains the compatibility path until each capability
    # has its own contract tests and is explicitly enabled by the operator.
    enable_target_understanding: bool = Field(
        default=False,
        description=(
            "Enable evidence-backed target-understanding enrichment on top of "
            "the existing Mental Model."
        ),
    )
    enable_parallel_recon: bool = Field(
        default=False,
        description=(
            "Track 2 (VIP speed initiative, 2026-10-19): run the "
            "subdomain_takeover and cloud_storage recon nodes concurrently "
            "(same LangGraph superstep) instead of sequentially, via a "
            "recon_fanout/recon_join pair in graph/builder.py. Disabled by "
            "default; the sequential chain is unchanged when False. Both "
            "nodes' state writes land in Annotated/merge_* channels "
            "(findings, crawled_data-derived observation lists), so "
            "concurrent writes merge safely; see "
            "UNFREEZE_TRACK2_PARALLEL_RECON_20261019.md for the verified "
            "concurrency behavior (empirically confirmed against the "
            "pinned langgraph==1.2.10)."
        ),
    )
    enable_parallel_rabbit_hole_drafting: bool = Field(
        default=False,
        description=(
            "Track 3 (VIP speed initiative, 2026-10-20): draft each "
            "approved Rabbit Hole branch's 'what to do next' LLM "
            "description concurrently instead of sequentially, in "
            "rabbit_hole_node (agents/rabbit_hole/agent.py). Disabled by "
            "default; the sequential per-candidate loop is unchanged when "
            "False. Only the narrow LLM-drafting step is parallelized — "
            "the deterministic classification / loop-prevention / "
            "risk-manager / scope-re-check gate sequence that decides "
            "WHICH candidates are approved (and in what order they consume "
            "the branch budget) always runs sequentially first, exactly as "
            "before; drafting only starts after that sequential pass has "
            "already produced the final, order-dependent list of approved "
            "candidates (bounded by _MAX_BRANCHES_PER_PASS=3), so turning "
            "this on changes LLM-call wall-clock time only, never which "
            "branches are entered, their order, or any Decision Log / "
            "Goal Tree / Mental Model / ledger content. See "
            "UNFREEZE_TRACK3_RABBIT_HOLE_DRAFTING_20261020.md."
        ),
    )
    enable_attack_graph: bool = Field(
        default=False,
        description=(
            "Enable the projected Attack Graph and relational path metadata "
            "without replacing the existing findings pipeline."
        ),
    )
    enable_adaptive_hunt: bool = Field(
        default=False,
        description=(
            "Enable bounded adaptive prioritization and targeted revisit tasks "
            "after the compatibility path is verified."
        ),
    )
    enable_workflow_understanding: bool = Field(
        default=False,
        description=(
            "Enable passive workflow extraction and bounded business-logic "
            "hypotheses without changing the legacy fuzzer path."
        ),
    )
    enable_planner_decisions: bool = Field(
        default=False,
        description=(
            "Enable advisory structured planner proposals. Proposals remain "
            "non-executable and must pass deterministic policy, scope, budget, "
            "and tool-availability gates."
        ),
    )
    max_planner_decision_cost: float = Field(
        default=10.0,
        ge=0.0,
        le=100.0,
        description="Maximum estimated cost accepted for one planner proposal.",
    )
    enable_integration_agenda: bool = Field(
        default=False,
        description=(
            "Enable the Shannon-pattern integration planning lane "
            "(research agenda bridge + source-lane annotations). "
            "Advisory and planning-only; CausalGuard remains the sole "
            "verdict authority. Disabled by default."
        ),
    )
    enable_authorization_matrix: bool = Field(
        default=False,
        description=(
            "Enable bounded multi-identity authorization matrix observations. "
            "The matrix is read-only, redacted, and never auto-promotes findings."
        ),
    )
    max_authorization_matrix_rows: int = Field(default=500, gt=0, le=10000)
    max_authorization_matrix_comparisons: int = Field(default=1000, gt=0, le=20000)
    enable_idor_enumeration: bool = Field(
        default=False,
        description=(
            "Enable bounded numeric adjacent-ID enumeration for BAC candidates. "
            "Disabled by default; enumeration remains read-only and never confirms a finding."
        ),
    )
    idor_enumeration_neighbors: int = Field(default=5, ge=1, le=10)
    enable_js_intelligence: bool = Field(
        default=False,
        description=(
            "Enable bounded, static JavaScript source review. Results are "
            "redacted observations and non-destructive targeted mapping tasks."
        ),
    )
    max_js_assets: int = Field(default=50, gt=0, le=200)
    max_js_asset_bytes: int = Field(default=2_000_000, gt=0, le=20_000_000)
    max_js_routes: int = Field(default=1000, gt=0, le=5000)
    max_js_targeted_tasks: int = Field(default=1500, gt=0, le=5000)
    enable_cve_advisory_hypotheses: bool = Field(
        default=False,
        description=(
            "M3 ق6 (UM-DR-16): feed the offline CVE/KEV/EPSS advisory "
            "engine's n-day-exposure hypotheses into target_understanding's "
            "hypotheses channel. Advisory-only by construction (the records "
            "carry advisory_only/does_not_confirm pins and cve_advisory "
            "provenance); never auto-confirmed; fail-soft on any feed error."
        ),
    )
    enable_api_surface_shadow_hypotheses: bool = Field(
        default=False,
        description=(
            "M3 ق8 (UM-DR-16): derive api-surface-shadow hypotheses "
            "(undocumented JS endpoints, source-map disclosures, secret "
            "candidates, auth hints) from the JS intelligence pass into the "
            "hypotheses channel + crawled_data.shadow_endpoints projection "
            "the planner reads on replan passes. Advisory-only, fail-soft, "
            "never auto-confirmed."
        ),
    )
    enable_js_ast_reversing: bool = Field(
        default=False,
        description=(
            "M3 Fix ف3.2 (UM-DR-17): analyze in-scope JavaScript bundles "
            "with the esprima AST reverser (jsintel/js_reversing.py) instead "
            "of the legacy regex engine — constant propagation across "
            "multi-level string concatenation, template literals, call-site-"
            "verified sinks (no comment/prose false positives), literal-"
            "verified secret candidates. Graceful degradation: esprima "
            "unavailable or unparseable source falls back to the frozen "
            "regex engine with an observable js_ast_* coverage gap. "
            "Flag-off keeps the legacy engine byte-identical."
        ),
    )
    enable_family_execution_spine: bool = Field(
        default=False,
        description=(
            "M3 UM-DR-17 (tenant_isolation qualification seam, M1b "
            "residual ②): wire the causal family execution spine "
            "(families/execution_node.py — the six passive analyzers "
            "incl. tenant_isolation, deterministic validators, ProofBundle "
            "sealing, promotion) into the production graph between "
            "execution_sandbox and validator, fed by "
            "shared/family_feeds.py which derives endpoint_inventory / "
            "multi_tenant / auth_flows from the real crawled_data + "
            "identity_profiles channels. Additive-only edges (the "
            "sandbox→validator edge stays); fail-closed default False; "
            "no executor ⇒ plans_pending_execution, replays are never "
            "faked."
        ),
    )
    enable_stateful_discovery: bool = Field(
        default=False,
        description=(
            "UM-DR-28 (production discovery integration): inside the wired "
            "family_execution node, run the source-driven stateful discovery "
            "(production/stateful_discovery.py — structural case mining "
            "from the observed endpoint inventory + the observed-surface "
            "transition prober + bounded control rotation) against the "
            "campaign target through the injected/default http executor. "
            "CONFIRMED outcomes are promoted as findings with full "
            "provenance (transitions, request counts, evidence trace) and "
            "pass the node's adversarial review + self-verify like every "
            "other finding; guarded_causal_evaluate stays the only "
            "confirmation authority. Fail-closed default False; fail-soft "
            "on internal errors (honest error status, campaign continues); "
            "scope enforced before any request leaves the process; "
            "hard bounds: <=24 cases, <=360 requests per campaign run."
        ),
    )
    enable_coverage_gap_report: bool = Field(
        default=False,
        description=(
            "UM-DR-30 (Workstream F §8 — campaign-runtime coverage gap "
            "map): wire the coverage_gap_report node "
            "(production/coverage_gap_report.py) between the reporter and "
            "reflection nodes. The node projects the REAL final campaign "
            "state through the shared coverage ledger "
            "(shared/coverage_ledger.py via coverage/coverage_map.py + "
            "coverage/gap_detector.py — previously zero-importer orphans) "
            "and returns an explicit, bounded, advisory gap report on the "
            "declared coverage_gap_report state channel. Advisory only: "
            "no finding vocabulary, no promotion, no confirmation "
            "authority — the report tells the operator and future "
            "replanning WHERE the campaign did NOT look (not_scanned, "
            "blocked_by_precondition, policy_block, "
            "infrastructure_failure, inconclusive, human_review_only, "
            "missing-validator). Fail-closed default False; fail-soft on "
            "projection errors (error-shaped report, campaign outcome "
            "unaffected); gap entries capped at 200."
        ),
    )
    enable_adaptive_research_loop: bool = Field(
        default=False,
        description=(
            "UM-DR-31 (evidence-driven adaptive research loop): wire the "
            "research_loop node (production/adaptive_research.py) ahead of "
            "the strategist planner on the discovery-line, research-line "
            "and post-validation replan routes (conditional-mapping "
            "overrides, additive-only; flag-off keeps the graph shape "
            "byte-comparable). Each bounded iteration classifies the "
            "coverage-ledger gaps (six-way: observed-not-tested / "
            "inconclusive / blocked-operational / blocked-policy / "
            "tested-rejected / confirmed), the invariant-review candidates "
            "and the untested workflow authorization boundaries, then "
            "injects DEDUPLICATED ordinary hypotheses (deterministic "
            "uuid5 ids + stable fingerprints; conclusively-rejected and "
            "promoted hypotheses are never repeated) into the real "
            "hypothesis pool for the UNCHANGED strategist ranking and "
            "promotion gates. Non-promoting by construction: no findings, "
            "no confirmations, no authority — cqa_v2.guarded_causal_evaluate "
            "stays the sole confirmation authority. Scope-respecting: "
            "scope-denied invariant results generate NO hypothesis. "
            "Fail-closed default False; fail-soft on internal errors; "
            "bounded by max_research_iterations x "
            "max_research_hypotheses_per_iteration."
        ),
    )
    max_research_iterations: int = Field(
        default=3,
        ge=1,
        le=16,
        description=(
            "UM-DR-31: hard cap on research_loop iterations that do work "
            "(invocations beyond the cap are honest pass-throughs with "
            "capped telemetry). Mandatory limit — unavailable/invalid "
            "means the node fails closed to a no-op. Configurable but "
            "bounded: values above 16 are clamped by the node."
        ),
    )
    max_research_hypotheses_per_iteration: int = Field(
        default=12,
        ge=1,
        le=64,
        description=(
            "UM-DR-31: hard cap on new research hypotheses per research_loop "
            "iteration (deterministic info-gain priority order; the cap is "
            "reported, never silently truncated). Mandatory limit — "
            "unavailable/invalid means the node fails closed to a no-op. "
            "Configurable but bounded: values above 64 are clamped."
        ),
    )
    stateful_discovery_max_requests: int = Field(
        default=360,
        ge=1,
        le=3600,
        description=(
            "UM-DR-31 (configurable limits, directive §5.4): the whole-"
            "discovery request budget the family_execution node passes to "
            "run_stateful_discovery (the MAX_TOTAL_REQUESTS ceiling, now "
            "operator-configurable instead of a hard constant). Default "
            "keeps the UM-DR-28 behavior (360); the ablation harness uses "
            "a constrained value to make the research-priority ordering's "
            "contribution measurable. Bounded: 1..3600."
        ),
    )
    enable_identity_orchestrator: bool = Field(
        default=False,
        description=(
            "M3 ق7 (UM-DR-17): the worker-side identity orchestrator — "
            "the runner injects the reauth-vault-backed session_factory "
            "(auth/worker_session_factory.py) the orchestrator's "
            "fail-closed constructor requires. Roles come from the "
            "engagement's identity_profiles; sessions restore from the "
            "sealed identity vault (cookie-restore default; a "
            "login_executor may be injected for real multi-step logins). "
            "Provenance (roles + live flags, never session material) is "
            "attached to the task result as "
            "identity_session_provenance. Fail-soft; flag-off keeps the "
            "worker byte-identical."
        ),
    )
    enable_stateful_api_testing: bool = Field(
        default=False,
        description=(
            "M5 (Part 4 §7): derive the stateful API engine's advisory "
            "hypotheses inside api_testing_node — contract ingestion "
            "(OpenAPI routes + observed surface), the inferred "
            "state-dependency model, bounded replayable sequence plans "
            "with cleanup budgets, and two-authorized-identity "
            "BOLA/IDOR differential plans with randomized-id negative "
            "controls and causal evidence specs. Planning ONLY (the "
            "deterministic validator owns confirmation); requires ≥2 "
            "operator-supplied identities for the BOLA differential; "
            "fail-closed default False; flag-off keeps the node "
            "byte-identical."
        ),
    )
    enable_report_quality_gate: bool = Field(
        default=False,
        description=(
            "Enable deterministic report contract validation. When enabled, "
            "strict report exporters reject findings missing evidence, "
            "reproduction, impact, or CVSS; legacy exports remain unchanged "
            "when disabled."
        ),
    )
    enable_bug_bounty_reporter: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "enable_bug_bounty_reporter",
            "ENABLE_BUG_BOUNTY_REPORTER",
            "WEBPENT_ENABLE_BUG_BOUNTY_REPORTER",
        ),
        description=(
            "Use the concise bug-bounty report node in the graph. Disabled "
            "by default to preserve the enterprise report path."
        ),
    )
    # FEATURE PROPOSALS ق10 window (2026-11-04, UM-DR-09): the platform
    # export renderer (reporter/platform_export.py, PROPOSALS_ULTIMATE_V3
    # §6) was merged with its flag-gate reference but the flag itself was
    # never declared here — every gate read raised AttributeError and the
    # module was dead on arrival (UM-DR-06 residual). Declared now with
    # the standard fail-closed default (False = no paste-ready export).
    enable_platform_export: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "enable_platform_export",
            "ENABLE_PLATFORM_EXPORT",
            "WEBPENT_ENABLE_PLATFORM_EXPORT",
        ),
        description=(
            "Enable the paste-ready platform report export (HackerOne/"
            "Bugcrowd/Intigriti markdown via reporter/platform_export.py). "
            "No platform API exists behind this flag — it only renders "
            "text the operator submits themselves. Disabled by default."
        ),
    )
    # ------------------------------------------------------------------
    # RED-TEAM WINDOW (2026-11-06, UM-DR-25) — subsystem flag re-declaration.
    # The 2026-11-06 red-team sweep found the UM-DR-09 defect class had
    # recurred wholesale: the subsystems below were merged with their
    # gate reads (``get_settings().enable_*``) but the fields were never
    # declared here, so every gate read raised AttributeError at runtime
    # and the subsystems were dead on arrival (~310 test failures across
    # 30+ files). All are declared now with the standard fail-closed
    # default False; flag-off behavior is byte-identical to the previous
    # (crashing) off-state from the caller's perspective — the gates now
    # return False instead of raising.
    # ------------------------------------------------------------------
    enable_advanced_web_vulns: bool = Field(
        default=False,
        description=(
            "Gate for agents/advanced_web_vulns/agent.py (DOM clobbering, "
            "deserialization, cache-poisoning advisory family)."
        ),
    )
    enable_chain_review_section: bool = Field(
        default=False,
        description=(
            "Gate for reporter/chain_review.py — append the exploit-chain "
            "review section to generated reports."
        ),
    )
    enable_chain_v3: bool = Field(
        default=False,
        description=(
            "Gate for chained_exploits/graph_v3.py — the v3 exploit-chain "
            "graph planner. Off keeps the frozen v2 path."
        ),
    )
    enable_cross_campaign_learning: bool = Field(
        default=False,
        description=(
            "Gate for learning/technique_library.py — allow technique "
            "notes learned in one campaign to inform later campaigns "
            "(read at technique_library.py:224 together with "
            "technique_library_path)."
        ),
    )
    enable_graphql_deep: bool = Field(
        default=False,
        description=(
            "Gate for graphql_testing/deep.py — deep GraphQL testing "
            "(batch/alias/depth abuse probing) bounded by "
            "graphql_deep_max_batch."
        ),
    )
    enable_h2_race: bool = Field(
        default=False,
        description=(
            "Gate for the HTTP/2 single-packet race probes inside "
            "workflow_fuzzing/agent.py."
        ),
    )
    enable_js_discovery: bool = Field(
        default=False,
        description=(
            "Gate for agents/js_discovery/agent.py — JavaScript endpoint "
            "discovery pass."
        ),
    )
    enable_logic_fuzzing: bool = Field(
        default=False,
        description=(
            "Gate for business_logic/value_fuzzer.py — bounded business-"
            "logic value fuzzing (logic_fuzz_max_mutations per field)."
        ),
    )
    enable_notifications: bool = Field(
        default=False,
        description=(
            "Gate for integrations/notifications/dispatch.py — outbound "
            "notification dispatch. Fail-closed: False refuses before any "
            "send."
        ),
    )
    enable_refutation_learning: bool = Field(
        default=False,
        description=(
            "Gate for learning/refutation_ledger.py (and the agent-level "
            "reads in advanced_web_vulns + graphql_testing) — record "
            "refuted hypotheses so they are not re-proposed."
        ),
    )
    enable_benchmark_gate: bool = Field(
        default=False,
        description=(
            "Gate for the vulnbox benchmark harness (UM-DR-26 declaration): "
            "the planted-vuln lab campaign scores its confusion matrix only "
            "when this flag is on; default-off keeps CI hermetic."
        ),
    )
    cache_key_max_endpoints: int = Field(
        default=15,
        description=(
            "Bounded endpoint sweep window for cache-key discovery "
            "(UM-DR-26 declaration): the live-fixture sweep probes at most "
            "this many discovered endpoints per campaign."
        ),
    )
    enable_coverage_scheduling: bool = Field(
        default=False,
        description=(
            "Gate for coverage/scheduler.py (UM-DR-26 declaration): the "
            "planner appends the deterministic Coverage advisory block "
            "(advisory data, never instructions) only when this flag is on "
            "and a crawled surface exists."
        ),
    )
    enable_regression_monitor: bool = Field(
        default=False,
        description=(
            "Gate for monitor/regression_monitor.py — compare new runs "
            "against recorded baselines and alert on regressions."
        ),
    )
    enable_robots_override: bool = Field(
        default=False,
        description=(
            "Gate for safety/agency.py — allow operator-recorded robots.txt "
            "overrides. Fail-closed: False honors robots always."
        ),
    )
    enable_secrets_scanner: bool = Field(
        default=False,
        description=(
            "Gate for secrets_scanner/scanner.py — entropy+pattern secret "
            "scanning with secrets_min_entropy threshold."
        ),
    )
    enable_takeover_scan: bool = Field(
        default=False,
        description=(
            "Gate for recon/takeover.py — subdomain-takeover signature "
            "probing with takeover_concurrency parallel workers."
        ),
    )
    enable_waf_adaptive: bool = Field(
        default=False,
        description=(
            "Gate for waf_evasion/adaptive.py — bounded adaptive request "
            "transformation after transport-level blocks "
            "(waf_adaptive_max_attempts cap)."
        ),
    )
    enable_workflow_fuzzing: bool = Field(
        default=False,
        description=(
            "Gate for workflow_fuzzing/agent.py — multi-step business-"
            "workflow fuzzing with per-run mutation caps."
        ),
    )
    enable_worker_status_endpoint: bool = Field(
        default=False,
        description=(
            "Gate for the read-only worker-status endpoint family "
            "(tests/test_worker_status.py). The F-05 (0.33.0) auth "
            "hardening kept viewer-auth; this flag additionally allows "
            "operators to hide the routes entirely (404 when off)."
        ),
    )
    enable_kill_switch: bool = Field(
        default=False,
        description=(
            "Safety-governor master kill switch — when True every governed "
            "send path refuses (tests/test_safety_governor.py)."
        ),
    )
    enable_llm_spend_cap: bool = Field(
        default=False,
        description=(
            "Gate for the per-engagement LLM token spend cap "
            "(llm_token_cap_per_engagement, enforced by safety/"
            "spend_governor.py)."
        ),
    )
    enable_request_ledger: bool = Field(
        default=False,
        description=(
            "Gate for the append-only request ledger the safety governor "
            "audits every outbound send against."
        ),
    )
    enable_oob_collaboration: bool = Field(
        default=False,
        description=(
            "Gate for shared/oob.py — OOB collaborator probing; the "
            "collaborator domain comes from oob_collaborator_domain."
        ),
    )
    enable_role_matrix: bool = Field(
        default=False,
        description=(
            "Gate for agents/role_matrix — role/permission matrix testing "
            "bounded by role_matrix_max_pairs."
        ),
    )
    enable_model_tiering: bool = Field(
        default=False,
        description=(
            "Gate for llm_researcher/tiering.py — route cheap tasks to "
            "model_tier_fast and hard tasks to model_tier_strong."
        ),
    )
    enable_evidence_bundle: bool = Field(
        default=False,
        description=(
            "Gate for reporter/evidence_bundle.py — sealed evidence "
            "bundles up to evidence_bundle_max_bytes."
        ),
    )
    enable_external_submission: bool = Field(
        default=False,
        description=(
            "Gate for the external submission path built on evidence "
            "bundles. Fail-closed default False."
        ),
    )
    enable_live_benchmarks: bool = Field(
        default=False,
        description=(
            "Gate for benchmark/live_runner.py — LOCAL-target live "
            "benchmark runs against benchmark_target. Refuses non-local "
            "targets regardless of this flag."
        ),
    )
    enable_cache_key_discovery: bool = Field(
        default=False,
        description=(
            "Gate for shared/cache_key_discovery.py — infer cache keys "
            "from response variance."
        ),
    )
    enable_dom_xss: bool = Field(
        default=False,
        description=(
            "Gate for agents/dom_xss — DOM XSS analysis bounded by "
            "dom_xss_max_ast_nodes."
        ),
    )
    dom_xss_max_ast_nodes: int = Field(
        default=50_000,
        description=(
            "AST-node bound for the DOM XSS analyzer (agents/dom_xss) — "
            "the parse is abandoned (bounded gap reported) beyond it."
        ),
    )
    enable_source_maps: bool = Field(
        default=False,
        description=(
            "Gate for agents/sourcemap_analysis — parse shipped .map "
            "files for recovered source paths."
        ),
    )
    enable_selfcheck: bool = Field(
        default=False,
        description=(
            "Gate for the VIP orchestrator red-vs-blue selfcheck pass."
        ),
    )
    enable_session_pool: bool = Field(
        default=False,
        description=(
            "Gate for the bounded authenticated-session reuse pool."
        ),
    )
    enable_smart_campaigns: bool = Field(
        default=False,
        description=(
            "Gate for smart campaign scheduling (redteam_r2_c3)."
        ),
    )
    enable_target_selector: bool = Field(
        default=False,
        description=(
            "Gate for the measured target-selection heuristics module."
        ),
    )
    technique_library_path: str = Field(
        default="",
        description=(
            "Optional path for learning/technique_library.py cross-"
            "campaign notes (used when enable_cross_campaign_learning)."
        ),
    )
    graphql_deep_max_batch: int = Field(
        default=10,
        description=(
            "Hard cap on GraphQL batch/alias abuse probes per round "
            "(graphql_testing/deep.py). Deliberately UNVALIDATED here — "
            "the builder refuses bad caps with its typed "
            "GraphQlDeepError('bad_cap') so the refusal is observable at "
            "the call site, not only at construction."
        ),
    )
    llm_token_cap_per_engagement: int = Field(
        default=1_000_000,
        ge=0,
        description=(
            "Token spend cap per engagement enforced when "
            "enable_llm_spend_cap (safety/spend_governor.py); the "
            "governor still counts when the cap is 0-unset."
        ),
    )
    logic_fuzz_max_mutations: int = Field(
        default=24,
        ge=1,
        description=(
            "Per-field mutation bound for business_logic/value_fuzzer.py."
        ),
    )
    refutation_ledger_db: str = Field(
        default="",
        description=(
            "SQLite URL for learning/refutation_ledger.py; empty falls "
            "back to :memory:."
        ),
    )
    secrets_min_entropy: float = Field(
        default=3.5,
        description=(
            "Minimum Shannon entropy (bits/char) for secrets_scanner "
            "candidates. Deliberately UNVALIDATED here — scan_text "
            "refuses bad thresholds with its typed SecretsScannerError."
        ),
    )
    takeover_concurrency: int = Field(
        default=4,
        description=(
            "Parallel signature probes for recon/takeover.py. "
            "Deliberately UNVALIDATED here — the takeover batch runner "
            "refuses bad concurrency with its own typed error so the "
            "refusal is observable at the call site."
        ),
    )
    waf_adaptive_max_attempts: int = Field(
        default=3,
        ge=1,
        le=5,
        description=(
            "Bounded adaptive transform attempts per blocked request "
            "(waf_evasion/adaptive.py). Settings-level cap is 5; the "
            "module's MAX_ATTEMPTS_CAP is the second layer."
        ),
    )
    model_tier_fast: str = Field(
        default="",
        description=(
            "Fast-tier model id for llm_researcher/tiering.py (empty = "
            "tiering refuses to route)."
        ),
    )
    model_tier_strong: str = Field(
        default="",
        description=(
            "Strong-tier model id for llm_researcher/tiering.py."
        ),
    )
    oob_collaborator_domain: str = Field(
        default="",
        description=(
            "Operator OOB collaborator base domain (shared/oob.py). "
            "Empty = OOB disabled (fail-closed)."
        ),
    )
    role_matrix_max_pairs: int = Field(
        default=200,
        ge=1,
        description=(
            "Bound on role-pair probes for agents/role_matrix."
        ),
    )
    evidence_bundle_max_bytes: int = Field(
        default=10 * 1024 * 1024,
        ge=1,
        description=(
            "Sealed evidence-bundle size cap (reporter/"
            "evidence_bundle.py)."
        ),
    )
    benchmark_target: str = Field(
        default="",
        description=(
            "LOCAL target URL for benchmark/live_runner.py — refuses "
            "non-localhost values regardless of flags."
        ),
    )
    regression_watch_path: str = Field(
        default="",
        description=(
            "Optional path monitor/regression_monitor.py watches for "
            "recorded baselines; empty = monitor refuses (fail-closed)."
        ),
    )
    notify_min_severity: Literal["low", "medium", "high", "critical"] = Field(
        default="high",
        description=(
            "Minimum finding severity integrations/notifications/"
            "dispatch.py will notify on (default high — the plan's "
            "noise-floor)."
        ),
    )
    notify_channels: list[str] = Field(
        default_factory=list,
        description=(
            "Enabled notification channels (e.g. slack, discord). Empty "
            "list = no channel is ever selected (fail-closed)."
        ),
    )
    # END red-team window UM-DR-25 flag re-declaration block.
    # ------------------------------------------------------------------
    # Ultimate Autonomous Bug Hunter plan (2026-10-27) flags.
    # Proposals 2/5/7/8: each new capability is additive, deterministic
    # where stated, and disabled by default unless the plan explicitly
    # defaults it on (GraphQL testing and the new deterministic detectors
    # default ON per the plan: "كشف جديد مش تعديل سلوك قديم").
    # ------------------------------------------------------------------
    enable_archive_discovery: bool = Field(
        default=False,
        description=(
            "Ultimate plan, proposal 5 (recon depth): enable the gau "
            "archive-discovery recon tool wrapper (tools/recon/gau.py). "
            "Archive endpoints are re-checked against the engagement "
            "scope allowlist before any use. Disabled by default: it "
            "requires the external gau binary and out-of-band historical "
            "data, so it stays an explicit operator opt-in."
        ),
    )
    enable_infra_scan: bool = Field(
        default=False,
        description=(
            "Ultimate plan, proposal 5 (recon depth): enable the bounded "
            "nmap infrastructure probe (tools/recon/nmap.py). Limited to "
            "top-N ports, rate-limited, and requires the target host to "
            "be inside the engagement scope file with an explicit "
            "infra_scan=true host entry. Disabled by default."
        ),
    )
    nmap_top_ports: int = Field(
        default=100,
        ge=10,
        le=1000,
        description="Bounded nmap port budget when enable_infra_scan is on.",
    )
    enable_source_leak_advisory: bool = Field(
        default=False,
        description=(
            "Ultimate plan, proposal 5: enable the advisory-only source "
            "leak discovery hints (shared/source_leak_discovery.py). The "
            "module never fetches or scans code; it only annotates "
            "candidate public-repo names for the operator. Disabled by "
            "default."
        ),
    )
    enable_graphql_testing: bool = Field(
        default=True,
        description=(
            "Ultimate plan, proposal 7: run the deterministic GraphQL "
            "validators (validators/graphql_validator.py) when "
            "schema_ingestion reports non-empty graphql_operations. New "
            "detection only — no legacy behavior changes when the target "
            "has no GraphQL surface (the node never activates)."
        ),
    )
    enable_cache_poisoning_detection: bool = Field(
        default=True,
        description=(
            "Ultimate plan, proposal 7: deterministic cache-poisoning "
            "header analysis (shared/cache_poisoning_detector.py) over "
            "already-captured probe responses. No extra requests are "
            "issued by the analyzer itself."
        ),
    )
    enable_prototype_pollution_detection: bool = Field(
        default=True,
        description=(
            "Ultimate plan, proposal 7: deterministic prototype-pollution "
            "pattern analysis (shared/prototype_pollution_detector.py) "
            "over captured JSON-merge surfaces."
        ),
    )
    enable_oauth_misconfig_detection: bool = Field(
        default=True,
        description=(
            "Ultimate plan, proposal 7: deterministic OAuth/SSO "
            "misconfiguration checks (validators/oauth_misconfig_validator.py) "
            "over captured authorization-flow evidence."
        ),
    )
    enable_llm_consistency_check: bool = Field(
        default=False,
        description=(
            "Ultimate plan, proposal 8: annotate high-severity LLM "
            "decisions with a self-consistency agreement score "
            "(shared/llm_consistency.py). Advisory-only metadata — it "
            "never changes a deterministic validator verdict. Disabled "
            "by default because it multiplies LLM cost on the checked "
            "decisions."
        ),
    )
    llm_consistency_agreement_threshold: float = Field(
        default=0.67,
        ge=0.0,
        le=1.0,
        description="Agreement threshold used by verify_llm_consistency.",
    )
    enable_lesson_consultation: bool = Field(
        default=True,
        description=(
            "Ultimate plan, proposal 3: consult accumulated campaign "
            "lessons after planning (advisory context for hypothesis and "
            "payload generation) and extract new lessons at reflection. "
            "Advisory context only — lesson content is never treated as "
            "executable instructions."
        ),
    )
    enable_dynamic_step_budget: bool = Field(
        default=True,
        description=(
            "Ultimate plan, proposal 2: derive the per-campaign graph "
            "step budget from the measured target surface size instead "
            "of the flat max_graph_steps ceiling, always clamped to "
            "min(computed, dynamic_step_budget_cap) and to the cost "
            "ceiling. When disabled, the flat max_graph_steps ceiling "
            "applies unchanged (legacy behavior)."
        ),
    )
    dynamic_step_budget_cap: int = Field(
        default=400,
        ge=50,
        le=4000,
        description=(
            "Hard upper bound for the dynamically computed step budget "
            "(proposal 2: min(computed, cap))."
        ),
    )
    enable_unified_hunt_progress: bool = Field(
        default=True,
        description=(
            "Ultimate plan, proposal 12: live phase-based progress "
            "rendering and instant CONFIRMED-finding lines during "
            "unified hunt runs."
        ),
    )
    enable_structure_aware_triage: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "enable_structure_aware_triage",
            "ENABLE_STRUCTURE_AWARE_TRIAGE",
            "WEBPENT_STRUCTURE_AWARE_TRIAGE",
        ),
        description=(
            "Enable passive structure-aware endpoint triage. The deterministic "
            "coverage queue is advisory and additive; it prevents URL-only "
            "ranking from hiding API, auth, upload, GraphQL, WebSocket, and "
            "state-changing surfaces without executing requests."
        ),
    )
    max_structure_aware_triage_endpoints: int = Field(
        default=25,
        gt=0,
        le=500,
        validation_alias=AliasChoices(
            "max_structure_aware_triage_endpoints",
            "MAX_STRUCTURE_AWARE_TRIAGE_ENDPOINTS",
            "WEBPENT_MAX_STRUCTURE_AWARE_TRIAGE_ENDPOINTS",
        ),
    )
    discovery_route_seeds: str = Field(
        default="",
        validation_alias=AliasChoices(
            "discovery_route_seeds",
            "DISCOVERY_ROUTE_SEEDS",
            "WEBPENT_DISCOVERY_ROUTE_SEEDS",
        ),
        description=(
            "Comma-separated, operator-declared same-origin route seeds for the "
            "current target. Empty by default so routes from one lab cannot "
            "be injected into another target."
        ),
    )
    enable_http_discovery_supplement: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "enable_http_discovery_supplement",
            "ENABLE_HTTP_DISCOVERY_SUPPLEMENT",
            "WEBPENT_HTTP_DISCOVERY_SUPPLEMENT",
        ),
        description=(
            "Run a bounded authenticated GET-only HTTP discovery supplement even "
            "when an optional crawler binary returns endpoints. Disabled by "
            "default; vip-qualification enables it explicitly in the crawler."
        ),
    )
    http_discovery_supplement_pages: int = Field(
        default=20,
        gt=0,
        le=50,
        validation_alias=AliasChoices(
            "http_discovery_supplement_pages",
            "HTTP_DISCOVERY_SUPPLEMENT_PAGES",
            "WEBPENT_HTTP_DISCOVERY_SUPPLEMENT_PAGES",
        ),
    )
    enable_surface_security_analysis: bool = Field(
        default=False,
        description=(
            "Enable bounded passive coverage analysis across web-security "
            "surfaces. It emits redacted observations and coverage gaps only; "
            "it never executes payloads or promotes findings."
        ),
    )
    max_surface_security_observations: int = Field(default=100, gt=0, le=500)

    # Project Zero production wiring (2026-10-22): additive, default-off
    # callers for the six library-tier PZ modules. Each flag gates one
    # production call site; every site is fail-soft and writes advisory
    # state only (it never promotes findings or executes payloads).
    enable_surface_influence_graph: bool = Field(
        default=False,
        description=(
            "Include the surface influence graph (built from the same "
            "crawled_data as the surface evidence graph) in the passive "
            "surface-security summary."
        ),
    )
    enable_surface_drift_analysis: bool = Field(
        default=False,
        description=(
            "Diff the current surface evidence graph against the previous "
            "run's graph (read from prior state) and attach the drift "
            "report as advisory state."
        ),
    )
    enable_tech_stack_cve_correlation: bool = Field(
        default=False,
        description=(
            "Fingerprint the tech stack from response evidence already "
            "collected and correlate matched components against the "
            "CVE/KEV feed catalog already in state. Advisory only."
        ),
    )
    enable_taint_tracking: bool = Field(
        default=False,
        description=(
            "Record fingerprinted source/sink taint points for values the "
            "tool itself introduces (form fields, injected payloads) and "
            "surface cross-session flows. Advisory only; no new requests."
        ),
    )
    enable_red_vs_blue_selfcheck: bool = Field(
        default=False,
        description=(
            "Run an in-process red-vs-blue self-check of a production "
            "detector (the SSRF indicator extractor) after a devils "
            "advocate evaluation, feeding any escape to postmortem. Never "
            "touches the target; detection functions run on local strings."
        ),
    )
    # VIP campaign leader (2026-10-24 layer 2). Gates the single additive
    # graph node that runs one bounded, in-process perceive->plan pass of
    # the VIP Orchestrator after the disclosed-intel stage. The node never
    # sends requests, never executes payloads, and never promotes findings:
    # its output is advisory telemetry in vip_campaign_state only.
    enable_vip_orchestrator: bool = Field(
        default=False,
        description=(
            "Enable the one-shot VIP campaign-leader graph node (advisory "
            "perceive->plan pass over already-crawled surface data). "
            "Disabled by default; the node exists in the graph only when "
            "this flag is on."
        ),
    )
    # Project Zero catalog injection (2026-10-24): local JSON file paths for
    # the two advisory catalogs that previously had no producer at all.
    # Empty path = catalog stays empty (the pre-wiring default behavior).
    # Nothing is fetched from the network; the loaders are fail-soft.
    cve_feed_catalog_path: str = Field(
        default="",
        description=(
            "Optional path to a local JSON file with the CVE feed catalog "
            "used by tech-stack CVE correlation (a list of feed-entry "
            "objects). Empty = no catalog loaded."
        ),
    )
    kev_catalog_path: str = Field(
        default="",
        description=(
            "Optional path to a local JSON file with KEV identifiers "
            "(bare CVE strings or objects with a cve_id field) used by "
            "the reporter's KEV enrichment. Empty = no catalog loaded."
        ),
    )
    epss_catalog_path: str = Field(
        default="",
        description=(
            "Optional path to a local JSON file with EPSS scores "
            "(objects with cve_id/epss/percentile) used to prioritize "
            "tech-stack CVE correlations (shared/epss.py — advisory "
            "ordering only, never a confirmation signal). "
            "Empty = no catalog loaded."
        ),
    )

    # V55 Phase 12: separated memory boundaries and retrieval budgets.
    # Disabled by default so legacy RAG paths remain compatible until the
    # operator explicitly opts into the typed boundary.
    enable_memory_boundary: bool = Field(
        default=False,
        description=(
            "Enable the typed separation between target facts, security "
            "knowledge, and operator-reviewed experience lessons. Retrieval "
            "is advisory and cannot promote findings."
        ),
    )
    memory_max_records: int = Field(default=200, gt=0, le=5000)
    memory_max_retrievals: int = Field(default=50, ge=0, le=1000)
    memory_max_items_per_retrieval: int = Field(default=8, gt=0, le=50)
    memory_max_chars_per_retrieval: int = Field(default=6000, ge=100, le=50000)
    memory_max_content_chars: int = Field(default=8000, ge=100, le=20000)
    memory_max_feedback_records: int = Field(default=200, ge=0, le=5000)

    # -- HTTP / scanning defaults -------------------------------------------
    http_timeout: int = Field(default=30, gt=0)
    allow_insecure_tls: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "allow_insecure_tls",
            "ALLOW_INSECURE_TLS",
            "WEBPENT_ALLOW_INSECURE_TLS",
        ),
        description=(
            "Allow TLS certificate verification to be disabled for explicitly "
            "authorized lab targets. Keep false for production and public targets."
        ),
    )
    max_concurrent_requests: int = Field(default=10, gt=0)
    http_user_agent: str = Field(default="WebPent/0.2 (+https://github.com/example/webpent)")

    # -- External tool paths -------------------------------------------------
    nmap_path: str = "nmap"
    nikto_path: str = "nikto"
    sqlmap_path: str = "sqlmap"
    nuclei_path: str = "nuclei"
    ffuf_path: str = "ffuf"
    ffuf_enabled: bool = Field(
        default=False,
        validation_alias=AliasChoices("ffuf_enabled", "FFUF_ENABLED", "WEBPENT_FFUF_ENABLED"),
        description="Enable ffuf content discovery; disabled by default.",
    )
    ffuf_wordlist_path: str = Field(
        default="",
        validation_alias=AliasChoices(
            "ffuf_wordlist_path", "FFUF_WORDLIST_PATH", "WEBPENT_FFUF_WORDLIST_PATH"
        ),
        description="Explicit local ffuf wordlist path; empty disables discovery.",
    )
    arjun_path: str = "arjun"
    arjun_enabled: bool = Field(
        default=False,
        validation_alias=AliasChoices("arjun_enabled", "ARJUN_ENABLED", "WEBPENT_ARJUN_ENABLED"),
        description="Enable arjun hidden-parameter discovery; disabled by default.",
    )
    arjun_wordlist_path: str = Field(
        default="",
        validation_alias=AliasChoices(
            "arjun_wordlist_path", "ARJUN_WORDLIST_PATH", "WEBPENT_ARJUN_WORDLIST_PATH"
        ),
        description=(
            "Optional local arjun parameter-name wordlist path; empty uses "
            "arjun's own bundled default wordlist (unlike ffuf, a wordlist "
            "is not mandatory for arjun to run)."
        ),
    )
    arjun_max_endpoints: int = Field(
        default=5,
        ge=0,
        le=50,
        validation_alias=AliasChoices(
            "arjun_max_endpoints", "ARJUN_MAX_ENDPOINTS", "WEBPENT_ARJUN_MAX_ENDPOINTS"
        ),
        description=(
            "Maximum number of curated crawler endpoints probed with arjun "
            "per campaign. Bounds engagement time; arjun's chunked requests "
            "are more expensive per-endpoint than a katana crawl hop."
        ),
    )
    gobuster_path: str = "gobuster"
    subfinder_path: str = "subfinder"
    # V8 FIX: Go httpx binary is installed at /usr/local/bin/httpx-pd in
    # Dockerfile.base to avoid shadowing by the Python httpx package's
    # console script. Operators running outside Docker can set
    # HTTPX_PATH=/usr/local/bin/httpx or install the Go tool as httpx-pd.
    httpx_path: str = "httpx-pd"
    zap_path: str = "/usr/share/zaproxy/zap.sh"
    katana_path: str = "katana"
    dalfox_path: str = "dalfox"

    # V5 Sprint 6: Optional deserialization-exploitation tools.
    # Defaults point to bare binary names so the wrappers can resolve
    # them via PATH; operators can override with absolute paths via env.
    ysoserial_path: str = "ysoserial.jar"
    phpggc_path: str = "phpggc"

    # -- Storage -------------------------------------------------------------
    # Each scan may derive a deterministic target-scoped workspace beneath
    # this root. Legacy callers remain compatible because they only opt in
    # when the scan entrypoint constructs a TargetWorkspace.
    # TEAM-1 Phase 9: explicit opt-in flags for the SUPPLEMENTARY CQA v2
    # causal post-process and VIP Smart prioritization layers. Both are
    # non-authoritative (original findings are never mutated) — see
    # webpent.cqa_v2.pipeline_integration governance note. Disabled by
    # default so the default graph run stays deterministic and minimal.
    enable_cqa_v2: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "enable_cqa_v2",
            "ENABLE_CQA_V2",
            "WEBPENT_ENABLE_CQA_V2",
        ),
        description="Attach the CQA v2 causal post-process to the reporter seam.",
    )
    enable_smart: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "enable_smart",
            "ENABLE_SMART",
            "WEBPENT_ENABLE_SMART",
        ),
        description="Include VIP Smart prioritization hints inside the CQA v2 post-process.",
    )
    # M1-C (UM-DR-12): declared-and-False flags for modules whose consumers
    # already gate on them (or whose tests assert the default) but whose
    # field was never declared — the referenced-but-undeclared defect from
    # UM-DR-10's known-findings note and M1_READINESS_REVIEW §5.5. Declaring
    # them fail-closed (default False) makes the modules constructible and
    # the flags honest; wiring them into the production graph stays with
    # each module's owning phase (M3 for OAST/bridge wiring).
    enable_oast: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "enable_oast",
            "ENABLE_OAST",
            "WEBPENT_ENABLE_OAST",
        ),
        description=(
            "Enable the OAST (out-of-band application security testing) "
            "DNS/HTTP responder plumbing. Fail-closed: the responder and its "
            "poll loop stay inert unless an operator explicitly opts in."
        ),
    )
    # M1-C (UM-DR-12): the OAST settings contract pinned by
    # tests/test_oast.py::TestFailClosedDefaults — declared fail-closed so
    # the module is constructible and its defaults are honest. The collector
    # binds loopback by default (L-4 disposition, M1-A); a non-loopback bind
    # is an explicit operator decision via the env aliases.
    oast_domain: str = Field(
        default="",
        validation_alias=AliasChoices(
            "oast_domain",
            "OAST_DOMAIN",
            "WEBPENT_OAST_DOMAIN",
        ),
        description=(
            "The operator's OAST zone domain (e.g. the interactsh or private "
            "DNS zone this deployment controls). Empty = OOB collaboration "
            "mints nothing (fail-closed: no probe can be registered)."
        ),
    )
    oast_poll_endpoint: str = Field(
        default="",
        validation_alias=AliasChoices(
            "oast_poll_endpoint",
            "OAST_POLL_ENDPOINT",
            "WEBPENT_OAST_POLL_ENDPOINT",
        ),
        description=(
            "HTTP base URL of the OOB collector used by the poll loop. "
            "Empty = no remote polling (local in-process collector only)."
        ),
    )
    oast_collector_bind_host: str = Field(
        default="127.0.0.1",
        validation_alias=AliasChoices(
            "oast_collector_bind_host",
            "OAST_COLLECTOR_BIND_HOST",
            "WEBPENT_OAST_COLLECTOR_BIND_HOST",
        ),
        description=(
            "Bind host for the local OOB HTTP collector. Defaults to the "
            "loopback interface — an internet-exposed collector is an "
            "evidence-integrity risk (callback spoofing) and must be a "
            "deliberate operator decision."
        ),
    )
    oast_collector_bind_port: int = Field(
        default=0,
        validation_alias=AliasChoices(
            "oast_collector_bind_port",
            "OAST_COLLECTOR_BIND_PORT",
            "WEBPENT_OAST_COLLECTOR_BIND_PORT",
        ),
        description=(
            "Bind port for the local OOB HTTP collector. 0 = an ephemeral "
            "OS-assigned port (the safe default for shared hosts)."
        ),
    )
    oast_dns_listen_port: int = Field(
        default=0,
        validation_alias=AliasChoices(
            "oast_dns_listen_port",
            "OAST_DNS_LISTEN_PORT",
            "WEBPENT_OAST_DNS_LISTEN_PORT",
        ),
        description=(
            "UDP listen port for the OAST DNS responder. 0 = an ephemeral "
            "OS-assigned port; authority for a real zone requires 53 and is "
            "an explicit operator decision."
        ),
    )
    enable_causal_chain_candidates: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "enable_causal_chain_candidates",
            "ENABLE_CAUSAL_CHAIN_CANDIDATES",
            "WEBPENT_ENABLE_CAUSAL_CHAIN_CANDIDATES",
        ),
        description=(
            "Emit causal-chain candidate findings from the validator's "
            "deterministic chain composer. Fail-closed default keeps the "
            "default graph run deterministic and minimal."
        ),
    )
    enable_campaign_resume: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "enable_campaign_resume",
            "ENABLE_CAMPAIGN_RESUME",
            "WEBPENT_ENABLE_CAMPAIGN_RESUME",
        ),
        description=(
            "Enable deterministic campaign-resume support (checkpoint "
            "markers + probe-execution ledger + bounded requeue). Fail-closed "
            "default: interrupted campaigns stay strictly operator-restarted."
        ),
    )
    target_workspace_root: Path = Field(
        default=Path("~/.webpent/workspaces"),
        validation_alias=AliasChoices(
            "target_workspace_root",
            "TARGET_WORKSPACE_ROOT",
            "WEBPENT_TARGET_WORKSPACE_ROOT",
        ),
        description=(
            "Root directory for per-target workspaces containing isolated "
            "reports, sessions, databases, ledgers, and RAG stores."
        ),
    )
    output_dir: Path = Field(default=Path("./output"))
    database_url: str = Field(
        default="sqlite:///./webpent.db",
        # R-04 (TEAM-2 residual): the NAMESPACED variable must win over the
        # generic ambient ``DATABASE_URL`` when both are present. Compose and
        # supported deployments pass ``WEBPENT_DATABASE_URL``; a stray generic
        # ``DATABASE_URL`` (frequent in CI/operator shells) previously took
        # precedence and silently redirected API/worker/validator/OOB
        # persistence to a foreign database.
        # NOTE: the bare field-name alias CANNOT stay in this chain: with
        # case_sensitive=False pydantic-settings folds it to ``database_url``,
        # which matches the ambient ``DATABASE_URL`` env var itself, so the
        # generic var always won regardless of alias order (proven by test).
        # The field name remains usable for attribute access and programmatic
        # kwargs; only the env lookup chain is namespaced-first.
        validation_alias=AliasChoices("WEBPENT_DATABASE_URL", "DATABASE_URL"),
    )
    findings_ledger_path: Path = Field(
        default=Path("~/.webpent/findings_ledger.sqlite3"),
        validation_alias=AliasChoices(
            "findings_ledger_path",
            "FINDINGS_LEDGER_PATH",
            "WEBPENT_FINDINGS_LEDGER_PATH",
        ),
        description=(
            "Durable release-to-release findings ledger. It is separate from "
            "the per-run database and preserves findings across code revisions."
        ),
    )
    # Track 11 items 5/7 (2026-10-28): dedup-before-nomination gate and
    # controlled retest. The gate is deterministic, makes no network calls,
    # and never deletes findings (it annotates; the reporter renders the
    # duplicates appendix), so it defaults ON. Opt-out keeps the exact
    # pre-0.17.0 graph shape (executive_summary -> reporter direct edge).
    enable_dedup_gate: bool = Field(
        default=True,
        validation_alias=AliasChoices(
            "enable_dedup_gate",
            "ENABLE_DEDUP_GATE",
            "WEBPENT_ENABLE_DEDUP_GATE",
        ),
        description=(
            "Wire the Track 11 item 5 dedup gate between executive_summary "
            "and reporter: prior-findings review becomes a condition before "
            "nomination (fail-safe, never silent)."
        ),
    )
    retest_request_timeout: float = Field(
        default=15.0,
        validation_alias=AliasChoices(
            "retest_request_timeout",
            "RETEST_REQUEST_TIMEOUT",
            "WEBPENT_RETEST_REQUEST_TIMEOUT",
        ),
        description=(
            "Per-request timeout (seconds) for Track 11 item 7 controlled "
            "retests. One bounded replay per attempt; no retry storms."
        ),
    )
    retest_ledger_path: Path = Field(
        default=Path("~/.webpent/retest_ledger.jsonl"),
        validation_alias=AliasChoices(
            "retest_ledger_path",
            "RETEST_LEDGER_PATH",
            "WEBPENT_RETEST_LEDGER_PATH",
        ),
        description=(
            "Append-only JSONL comparison log for controlled retests "
            "(Track 11 item 7): before/after levels, outcome, authorization "
            "ref, and probe summary per attempt."
        ),
    )
    # Track 11 item 8 (2026-10-28): confirmation notifications. Channels are
    # user-chosen and ALL disabled by default: the webhook channel reuses
    # WEBHOOK_ENABLED/WEBHOOK_URL; the file channel writes a local JSONL
    # inbox. Sensitive details (payload/reasoning) are stripped by default —
    # explicit opt-in only. Dispatch is fire-and-forget from a bounded
    # worker thread and can never block or break the persistence path.
    notification_include_details: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "notification_include_details",
            "NOTIFICATION_INCLUDE_DETAILS",
            "WEBPENT_NOTIFICATION_INCLUDE_DETAILS",
        ),
        description=(
            "Include the attack payload/reasoning in notification bodies. "
            "Default False (roadmap: no sensitive details by default); the "
            "identifier payload (id/title/severity/class/url) is always sent."
        ),
    )
    notification_file_path: Path = Field(
        default=Path(""),  # empty = channel disabled
        validation_alias=AliasChoices(
            "notification_file_path",
            "NOTIFICATION_FILE_PATH",
            "WEBPENT_NOTIFICATION_FILE_PATH",
        ),
        description=(
            "Local JSONL notification inbox (file channel). Empty path "
            "disables the channel. Example: ~/.webpent/notifications.jsonl"
        ),
    )
    notification_min_severity: str = Field(
        default="low",
        validation_alias=AliasChoices(
            "notification_min_severity",
            "NOTIFICATION_MIN_SEVERITY",
            "WEBPENT_NOTIFICATION_MIN_SEVERITY",
        ),
        description="Minimum severity bucket to notify (info|low|medium|high|critical).",
    )
    notification_queue_maxsize: int = Field(
        default=256,
        validation_alias=AliasChoices(
            "notification_queue_maxsize",
            "NOTIFICATION_QUEUE_MAXSIZE",
            "WEBPENT_NOTIFICATION_QUEUE_MAXSIZE",
        ),
        description=(
            "Bounded dispatch queue size; overflow DROPS events with a "
            "warning counter (persistence safety over notification "
            "completeness)."
        ),
    )
    # Track 12 item 2 (2026-10-28): shared concurrency governor. Limits are
    # conservative by default (resource exhaustion and campaign starvation
    # guardrails); 0 disables the corresponding limit entirely.
    max_concurrent_campaigns: int = Field(
        default=2,
        validation_alias=AliasChoices(
            "max_concurrent_campaigns",
            "MAX_CONCURRENT_CAMPAIGNS",
            "WEBPENT_MAX_CONCURRENT_CAMPAIGNS",
        ),
        description=(
            "Global cap on simultaneously RUNNING campaigns admitted by "
            "the concurrency governor (Track 12 item 2). 0 = unlimited."
        ),
    )
    max_concurrent_per_target: int = Field(
        default=1,
        validation_alias=AliasChoices(
            "max_concurrent_per_target",
            "MAX_CONCURRENT_PER_TARGET",
            "WEBPENT_MAX_CONCURRENT_PER_TARGET",
        ),
        description=(
            "Cap on concurrently RUNNING campaigns against the SAME "
            "normalized target (politeness + resource guard). 0 = unlimited."
        ),
    )
    # Track 12 item 2 phase 2 (2026-10-28): cross-process lease backend.
    # Disabled by default — phase-1 process-wide behavior is preserved
    # until the operator opts into shared caps across worker processes.
    governor_cross_process: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "governor_cross_process",
            "GOVERNOR_CROSS_PROCESS",
            "WEBPENT_GOVERNOR_CROSS_PROCESS",
        ),
        description=(
            "Enable the cross-process lease backend for the concurrency "
            "governor (Track 12 item 2 phase 2): global/per-target caps "
            "are then shared across worker processes via flock-based "
            "slot files."
        ),
    )
    governor_lease_dir: str = Field(
        default="",
        validation_alias=AliasChoices(
            "governor_lease_dir",
            "GOVERNOR_LEASE_DIR",
            "WEBPENT_GOVERNOR_LEASE_DIR",
        ),
        description=(
            "Runtime directory holding the governor's cross-process "
            "lease slot files. Empty = a safe default under the platform "
            "temp directory."
        ),
    )
    # Track 12 item 3 operational wiring (v0.25.0): campaign-lifetime
    # worker claims. Disabled by default — the service behaves exactly
    # as before until the operator opts into cross-worker mutual
    # exclusion via a shared coordination directory.
    worker_coordination_enabled: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "worker_coordination_enabled",
            "WORKER_COORDINATION_ENABLED",
            "WEBPENT_WORKER_COORDINATION_ENABLED",
        ),
        description=(
            "Enable campaign-lifetime worker claims (Track 12 item 3): "
            "each RUNNING campaign holds a coordination claim so two "
            "workers sharing a coord dir cannot run the same campaign. "
            "Resource guard only — scope/authorization are unaffected."
        ),
    )
    worker_coordination_dir: str = Field(
        default="",
        validation_alias=AliasChoices(
            "worker_coordination_dir",
            "WORKER_COORDINATION_DIR",
            "WEBPENT_WORKER_COORDINATION_DIR",
        ),
        description=(
            "Shared coordination directory for worker claims (must be on "
            "a filesystem with working flock). Required when "
            "worker_coordination_enabled is true; empty keeps the "
            "feature off."
        ),
    )
    action_ledger_path: Path = Field(
        default=Path("~/.webpent/action_ledger.sqlite3"),
        validation_alias=AliasChoices(
            "action_ledger_path",
            "ACTION_LEDGER_PATH",
            "WEBPENT_ACTION_LEDGER_PATH",
        ),
        description=(
            "Durable action reservation ledger used by runtime campaign executors; "
            "it stores redacted metadata only."
        ),
    )
    target_package_lease_path: Path = Field(
        default=Path("~/.webpent/target_package_leases.sqlite3"),
        validation_alias=AliasChoices(
            "target_package_lease_path",
            "TARGET_PACKAGE_LEASE_PATH",
            "WEBPENT_TARGET_PACKAGE_LEASE_PATH",
        ),
        description=(
            "Global durable one-time lease database for signed bbscout Target Packages. "
            "Only package identity/digests and lease metadata are stored; raw packages "
            "and trust roots are never persisted."
        ),
    )
    reauth_vault_shared_store: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "reauth_vault_shared_store",
            "WEBPENT_REAUTH_VAULT_SHARED_STORE",
        ),
        description=(
            "Persist encrypted re-auth records in shared SQLite so worker restarts "
            "can resume sessions; disabled by default for backward compatibility."
        ),
    )
    reauth_vault_database_url: str | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "reauth_vault_database_url",
            "WEBPENT_REAUTH_VAULT_DATABASE_URL",
        ),
        description=(
            "Optional SQLite URL for the shared re-auth store; when unset, "
            "DATABASE_URL is used."
        ),
    )

    # -- V10 P0-2: Embeddings / RAG offline mode ---------------------------
    # Audits flagged that all-MiniLM-L6-v2 first-run hits huggingface.co
    # and stalls offline scans for multi-minute downloads. These switches
    # let the operator declare "I am offline" or "skip RAG entirely" so
    # HTTP-only scans proceed without vector init.
    embeddings_offline: bool = Field(
        default=False,
        description=(
            "V10 P0-2: When True, the embeddings model will ONLY load "
            "from the local HuggingFace cache. If the model is not "
            "cached, RAG retrieval returns empty (no network call). "
            "Set EMBEDDINGS_OFFLINE=true for air-gapped / offline lab "
            "scans where a multi-minute huggingface.co download would "
            "stall the first scan."
        ),
    )
    disable_rag: bool = Field(
        default=False,
        description=(
            "V10 P0-2: When True, the RAG subsystem (lessons + knowledge "
            "retrieval) is explicitly disabled — no embeddings model is "
            "loaded, no Chroma store is initialised. Set DISABLE_RAG=true "
            "to skip RAG entirely (e.g. for minimal HTTP-only scans where "
            "the operator does not need lesson learning or knowledge "
            "enrichment). Distinct from EMBEDDINGS_OFFLINE: offline mode "
            "still tries to use a cached model; disable mode skips RAG "
            "completely."
        ),
    )

    # -- V10 P1-2: Configurable tool subprocess timeouts -------------------
    # Audits flagged that the nuclei timeout was hardcoded at 600s and
    # sqlmap/dalfox used the shared run_command default. These env-driven
    # ceilings let operators tune per-tool for lab vs production without
    # editing code. Safe defaults preserved.
    nuclei_timeout: int = Field(
        default=600,
        gt=0,
        description=(
            "V10 P1-2: subprocess timeout for nuclei, in seconds. "
            "Default 600 (10 min). Raise for large-scope production "
            "scans; lower for fast lab sweeps."
        ),
    )
    nuclei_request_timeout: int = Field(
        default=10,
        gt=0,
        le=120,
        validation_alias=AliasChoices(
            "nuclei_request_timeout",
            "NUCLEI_REQUEST_TIMEOUT",
            "WEBPENT_NUCLEI_REQUEST_TIMEOUT",
        ),
        description=(
            "Per-request timeout passed to nuclei templates in seconds. "
            "The engagement-level nuclei_timeout remains the outer ceiling."
        ),
    )
    nuclei_retries: int = Field(
        default=1,
        ge=0,
        le=3,
        validation_alias=AliasChoices(
            "nuclei_retries",
            "NUCLEI_RETRIES",
            "WEBPENT_NUCLEI_RETRIES",
        ),
        description="Retries for individual nuclei requests.",
    )
    nuclei_concurrency: int = Field(
        default=25,
        ge=1,
        le=100,
        validation_alias=AliasChoices(
            "nuclei_concurrency",
            "NUCLEI_CONCURRENCY",
            "WEBPENT_NUCLEI_CONCURRENCY",
        ),
        description="Maximum concurrent nuclei template requests.",
    )
    nuclei_rate_limit: int = Field(
        default=150,
        ge=0,
        le=1000,
        validation_alias=AliasChoices(
            "nuclei_rate_limit",
            "NUCLEI_RATE_LIMIT",
            "WEBPENT_NUCLEI_RATE_LIMIT",
        ),
        description=(
            "Maximum nuclei requests per second; zero leaves nuclei's own "
            "rate behavior disabled."
        ),
    )
    ffuf_timeout: int = Field(
        default=300,
        gt=0,
        le=3600,
        validation_alias=AliasChoices("ffuf_timeout", "FFUF_TIMEOUT", "WEBPENT_FFUF_TIMEOUT"),
        description="Maximum ffuf content-discovery subprocess time in seconds.",
    )
    arjun_timeout: int = Field(
        default=180,
        gt=0,
        le=3600,
        validation_alias=AliasChoices("arjun_timeout", "ARJUN_TIMEOUT", "WEBPENT_ARJUN_TIMEOUT"),
        description="Maximum arjun hidden-parameter-discovery subprocess time in seconds.",
    )
    arjun_request_timeout: int = Field(
        default=15,
        gt=0,
        le=120,
        validation_alias=AliasChoices(
            "arjun_request_timeout", "ARJUN_REQUEST_TIMEOUT", "WEBPENT_ARJUN_REQUEST_TIMEOUT"
        ),
        description="Per-HTTP-request timeout (arjun's -T) in seconds.",
    )
    sqlmap_timeout: int = Field(
        default=300,
        gt=0,
        validation_alias=AliasChoices("sqlmap_timeout", "SQLMAP_TIMEOUT", "WEBPENT_SQLMAP_TIMEOUT"),
        description="V10 P1-2: subprocess timeout for sqlmap, in seconds.",
    )
    sqlmap_post_timeout: int = Field(
        default=10,
        gt=0,
        le=60,
        validation_alias=AliasChoices(
            "sqlmap_post_timeout",
            "SQLMAP_POST_TIMEOUT",
            "WEBPENT_SQLMAP_POST_TIMEOUT",
        ),
        description=(
            "Per-request timeout passed to sqlmap for discovered POST forms. "
            "The engagement-level sqlmap_timeout remains the outer ceiling."
        ),
    )
    sqlmap_post_retries: int = Field(
        default=1,
        ge=0,
        le=3,
        validation_alias=AliasChoices(
            "sqlmap_post_retries",
            "SQLMAP_POST_RETRIES",
            "WEBPENT_SQLMAP_POST_RETRIES",
        ),
        description="Retries for sqlmap POST form requests.",
    )
    sqlmap_post_threads: int = Field(
        default=4,
        ge=1,
        le=8,
        validation_alias=AliasChoices(
            "sqlmap_post_threads",
            "SQLMAP_POST_THREADS",
            "WEBPENT_SQLMAP_POST_THREADS",
        ),
        description="Concurrent sqlmap workers for POST form validation.",
    )
    dalfox_timeout: int = Field(
        default=300,
        gt=0,
        description="V10 P1-2: subprocess timeout for dalfox, in seconds.",
    )

    # -- V10 P1-2: Configurable rate-governor thresholds -------------------
    # The RequestRateGovernor was previously constructed with hardcoded
    # max_concurrent=20 / error_rate_threshold=0.3. These env-driven
    # fields let operators tune for lab (more permissive) vs production
    # (more conservative) without editing code.
    governor_max_concurrent: int = Field(
        default=20,
        gt=0,
        validation_alias=AliasChoices(
            "governor_max_concurrent",
            "GOVERNOR_MAX_CONCURRENT",
            "WEBPENT_GOVERNOR_MAX_CONCURRENT",
        ),
        description=(
            "V10 P1-2: max concurrent in-flight requests per target host "
            "in a business-logic burst. Default 20. Lower for fragile "
            "targets; raise for lab targets that can handle the load."
        ),
    )
    governor_error_rate_threshold: float = Field(
        default=0.3,
        gt=0.0,
        le=1.0,
        description=(
            "V10 P1-2: abort a burst when the 5xx error rate crosses "
            "this fraction (default 0.3 = 30%). 4xx responses do NOT "
            "count as errors (they are target-side rejections, not "
            "infrastructure failures)."
        ),
    )
    business_logic_burst_size: int = Field(
        default=10,
        ge=1,
        le=20,
        validation_alias=AliasChoices(
            "business_logic_burst_size",
            "BUSINESS_LOGIC_BURST_SIZE",
            "WEBPENT_BUSINESS_LOGIC_BURST_SIZE",
        ),
        description=(
            "Maximum concurrent requests in one bounded race-condition "
            "probe. Lower this for fragile local labs; the default preserves "
            "the historical bounded behavior."
        ),
    )
    business_logic_max_endpoints: int = Field(
        default=10,
        ge=1,
        le=25,
        validation_alias=AliasChoices(
            "business_logic_max_endpoints",
            "BUSINESS_LOGIC_MAX_ENDPOINTS",
            "WEBPENT_BUSINESS_LOGIC_MAX_ENDPOINTS",
        ),
        description=(
            "Maximum structured state-changing forms probed by the business "
            "logic fuzzer per engagement."
        ),
    )

    # -- OOB callback infrastructure (V5 Sprint 5) --------------------------
    # Public base URL where the FastAPI app is reachable from the *target*
    # network. Used by the validator when constructing OOB callback URLs
    # for SSRF/RCE confirmation. Must be reachable from the target host.
    oob_callback_base_url: str = Field(
        default="",
        validation_alias=AliasChoices(
            "oob_callback_base_url",
            "OOB_CALLBACK_BASE_URL",
            "WEBPENT_OOB_CALLBACK_BASE_URL",
        ),
        description=(
            "Public base URL of the WebPent API used to build OOB "
            "callback URLs (e.g. 'http://203.0.113.10:8000'). The "
            "target must be able to reach this URL for OOB SSRF/RCE "
            "confirmation to succeed. Empty default = OOB URL "
            "construction disabled (SSRF/RCE will fall back to "
            "AI-Assessed). Set to http://localhost:8000 for local "
            "single-instance testing."
        ),
    )
    # Shared secret used to authenticate OOB callbacks so an attacker
    # cannot trivially forge a callback to auto-confirm a finding.
    # When empty, OOB confirmation is disabled (fail-safe).
    oob_callback_secret: str = Field(
        default="",
        validation_alias=AliasChoices(
            "oob_callback_secret",
            "OOB_CALLBACK_SECRET",
            "WEBPENT_OOB_CALLBACK_SECRET",
        ),
        description=(
            "Shared secret appended as a path segment to every OOB "
            "callback URL. The endpoint rejects requests whose secret "
            "does not match. Empty default = OOB feature disabled."
        ),
    )
    # Sprint R1 FIX 2: explicit fail-closed gate on the OOB confirmation
    # route, separate from oob_callback_secret. oob_callback_secret governs
    # authentication of an incoming callback; this flag governs whether the
    # route is permitted to run at all. _oob_db_lookup_and_confirm builds a
    # ProofBundle and writes db.mark_oob_confirmed() directly, outside the
    # framework's normal verification pipeline, so the route must be
    # explicitly enabled in addition to having a secret configured.
    # Default False = both OOB callback routes are disabled out of the box.
    oob_confirm_route_enabled: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "oob_confirm_route_enabled",
            "OOB_CONFIRM_ROUTE_ENABLED",
            "WEBPENT_OOB_CONFIRM_ROUTE_ENABLED",
        ),
        description=(
            "Fail-closed master switch for the OOB confirmation callback "
            "routes (GET/POST /api/oob/{finding_id}/{secret} and the "
            "workspace-scoped variant). Default disabled: both routes "
            "return a non-mutating response and perform no DB writes "
            "until this is explicitly set true."
        ),
    )
    # How long the validator blocks waiting for an OOB callback before
    # falling back to AI-Assessed. Kept short so the graph stays snappy.
    oob_poll_timeout_seconds: float = Field(
        default=3.0,
        ge=0.5,
        le=30.0,
        description="Seconds to wait for an OOB callback before fallback.",
    )
    oob_poll_max_attempts: int = Field(
        default=100,
        validation_alias=AliasChoices(
            "oob_poll_max_attempts",
            "OOB_POLL_MAX_ATTEMPTS",
            "WEBPENT_OOB_POLL_MAX_ATTEMPTS",
        ),
        ge=1,
        le=300,
        description="Maximum database polls per OOB validation attempt.",
    )

    # -- Optional Interactsh OOB provider ------------------------------------
    # The local authenticated callback remains the default.  External OOB is
    # opt-in and requires an explicit server so offline/local runs never
    # contact a public service implicitly.
    oob_provider: str = Field(
        default="local",
        validation_alias=AliasChoices(
            "oob_provider",
            "OOB_PROVIDER",
            "WEBPENT_OOB_PROVIDER",
        ),
        description="OOB provider: local (default) or interactsh (explicit opt-in).",
    )
    interactsh_binary: str = Field(
        default="interactsh-client",
        validation_alias=AliasChoices(
            "interactsh_binary",
            "INTERACTSH_BINARY",
            "WEBPENT_INTERACTSH_BINARY",
        ),
        description="Pinned interactsh-client executable path/name.",
    )
    interactsh_server: str = Field(
        default="",
        validation_alias=AliasChoices(
            "interactsh_server",
            "INTERACTSH_SERVER",
            "WEBPENT_INTERACTSH_SERVER",
        ),
        description="Explicit self-hosted Interactsh server; empty disables provider.",
    )
    interactsh_token: SecretStr = Field(
        default=SecretStr(""),
        validation_alias=AliasChoices(
            "interactsh_token",
            "INTERACTSH_TOKEN",
            "WEBPENT_INTERACTSH_TOKEN",
        ),
        description="Optional protected Interactsh server token; never report it.",
    )
    interactsh_poll_interval_seconds: int = Field(
        default=1,
        ge=1,
        le=30,
        validation_alias=AliasChoices(
            "interactsh_poll_interval_seconds",
            "INTERACTSH_POLL_INTERVAL_SECONDS",
            "WEBPENT_INTERACTSH_POLL_INTERVAL_SECONDS",
        ),
        description="Bounded Interactsh polling interval.",
    )

    # -- Stealth mode (V5 Sprint 6) -----------------------------------------
    # When stealth_mode is True, the framework inserts randomized
    # delays (jitter) before every external tool invocation and every
    # Playwright navigation/form-submit, and enforces a minimum spacing
    # between successive requests to the same target. This helps evade
    # naive WAF / IDS rules that flag bursty, machine-paced traffic.
    # All values are in seconds. Defaults are conservative (2-5s jitter)
    # and can be tuned via environment variables.
    stealth_jitter_min: float = Field(
        default=2.0,
        ge=0.0,
        description=(
            "Minimum jitter (seconds) inserted before tool/Playwright "
            "actions when stealth_mode is enabled."
        ),
    )
    stealth_jitter_max: float = Field(
        default=5.0,
        ge=0.0,
        description=(
            "Maximum jitter (seconds) inserted before tool/Playwright "
            "actions when stealth_mode is enabled. Must be >= "
            "stealth_jitter_min."
        ),
    )
    # Hard floor on inter-request spacing. Even if jitter draws a small
    # value, two consecutive requests to the same host are always
    # separated by at least this many seconds.
    stealth_min_request_interval: float = Field(
        default=1.0,
        ge=0.0,
        description="Minimum seconds between successive target requests in stealth mode.",
    )

    # -- Webhook / Ticketing Integration (V5 Sprint 11) --------------------
    # When enabled, the framework pushes "Tool-Confirmed" and
    # "Needs Human Review" findings to an external webhook (Slack,
    # Discord, Jira, etc.) via the integrations.webhook module.
    webhook_enabled: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "webhook_enabled", "WEBHOOK_ENABLED", "WEBPENT_WEBHOOK_ENABLED"
        ),
        description=(
            "V5 Sprint 11: When True, push actionable findings to the "
            "configured webhook URL. Set WEBHOOK_ENABLED=true to enable."
        ),
    )
    webhook_url: str = Field(
        default="",
        validation_alias=AliasChoices("webhook_url", "WEBHOOK_URL", "WEBPENT_WEBHOOK_URL"),
        description=(
            "V5 Sprint 11: The webhook endpoint URL to receive finding "
            "notifications (Slack, Discord, Jira, custom). Empty string "
            "disables the integration even if webhook_enabled is True."
        ),
    )
    webhook_on_promoted: bool = Field(
        default=True,
        validation_alias=AliasChoices(
            "webhook_on_promoted", "WEBHOOK_ON_PROMOTED", "WEBPENT_WEBHOOK_ON_PROMOTED"
        ),
        description="Emit one lifecycle webhook when a finding is promoted.",
    )
    webhook_on_refuted: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "webhook_on_refuted", "WEBHOOK_ON_REFUTED", "WEBPENT_WEBHOOK_ON_REFUTED"
        ),
        description="Optionally emit lifecycle webhooks for refuted findings.",
    )
    webhook_on_campaign_complete: bool = Field(
        default=True,
        validation_alias=AliasChoices(
            "webhook_on_campaign_complete", "WEBHOOK_ON_CAMPAIGN_COMPLETE",
            "WEBPENT_WEBHOOK_ON_CAMPAIGN_COMPLETE",
        ),
        description="Emit one lifecycle webhook when a campaign completes.",
    )
    webhook_timeout: float = Field(
        default=10.0,
        validation_alias=AliasChoices(
            "webhook_timeout", "WEBHOOK_TIMEOUT", "WEBPENT_WEBHOOK_TIMEOUT"
        ),
        ge=1.0,
        description="Webhook HTTP request timeout in seconds.",
    )
    webhook_secret: SecretStr = Field(
        default=SecretStr(""),
        validation_alias=AliasChoices("webhook_secret", "WEBHOOK_SECRET", "WEBPENT_WEBHOOK_SECRET"),
        description=(
            "HMAC signing secret for webhook payloads. Webhook delivery is "
            "refused when enabled without a non-empty secret."
        ),
    )
    webhook_max_concurrency: int = Field(
        default=4,
        validation_alias=AliasChoices(
            "webhook_max_concurrency",
            "WEBHOOK_MAX_CONCURRENCY",
            "WEBPENT_WEBHOOK_MAX_CONCURRENCY",
        ),
        ge=1,
        le=32,
        description=("Maximum number of concurrent webhook deliveries in a batch."),
    )

    # -- API Security (V5 Sprint 13 / V6 Develop-First) -------------------
    # Local development/lab may keep auth disabled explicitly; strict profiles
    # hard-stop unless authentication and real secrets are configured.
    auth_enabled: bool = Field(
        default=False,
        validation_alias=AliasChoices("auth_enabled", "AUTH_ENABLED", "WEBPENT_AUTH_ENABLED"),
        description=(
            "V6: When False, all JWT validation is bypassed and the "
            "default admin user is returned. Set to True for production."
        ),
    )
    # JWT authentication + RBAC for all /api/v1/* endpoints.
    jwt_secret_key: str = Field(
        default="",
        validation_alias=AliasChoices("jwt_secret_key", "JWT_SECRET_KEY", "WEBPENT_JWT_SECRET_KEY"),
        description=(
            "Secret key used to sign JWTs. It is intentionally empty by default; "
            "strict profiles require an operator-supplied JWT_SECRET_KEY."
        ),
    )
    audit_secret_key: str = Field(
        default="",
        validation_alias=AliasChoices(
            "audit_secret_key", "AUDIT_SECRET_KEY", "WEBPENT_AUDIT_SECRET_KEY"
        ),
        description=(
            "HMAC-SHA256 key used to sign evidence bundles and the master "
            "report hash. It is intentionally empty by default; strict "
            "profiles require an operator-supplied AUDIT_SECRET_KEY."
        ),
    )
    # V10 HOSTILE-AUDIT FIX (CH-2): key used to encrypt operator-supplied
    # credentials (specifically the password) for the duration they sit
    # on the Celery/Redis broker as task kwargs. Without this, ScanRequest
    # credentials transit Redis (task_serializer="json", plain redis://
    # by default — see workers/pentest_worker.py) in PLAINTEXT. See
    # webpent.utils.task_crypto for the encrypt/decrypt call sites (API
    # dispatch and worker task entry, respectively). A Fernet key is
    # derived from this string via versioned PBKDF2-HMAC-SHA256 so operators
    # can set any sufficiently long passphrase, matching the UX of
    # jwt_secret_key / audit_secret_key above, rather than being required
    # to hand-generate a raw Fernet key.
    celery_payload_key: str = Field(
        default="",
        # V10 EXHAUSTIVE AUDIT (reviewer follow-up): this Settings class
        # has no env_prefix, so pydantic-settings only ever read the
        # BARE env var name here -- confirmed empirically. The
        # description below (and .env.example, and the runtime warning
        # a few hundred lines down) told operators to set
        # WEBPENT_CELERY_PAYLOAD_KEY, which was silently never read;
        # the insecure default stayed in effect even after "fixing" it
        # per the docs. AliasChoices accepts BOTH names so this is
        # fixed for new deployments following the corrected docs below
        # AND for anyone who already set the old (broken) name.
        validation_alias=AliasChoices(
            "CELERY_PAYLOAD_KEY", "WEBPENT_CELERY_PAYLOAD_KEY", "celery_payload_key"
        ),
        description=(
            "Passphrase used to derive the Fernet key that encrypts "
            "operator-supplied credentials before they are placed on the "
            "Celery/Redis broker. It is intentionally empty by default; "
            "strict profiles require an operator-supplied key via "
            "CELERY_PAYLOAD_KEY (WEBPENT_CELERY_PAYLOAD_KEY is also "
            "accepted for back-compat). Does not replace TLS on the "
            "Redis connection itself (WEBPENT_REDIS_URL should still use "
            "rediss:// in production) — this is defense in depth for the "
            "task PAYLOAD specifically."
        ),
    )
    celery_payload_key_previous: str | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "CELERY_PAYLOAD_KEY_PREVIOUS",
            "WEBPENT_CELERY_PAYLOAD_KEY_PREVIOUS",
            "CELERY_PAYLOAD_KEY_OLD",
            "WEBPENT_CELERY_PAYLOAD_KEY_OLD",
            "celery_payload_key_previous",
        ),
        description=(
            "Optional previous Celery payload passphrase used only to decrypt "
            "legacy envelopes during key rotation; new payloads always use the current key."
        ),
    )
    jwt_algorithm: str = Field(
        default="HS256",
        description="JWT signing algorithm (HS256, HS384, HS512, RS256).",
    )
    jwt_issuer: str = Field(
        default="webpent-api",
        validation_alias=AliasChoices("jwt_issuer", "JWT_ISSUER", "WEBPENT_JWT_ISSUER"),
        min_length=1,
        max_length=128,
        description="Expected JWT issuer claim.",
    )
    jwt_audience: str = Field(
        default="webpent",
        validation_alias=AliasChoices("jwt_audience", "JWT_AUDIENCE", "WEBPENT_JWT_AUDIENCE"),
        min_length=1,
        max_length=128,
        description="Expected JWT audience claim.",
    )
    jwt_expire_minutes: int = Field(
        default=60,
        validation_alias=AliasChoices(
            "jwt_expire_minutes", "JWT_EXPIRE_MINUTES", "WEBPENT_JWT_EXPIRE_MINUTES"
        ),
        ge=1,
        description="JWT token lifetime in minutes (default 1 hour).",
    )

    # -- CORS (V5 Sprint 13) -----------------------------------------------
    cors_origins: list[str] = Field(
        default_factory=lambda: ["*"],
        validation_alias=AliasChoices("cors_origins", "CORS_ORIGINS", "WEBPENT_CORS_ORIGINS"),
        description=(
            "V5 Sprint 13: Allowed CORS origins. Use ['*'] for dev "
            "(any origin). For production, specify explicit origins: "
            "['https://app.example.com', 'https://console.example.com']."
        ),
    )

    # -- Rate Limiting (V5 Sprint 13) --------------------------------------
    rate_limit_enabled: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "rate_limit_enabled", "RATE_LIMIT_ENABLED", "WEBPENT_RATE_LIMIT_ENABLED"
        ),
        description=(
            "V6: Defaults to False for frictionless development/testing. "
            "Set RATE_LIMIT_ENABLED=true in production to enforce limits."
        ),
    )
    # M1-A (M-3): the transport-level ceiling enforced by
    # SSRFPinningTransport via the process-wide GlobalRateGovernor when
    # rate_limit_enabled is on.  The factory in
    # shared/global_rate_governor.py reads these exact field names and
    # falls back to 8/120 when they are absent.
    global_rate_governor_max_concurrent: int = Field(
        default=8,
        validation_alias=AliasChoices(
            "global_rate_governor_max_concurrent",
            "GLOBAL_RATE_GOVERNOR_MAX_CONCURRENT",
            "WEBPENT_GLOBAL_RATE_GOVERNOR_MAX_CONCURRENT",
        ),
        description=(
            "Max in-flight requests through the safe transport across the "
            "whole process (rate_limit_enabled=true)."
        ),
    )
    global_rate_governor_requests_per_minute: int = Field(
        default=120,
        validation_alias=AliasChoices(
            "global_rate_governor_requests_per_minute",
            "GLOBAL_RATE_GOVERNOR_REQUESTS_PER_MINUTE",
            "WEBPENT_GLOBAL_RATE_GOVERNOR_REQUESTS_PER_MINUTE",
        ),
        description=(
            "Max requests per rolling 60s window through the safe "
            "transport across the whole process (rate_limit_enabled=true)."
        ),
    )
    rate_limit_scan_per_minute: int = Field(
        default=5,
        validation_alias=AliasChoices(
            "rate_limit_scan_per_minute",
            "RATE_LIMIT_SCAN_PER_MINUTE",
            "WEBPENT_RATE_LIMIT_SCAN_PER_MINUTE",
        ),
        ge=1,
        description="Max scan-trigger requests per minute per IP/client.",
    )
    rate_limit_global_per_minute: int = Field(
        default=60,
        validation_alias=AliasChoices(
            "rate_limit_global_per_minute",
            "RATE_LIMIT_GLOBAL_PER_MINUTE",
            "WEBPENT_RATE_LIMIT_GLOBAL_PER_MINUTE",
        ),
        ge=1,
        description="Max global API requests per minute per IP/client.",
    )
    rate_limit_login_per_minute: int = Field(
        default=10,
        validation_alias=AliasChoices(
            "rate_limit_login_per_minute",
            "RATE_LIMIT_LOGIN_PER_MINUTE",
            "WEBPENT_RATE_LIMIT_LOGIN_PER_MINUTE",
        ),
        ge=1,
        description="Max login attempts per minute per IP and account key.",
    )
    rate_limit_redis_url: str = Field(
        default="",
        validation_alias=AliasChoices(
            "rate_limit_redis_url",
            "RATE_LIMIT_REDIS_URL",
            "WEBPENT_RATE_LIMIT_REDIS_URL",
        ),
        description=(
            "Redis URL for distributed rate limiting. Empty string = "
            "in-process memory limiter (single-instance only)."
        ),
    )
    # V6.1 P1: Only trust X-Forwarded-For from these proxy IPs.
    # Prevents spoofing by direct clients claiming to be behind a proxy.
    trusted_proxy_ips: list[str] = Field(
        default_factory=lambda: ["127.0.0.1", "172.18.0.0/16", "172.19.0.0/16"],
        validation_alias=AliasChoices(
            "trusted_proxy_ips", "TRUSTED_PROXY_IPS", "WEBPENT_TRUSTED_PROXY_IPS"
        ),
        description=(
            "V6.1: IPs/subnets trusted to send X-Forwarded-For headers. "
            "Requests from IPs not in this list will use request.client.host "
            "directly (ignoring X-Forwarded-For)."
        ),
    )

    # -- V7 P0: Dev/Prod Mode Framework — REMOVED ---------------------------
    # The old operation_mode / mock_target_hosts allowlist has been
    # removed entirely (P0 fix — Private-IP auth/crawl blocker). It was
    # a redundant mechanism operators had to manage by hand, and it was
    # not even the actual cause of private-IP targets (e.g. lab DVWA
    # hosts) being blocked — the private/reserved-network blocklist in
    # shared/http.py blocked them unconditionally, in BOTH modes. That
    # blocklist now allows the engagement's own declared target through
    # (see shared/engagement_scope.py) while still blocking every other
    # private-network host, which is the fix that actually matters.
    # If you have an old .env with OPERATION_MODE= or MOCK_TARGET_HOSTS=
    # set, those lines are now silently ignored (extra="ignore" below).
    mock_oob_server_url: str = Field(
        default="http://127.0.0.1:18099",
        description=(
            "V7 Sprint 0.3 / V8 P0 A0 cleanup: Base URL of the local "
            "mock OOB server. The mock server records canary-token pings "
            "so _poll_for_oob_callback can be tested end-to-end without "
            "contacting real Interactsh/Burp Collaborator. Empty string "
            "means use the real OOB provider. (The previous description "
            "referenced the removed Dev/Prod Mode framework — that "
            "framework was deleted in V7 P0; this field is now just a "
            "plain configuration knob, not a mode toggle.)"
        ),
    )

    # -- Validators ----------------------------------------------------------
    # V6 Zero-Day Patched P0-2 / V6 The-Final-Seal P0-3: Both the JWT
    # secret AND the audit secret are now validated via a single
    # ``@model_validator(mode="after")`` instead of separate
    # ``@field_validator`` decorators. A field_validator only sees the
    # individual field value in isolation and has NO access to
    # ``self.auth_enabled`` — so it could only log a warning when a
    # default secret was detected, never hard-stop. An operator who
    # set AUTH_ENABLED=true without overriding the secret env vars
    # would get a silently-insecure production deployment: JWTs / HMAC
    # signatures produced with publicly-known default keys, forgeable
    # by anyone who reads the source code.
    #
    # The model_validator runs AFTER all fields are populated, so it can
    # inspect BOTH ``self.auth_enabled`` and the secret fields. When
    # auth is enabled AND a secret is an insecure default, it raises
    # ``ValueError`` to hard-stop Settings construction — Pydantic
    # surfaces this as a validation error, preventing the app from
    # starting with an insecure configuration.
    _INSECURE_JWT_DEFAULTS = frozenset(
        {
            "webpent-dev-secret-key-change-in-production",
            "change-me-in-production",
            "",
        }
    )

    # M1-A (H-2, 2026-11-05): the placeholder format actually shipped in
    # .env.example ("CHANGE-ME-generate-a-random-secret" — 34 chars, so it
    # also passed every length check) was never a member of the three
    # insecure-default sets, so an operator who copied .env.example to
    # .env and flipped AUTH_ENABLED=true got a clean Settings() built on
    # repo-readable, forgeable secrets. Reject the whole placeholder
    # family by prefix, case-insensitively.
    @staticmethod
    def _looks_like_placeholder(value: str) -> bool:
        v = str(value or "").strip()
        return v.upper().startswith("CHANGE-ME") or v.upper().startswith("CHANGEME")

    # V6 The-Final-Seal P0-3: audit_secret_key has its own set of
    # insecure defaults. We reuse the same _INSECURE_JWT_DEFAULTS
    # set name for the JWT check (above), and define a separate
    # set here for the audit key. The CISO directive specifies
    # ``self.audit_secret_key in self._INSECURE_JWT_DEFAULTS`` —
    # i.e. the audit key must be checked against the SAME insecure-
    # defaults set as the JWT key. We union the audit-specific
    # default into _INSECURE_JWT_DEFAULTS so the cross-field check
    # catches both the JWT default AND the audit default under one
    # set. (An empty string is already in _INSECURE_JWT_DEFAULTS.)
    # However, to keep the audit-specific default visible and
    # self-documenting, we ALSO list it here — the union is
    # idempotent because frozenset deduplicates.
    _INSECURE_AUDIT_DEFAULTS = frozenset(
        {
            "webpent-dev-audit-key-change-in-production",
            # The CISO directive checks audit_secret_key against
            # _INSECURE_JWT_DEFAULTS, so we don't need a separate
            # list — but we keep this frozenset for documentation
            # and in case future audits want to diverge the sets.
        }
    )

    # V10 HOSTILE-AUDIT FIX (CH-2): insecure default for the new
    # celery_payload_key, checked in the same model_validator below
    # using the same auth_enabled-gated hard-stop pattern as the JWT
    # and audit keys.
    _INSECURE_CELERY_PAYLOAD_DEFAULTS = frozenset(
        {
            "webpent-dev-celery-payload-key-change-in-production",
            "",
        }
    )

    @model_validator(mode="after")
    def _validate_jwt_secret_key(self) -> Settings:
        """V6 Zero-Day Patched P0-2 / V6 The-Final-Seal P0-3: Hard-stop on insecure default secrets.

        Replaces the previous ``@field_validator("jwt_secret_key")`` and
        ``@field_validator("audit_secret_key")`` which only logged
        warnings because they lacked access to ``self.auth_enabled``.
        The model validator runs after all fields are populated, so it
        can enforce the cross-field invariant: auth MUST NOT be enabled
        with a known-insecure default secret.

        V6 The-Final-Seal P0-3: The audit_secret_key check was
        previously a separate ``@field_validator`` that only logged a
        warning. It is now folded into this model_validator so the
        same hard-stop semantics apply: if ``auth_enabled is True``
        AND ``audit_secret_key`` is an insecure default, raise
        ``ValueError``.

        Raises:
            ValueError: If ``auth_enabled is True`` AND
                ``jwt_secret_key`` is one of the insecure JWT defaults.
                Also if ``auth_enabled is True`` AND
                ``audit_secret_key`` is one of the insecure defaults
                (per the CISO directive, checked against
                ``_INSECURE_JWT_DEFAULTS``).
        """
        # bbscout is an advisory package source only. These checks prevent a
        # configuration typo from turning it into an account-creation or provider
        # submission agent.
        if self.bbscout_mode not in {"offline", "live"}:
            raise ValueError("bbscout_mode must be either 'offline' or 'live'")
        if self.bbscout_mode == "live" and not self.bbscout_require_verified_signature:
            raise ValueError("live bbscout mode requires verified detached signatures")
        if self.bbscout_signup_enabled:
            raise ValueError("automatic bbscout signup is disabled by policy")
        if self.bbscout_provider_submission_enabled:
            raise ValueError("automatic bbscout provider submission is disabled by policy")
        if self.bbscout_browser_enabled and not self.bbscout_browser_read_only:
            raise ValueError("bbscout browser handoff must remain read-only")

        # Environment profile is explicit and fail-closed for non-lab deployments.
        # The lab default preserves existing local/offline behavior while staging and
        # production cannot silently run with authentication disabled.
        strict_profile = self.environment_profile in {
            EnvironmentProfile.QUALIFICATION,
            EnvironmentProfile.STAGING,
            EnvironmentProfile.PRODUCTION,
        }
        if strict_profile and not self.auth_enabled:
            raise ValueError(
                "SECURITY HARD STOP: environment_profile qualification/staging/production requires "
                "auth_enabled=True"
            )
        if strict_profile:
            if not self.cors_origins or "*" in self.cors_origins:
                raise ValueError(
                    "SECURITY HARD STOP: qualification/staging/production requires "
                    "explicit cors_origins"
                )
            if not self.rate_limit_enabled:
                raise ValueError(
                    "SECURITY HARD STOP: qualification/staging/production requires "
                    "rate_limit_enabled=True"
                )
            if not self.rate_limit_redis_url.lower().startswith("rediss://"):
                raise ValueError(
                    "SECURITY HARD STOP: qualification/staging/production requires a rediss:// "
                    "rate_limit_redis_url"
                )
            if self.allow_insecure_tls:
                raise ValueError(
                    "SECURITY HARD STOP: qualification/staging/production cannot "
                    "enable allow_insecure_tls"
                )

        # --- JWT secret hard-stop (V6 Zero-Day Patched P0-2) ---
        # M1-A (H-2): placeholder-form values ("CHANGE-ME-*" from
        # .env.example) are rejected alongside the named legacy defaults.
        if (
            (strict_profile or self.auth_enabled is True)
            and self.jwt_secret_key in self._INSECURE_JWT_DEFAULTS
        ):
            raise ValueError(
                "Hard-stop: Insecure default JWT secret used in production with auth_enabled=True"
            )
        if (
            (strict_profile or self.auth_enabled is True)
            and self._looks_like_placeholder(self.jwt_secret_key)
        ):
            raise ValueError(
                "Hard-stop: JWT_SECRET_KEY is still the .env.example placeholder "
                "(CHANGE-ME-*) — generate a real random secret before enabling "
                "auth (M1-A/H-2)."
            )
        # JWT minimum-length check (retained from the old field_validator).
        if (
            self.jwt_secret_key
            and len(self.jwt_secret_key) < 32
            and self.jwt_secret_key not in self._INSECURE_JWT_DEFAULTS
        ):
            raise ValueError(
                f"SECURITY HARD STOP: jwt_secret_key is only {len(self.jwt_secret_key)} "
                f"chars long — minimum 32 required for HS256."
            )

        # --- Audit secret hard-stop (V6 The-Final-Seal P0-3) ---
        # The CISO directive specifies:
        #   if self.auth_enabled is True and self.audit_secret_key in self._INSECURE_JWT_DEFAULTS:
        #       raise ValueError(...)
        # We check audit_secret_key against _INSECURE_JWT_DEFAULTS
        # (which includes "", "change-me-in-production", and the JWT
        # dev default) PLUS the audit-specific dev default. The
        # union is built lazily here so the check is self-contained.
        _all_insecure_audit = self._INSECURE_JWT_DEFAULTS | self._INSECURE_AUDIT_DEFAULTS
        if (
            (strict_profile or self.auth_enabled is True)
            and self.audit_secret_key in _all_insecure_audit
        ):
            raise ValueError(
                "Hard-stop: Insecure default audit secret used in production with auth_enabled=True"
            )
        # M1-A (H-2): placeholder-form audit secrets rejected as well.
        if (
            (strict_profile or self.auth_enabled is True)
            and self._looks_like_placeholder(self.audit_secret_key)
        ):
            raise ValueError(
                "Hard-stop: AUDIT_SECRET_KEY is still the .env.example "
                "placeholder (CHANGE-ME-*) — evidence HMACs would be forgeable "
                "with a repo-readable key (M1-A/H-2)."
            )
        # V10 AUDIT FIX (H9): in dev mode (auth_enabled=False), log a
        # loud WARNING if the insecure default is used — the operator
        # should know evidence hashes are forgeable. Previously the
        # insecure default was used SILENTLY in dev mode.
        # Sprint I-1b, item 2.3: this used to additionally require
        # `and self.audit_secret_key` (a truthy check), which meant the
        # warning never fired for the actual out-of-the-box default
        # ("" — confirmed the literal Field(default="") above) since ""
        # is falsy — only an explicitly-set-but-still-insecure NAMED
        # default (e.g. "webpent-dev-audit-key-change-in-production")
        # would warn. The plain, unconfigured empty-string case —
        # by far the most common dev/lab state — silently warned
        # about nothing at all. Removed the truthy check so every
        # insecure value, including the bare default, warns.
        if self.auth_enabled is False and self.audit_secret_key in _all_insecure_audit:
            import warnings as _warnings

            _warnings.warn(
                "INSECURE audit_secret_key in dev mode — evidence hashes "
                "are HMAC'd with a publicly-known key and can be forged. "
                "Set AUDIT_SECRET_KEY to a strong random value for any "
                "non-local deployment.",
                stacklevel=2,
            )
        # Audit secret minimum-length check (retained from the old
        # field_validator). Runs for both dev and prod — a 10-char
        # custom audit key is too short for HMAC-SHA256.
        if (
            self.audit_secret_key
            and len(self.audit_secret_key) < 32
            and self.audit_secret_key not in _all_insecure_audit
        ):
            raise ValueError(
                f"SECURITY HARD STOP: audit_secret_key is only {len(self.audit_secret_key)} "
                f"chars long — minimum 32 required for HMAC-SHA256."
            )

        # --- Celery payload key hard-stop (V10 HOSTILE-AUDIT FIX / CH-2) ---
        # Same pattern as the JWT/audit checks above: only hard-stop when
        # auth_enabled=True (the codebase's existing signal for "this is
        # a production-intent deployment, not frictionless dev"), so
        # Settings() with zero env vars still constructs successfully for
        # local dev / tests, unchanged from before this fix.
        if (
            (strict_profile or self.auth_enabled is True)
            and self.celery_payload_key in self._INSECURE_CELERY_PAYLOAD_DEFAULTS
        ):
            raise ValueError(
                "Hard-stop: Insecure default celery_payload_key used in "
                "production with auth_enabled=True — operator credentials "
                "would be encrypted with a publicly-known key, which is "
                "equivalent to not encrypting them at all."
            )
        # M1-A (H-2): placeholder-form Celery payload keys rejected as well.
        if (
            (strict_profile or self.auth_enabled is True)
            and self._looks_like_placeholder(self.celery_payload_key)
        ):
            raise ValueError(
                "Hard-stop: CELERY_PAYLOAD_KEY is still the .env.example "
                "placeholder (CHANGE-ME-*) — task credentials would transit "
                "Redis encrypted with a repo-readable key (M1-A/H-2)."
            )
        # V10 AUDIT FIX (H9): in dev mode, warn loudly if the insecure
        # default celery_payload_key is used — task passwords are
        # decryptable by anyone with Redis access.
        # Sprint I-1b, item 2.3: same fix as the audit_secret_key
        # warning above — removed the `and self.celery_payload_key`
        # truthy check so the bare, out-of-the-box empty-string default
        # warns too, not just an explicitly-set named insecure value.
        # TC-4 C1(b): condition wrapped — the single-line form tripped E501;
        # the truthiness semantics are unchanged (no line-concat of string
        # literals involved — pure boolean wrap).
        if (
            self.auth_enabled is False
            and self.celery_payload_key in self._INSECURE_CELERY_PAYLOAD_DEFAULTS
        ):
            import warnings as _warnings2

            _warnings2.warn(
                "INSECURE celery_payload_key in dev mode — task passwords "
                "are encrypted with a publicly-known key and can be "
                "decrypted by anyone with Redis access. Set "
                "CELERY_PAYLOAD_KEY to a strong random value "
                "for any non-local deployment.",
                stacklevel=2,
            )
        if (
            self.celery_payload_key
            and len(self.celery_payload_key) < 32
            and self.celery_payload_key not in self._INSECURE_CELERY_PAYLOAD_DEFAULTS
        ):
            raise ValueError(
                f"SECURITY HARD STOP: celery_payload_key is only "
                f"{len(self.celery_payload_key)} chars long — minimum 32 "
                f"required (it is SHA-256-derived into a Fernet key)."
            )
        return self

    @field_validator("log_level", mode="before")
    @classmethod
    def _normalise_log_level(cls, v: str | LogLevel) -> LogLevel:
        if isinstance(v, LogLevel):
            return v
        return LogLevel(str(v).upper())

    @field_validator("default_llm_provider", mode="before")
    @classmethod
    def _normalise_provider(cls, v: str | LLMProvider) -> LLMProvider:
        if isinstance(v, LLMProvider):
            return v
        return LLMProvider(str(v).lower())

    # -- Helpers -------------------------------------------------------------
    def api_key_for(self, provider: LLMProvider) -> str | None:
        return {
            LLMProvider.OPENAI: self.openai_api_key,
            LLMProvider.ANTHROPIC: self.anthropic_api_key,
            LLMProvider.GROQ: self.groq_api_key,
            LLMProvider.LOCAL: self.local_llm_api_key,
        }[provider]

    def ensure_output_dir(self) -> Path:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        return self.output_dir


_ACTIVE_SETTINGS: ContextVar[Settings | None] = ContextVar(
    "webpent_active_settings", default=None
)


@lru_cache(maxsize=1)
def _base_settings() -> Settings:
    """Return the process-wide legacy Settings singleton."""
    return Settings()


def get_settings() -> Settings:
    """Return active target-scoped settings, or the legacy singleton."""
    active = _ACTIVE_SETTINGS.get()
    return active if active is not None else _base_settings()


# Preserve the public cache-management hook used by existing tests and callers.
get_settings.cache_clear = _base_settings.cache_clear  # type: ignore[attr-defined]


@contextmanager
def activate_settings(settings: Settings) -> Iterator[Settings]:
    """Temporarily activate settings for one target execution context."""
    token = _ACTIVE_SETTINGS.set(settings)
    try:
        yield settings
    finally:
        _ACTIVE_SETTINGS.reset(token)
