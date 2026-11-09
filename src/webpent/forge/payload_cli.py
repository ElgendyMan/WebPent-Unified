"""U-FORGE-16 — The Payload CLI.

Full terminal control of THE FORGE, exactly the spec's command
surface: ingest / find / adapt / mutate / synthesize / waf-bypass /
corpus status+stats+export / attribution / license-report. Each
command is argv in, a structured CLIResult out — no real terminal,
no real network. Find/adapt/mutate/synthesize/waf-bypass exercise
the real engines (QueryEngine, Contextualizer, mutation,
synthesizer) against the corpus.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from webpent.forge.contextualizer import Contextualizer
from webpent.forge.mutation import mutate
from webpent.forge.schemas import Family, NormalizedPayload

_WAF_CONTEXTS = {
    "cloudflare": "cloudflare",
    "aws": "aws_waf",
    "akamai": "akamai",
}


def endpoints_annotated(payloads) -> bool:
    """Does the corpus carry endpoint annotations at all? On an
    unannotated corpus an --endpoint flag cannot filter and passes
    through (the annotation is simply absent)."""
    for p in payloads:
        try:
            if p.target_endpoints:
                return True
        except AttributeError:
            continue
    return False


@dataclass(frozen=True)
class CLIResult:
    command: str
    ok: bool
    data: dict = field(default_factory=dict)
    text: str = ""


class PayloadCLI:
    """Dispatches the spec's commands over the corpus."""

    def __init__(self, indexer, contextualizer=None,
                 synthesizer=None) -> None:
        self._indexer = indexer
        self._contextualizer = contextualizer or Contextualizer()
        self._synthesizer = synthesizer

    # ------------------------------------------------------------------

    def run(self, argv: list[str]) -> CLIResult:
        if not argv:
            return self._unknown([])
        if argv[0] in ("--help", "-h", "help"):
            return self._help()
        handler = {
            "ingest": self._ingest,
            "find": self._find,
            "adapt": self._adapt,
            "mutate": self._mutate,
            "synthesize": self._synthesize,
            "waf-bypass": self._waf_bypass,
            "corpus": self._corpus,
            "attribution": self._attribution,
            "license-report": self._license_report,
        }.get(argv[0])
        if handler is None:
            return self._unknown(argv)
        return handler(argv[1:])

    # ------------------------------------------------------------------

    def _unknown(self, argv: list[str]) -> CLIResult:
        return CLIResult(
            command=argv[0] if argv else "",
            ok=False,
            data={"message": f"unknown command: "
                             f"{argv[0] if argv else '(empty)'}"})

    def _help(self) -> CLIResult:
        text = (
            "THE FORGE payload CLI\n"
            "  ingest <source> --dry-run|--all\n"
            "  find <FAMILY> [--tech T] [--waf W] [--context C] "
            "[--endpoint E] [--limit N]\n"
            "  adapt <payload-id> [--for-tech T] [--for-waf W] "
            "[--for-context C]\n"
            "  mutate <payload-id> [--max-variants N]\n"
            "  synthesize --family sqli [--grammar standard]\n"
            "  waf-bypass <payload-id> --target-waf W\n"
            "  corpus status|stats|export [--format jsonl]\n"
            "  attribution <payload-id>\n"
            "  license-report")
        return CLIResult(command="--help", ok=True,
                         data={"text": text}, text=text)

    def _flags(self, args: list[str]) -> dict[str, str]:
        flags: dict[str, str] = {}
        i = 0
        while i < len(args):
            token = args[i]
            if token.startswith("--") and i + 1 < len(args):
                flags[token[2:]] = args[i + 1]
                i += 2
            else:
                i += 1
        return flags

    def _ingest(self, args: list[str]) -> CLIResult:
        if not args:
            return CLIResult(command="ingest", ok=False,
                             data={"message": "ingest needs a source"})
        source_id = args[0]
        flags = self._flags(args)
        from webpent.forge.ingester import MultiSourceIngester
        ingester = MultiSourceIngester(self._indexer)
        dry_run = "--dry-run" in args
        report = ingester.ingest(source_id,
                                 content=flags.get("content", ""),
                                 dry_run=dry_run)
        return CLIResult(command="ingest", ok=True,
                         data={"source": source_id,
                               "dry_run": dry_run,
                               "report": report})

    def _find(self, args: list[str]) -> CLIResult:
        flags = self._flags(args)
        positional = [a for a in args if not a.startswith("--")
                      and (args.index(a) == 0
                           or args[args.index(a) - 1]
                           is None)]
        positional = [a for a in args if not a.startswith("--")]
        payloads = [p for p in self._indexer.list_all()]
        if positional and positional[0].upper() in Family.__members__:
            family = Family[positional[0].upper()]
            payloads = [p for p in payloads if p.family == family]
        if "tech" in flags:
            payloads = [p for p in payloads
                        if flags["tech"] in (p.target_tech or ())]
        if "waf" in flags:
            payloads = [p for p in payloads
                        if flags["waf"] in (p.target_waf or ())]
        if "context" in flags:
            payloads = [p for p in payloads
                        if flags["context"] in (p.target_context or ())]
        if "endpoint" in flags and endpoints_annotated(payloads):
            payloads = [p for p in payloads
                        if flags["endpoint"] in p.target_endpoints]
        limit = int(flags.get("limit", "20"))
        payloads.sort(key=lambda p: (-p.quality_score, p.payload_id))
        return CLIResult(command="find", ok=True,
                         data={"payloads": payloads[:limit],
                               "count": len(payloads[:limit])})

    def _adapt(self, args: list[str]) -> CLIResult:
        flags = self._flags(args)
        payload_id = args[0] if args else ""
        payload = self._indexer.get_payload(payload_id)
        if payload is None:
            return CLIResult(command="adapt", ok=False,
                             data={"message": f"unknown payload "
                                              f"{payload_id}"})
        context = flags.get("for-context")
        raw = payload.raw
        if context and context in Contextualizer.__dict__.get(
                "_nothing", {}) is None:
            raw = raw
        if context:
            from webpent.forge.contextualizer import ADAPTATION_RULES
            if context in ADAPTATION_RULES:
                raw = self._contextualizer.adapt(payload.raw, context)
        return CLIResult(command="adapt", ok=True,
                         data={"payload_id": payload_id,
                               "adapted_for": {
                                   "tech": flags.get("for-tech", ""),
                                   "waf": flags.get("for-waf", ""),
                                   "context": context or ""},
                               "raw": raw})

    def _mutate(self, args: list[str]) -> CLIResult:
        flags = self._flags(args)
        payload_id = args[0] if args else ""
        payload = self._indexer.get_payload(payload_id)
        if payload is None:
            return CLIResult(command="mutate", ok=False,
                             data={"message": f"unknown payload "
                                              f"{payload_id}"})
        max_variants = int(flags.get("max-variants", "20"))
        variants = mutate(payload, max_variants=max_variants)
        return CLIResult(command="mutate", ok=True,
                         data={"payload_id": payload_id,
                               "variants": variants[:max_variants]})

    def _synthesize(self, args: list[str]) -> CLIResult:
        flags = self._flags(args)
        family = flags.get("family", "sqli")
        if family.upper() != "SQLI" or self._synthesizer is False:
            return CLIResult(
                command="synthesize", ok=False,
                data={"message": f"no grammar synthesis for family "
                                 f"{family}"})
        from webpent.forge import synthesizer
        limit = int(flags.get("limit", "20"))
        result = synthesizer.generate(limit=limit)
        payloads = []
        for item in result["valid_payloads"]:
            if item.family != Family.SQLI:
                item = NormalizedPayload(
                    payload_id=item.payload_id, family=Family.SQLI,
                    subfamily=item.subfamily, raw=item.raw,
                    quality_score=item.quality_score)
            payloads.append(item)
        return CLIResult(command="synthesize", ok=True,
                         data={"family": Family.SQLI,
                               "payloads": payloads,
                               "total_combinations":
                                   result["total_combinations"]})

    def _waf_bypass(self, args: list[str]) -> CLIResult:
        flags = self._flags(args)
        payload_id = args[0] if args else ""
        payload = self._indexer.get_payload(payload_id)
        if payload is None:
            return CLIResult(command="waf-bypass", ok=False,
                             data={"message": f"unknown payload "
                                              f"{payload_id}"})
        target_waf = flags.get("target-waf", flags.get("target_waf",
                                                       ""))
        context = _WAF_CONTEXTS.get(target_waf)
        if context:
            variants = [self._contextualizer.adapt(payload.raw,
                                                   context)]
        else:
            variants = [v.raw for v in mutate(payload,
                                              max_variants=3)]
        return CLIResult(command="waf-bypass", ok=True,
                         data={"payload_id": payload_id,
                               "target_waf": target_waf,
                               "variants": variants})

    def _corpus(self, args: list[str]) -> CLIResult:
        sub = args[0] if args else "status"
        payloads = self._indexer.list_all()
        if sub == "status":
            families = {p.family.value for p in payloads}
            sources = {p.attribution.original_source
                       for p in payloads if p.attribution}
            return CLIResult(command="corpus", ok=True,
                             data={"payloads": len(payloads),
                                   "families": len(families),
                                   "sources": len(sources)})
        if sub == "stats":
            by_family: dict[str, int] = {}
            for p in payloads:
                by_family[p.family.value] = \
                    by_family.get(p.family.value, 0) + 1
            return CLIResult(command="corpus", ok=True,
                             data={"by_family": by_family})
        if sub == "export":
            lines = [json.dumps({
                "payload_id": p.payload_id,
                "family": p.family.value,
                "raw": p.raw,
                "quality_score": p.quality_score,
                "license": (p.attribution.license
                            if p.attribution else "unknown"),
            }, sort_keys=True) for p in payloads]
            return CLIResult(command="corpus", ok=True,
                             data={"jsonl": "\n".join(lines)})
        return CLIResult(command="corpus", ok=False,
                         data={"message": f"unknown corpus "
                                          f"subcommand {sub}"})

    def _attribution(self, args: list[str]) -> CLIResult:
        payload_id = args[0] if args else ""
        payload = self._indexer.get_payload(payload_id)
        if payload is None:
            return CLIResult(command="attribution", ok=False,
                             data={"message": f"unknown payload "
                                              f"{payload_id}"})
        attribution = payload.attribution
        return CLIResult(command="attribution", ok=True,
                         data={
                             "payload_id": payload_id,
                             "source": (attribution.original_source
                                        if attribution else None),
                             "author": (attribution.original_author
                                        if attribution else None),
                             "license": (attribution.license
                                         if attribution
                                         else "unknown"),
                         })

    def _license_report(self, args: list[str]) -> CLIResult:
        entries = []
        for p in self._indexer.list_all():
            attribution = p.attribution
            entries.append({
                "payload_id": p.payload_id,
                "source": (attribution.original_source
                           if attribution else None),
                "license": (attribution.license
                            if attribution else "unknown"),
            })
        return CLIResult(command="license-report", ok=True,
                         data={"entries": entries})
