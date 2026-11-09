#!/usr/bin/env python3.12
"""WebPent Release Candidate — Independent Benchmark Runner
For use by the independent runtime team.
Receives only: target application, synthetic credentials, scope.
Does NOT receive: ground truth, labels, expected routes.
"""

import argparse
import hashlib
import json
import os
import sys
import time

import httpx

# Ensure src/ is in path
_HERE = os.path.dirname(os.path.abspath(__file__))
_SRC = os.path.join(_HERE, "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)


def _sd(t):
    return hashlib.sha256(t.encode()).hexdigest()


def make_obs(r, p, method="GET"):
    return {
        "status_code": r.status_code,
        "body_length": len(r.text),
        "semantic_digest": _sd(r.text),
        "response_shape": "json" if r.text.strip().startswith("{") else "text",
        "request": {"method": method, "path": p.split("?")[0], "header_names": ["X-Actor"]},
        "headers": {k.lower(): v for k, v in r.headers.items()},
    }


def run_target(base_url: str, routes: list, actors: list, output_dir: str):
    """Run independent evaluation against a target.
    routes: list of paths to probe (discovered independently, not from ground truth)
    actors: list of actor names for X-Actor header
    """
    os.makedirs(output_dir, exist_ok=True)
    findings = []
    bundles = []
    client = httpx.Client(timeout=10)

    for actor in actors:
        for route in routes:
            try:
                r = client.get(f"{base_url}{route}", headers={"X-Actor": actor})
                obs = make_obs(r, route)
                findings.append(
                    {
                        "actor": actor,
                        "route": route,
                        "status": r.status_code,
                        "observation": obs,
                    }
                )
            except Exception as e:
                findings.append({"actor": actor, "route": route, "error": str(e)})

    client.close()

    record = {
        "base_url": base_url,
        "timestamp": time.time(),
        "routes_probed": len(routes),
        "actors_used": len(actors),
        "findings": findings,
        "governance_note": "No ground truth, labels, or benchmark metadata were provided to this runner.",
    }

    with open(os.path.join(output_dir, "raw_observations.json"), "w") as f:
        json.dump(record, f, indent=2, default=str)

    return record


def main():
    parser = argparse.ArgumentParser(description="WebPent Independent Benchmark Runner")
    parser.add_argument("--target", required=True, help="Target base URL, e.g. http://127.0.0.1:9200")
    parser.add_argument("--routes", required=True, help="JSON file with list of routes to probe")
    parser.add_argument("--actors", required=True, help="JSON file with list of actor names")
    parser.add_argument("--output", required=True, help="Output directory for evidence")
    args = parser.parse_args()

    with open(args.routes) as f:
        routes = json.load(f)
    with open(args.actors) as f:
        actors = json.load(f)

    print(f"Target: {args.target}")
    print(f"Routes: {len(routes)}")
    print(f"Actors: {len(actors)}")
    print(f"Output: {args.output}")
    print("Governance: vip_qualified=false, P10=CLOSED")

    record = run_target(args.target, routes, actors, args.output)
    print(f"\n✅ Complete: {len(record['findings'])} observations recorded")
    print(f"   Saved to: {args.output}/raw_observations.json")


if __name__ == "__main__":
    main()
