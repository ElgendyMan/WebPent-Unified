from __future__ import annotations

import json
import os
from pathlib import Path

from webpent.memory.vectorstore import get_vector_store_manager
from webpent.shared.knowledge_retrieval import retrieve_knowledge_context


def main() -> int:
    manager = get_vector_store_manager()
    queries = {
        "methodology": "OWASP WSTG NIST penetration testing methodology",
        "repository": "security repository payload corpus templates",
        "report": "finding report evidence causal signal negative control",
        "writeup": "SQL injection XSS SSRF access control writeup patterns",
        "scenario": "authorized lab BAC IDOR GraphQL scenario",
    }
    records = []
    for doc_type, query in queries.items():
        hits = manager.search_knowledge(query, k=2, doc_type=doc_type)
        context = retrieve_knowledge_context(
            query,
            doc_types=(doc_type,),
            per_type_k=2,
            max_chars=1800,
        )
        records.append(
            {
                "doc_type": doc_type,
                "direct_hits": len(hits),
                "helper_context_chars": len(context),
                "helper_contains_type_marker": f"[RAG type={doc_type}" in context,
            }
        )
    output = Path(os.environ.get("RAG_VERIFY_OUTPUT", "artifacts/rag_knowledge_pack_verify.json"))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(records, indent=2), encoding="utf-8")
    print(json.dumps(records, indent=2))
    return (
        0
        if all(item["direct_hits"] > 0 and item["helper_contains_type_marker"] for item in records)
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(main())
