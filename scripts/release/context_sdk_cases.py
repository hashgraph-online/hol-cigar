"""Deterministic authored and seeded cases shared by installed SDK qualifiers."""

import json
from pathlib import Path
import random


def build_cases(root: Path) -> list[dict]:
    cases = []
    authored = json.loads(
        (root / "crates/cigar-context/fixtures/quality.json").read_bytes()
    )
    for case in authored:
        for mode in ["full", "query_windows"]:
            for budget in [32, 512, 2048]:
                cases.append(
                    {
                        "domain": f"rc-{case['id']}",
                        "documents": [
                            dict(zip(["id", "source", "text"], doc))
                            for doc in case["documents"]
                        ],
                        "edges": case["edges"],
                        "request": {
                            "query": case["query"],
                            "max_tokens": budget,
                            "excerpt_mode": mode,
                            "evidence_per_term": case.get("evidence_per_term", 1),
                        },
                    }
                )
    rng = random.Random(10_000)
    for index in range(100):
        documents = [
            {
                "id": str(i),
                "source": f"src/{i}.rs",
                "text": "\n".join(
                    rng.choices(
                        [
                            "alpha beta",
                            "fn authorize_user() {}",
                            "café 🦀 索引",
                            "tenant policy",
                            "retry identity",
                        ],
                        k=4,
                    )
                ),
            }
            for i in range(10)
        ]
        request = {
            "query": rng.choice(
                ["alpha", "authorizeUser", "tenant retry", "索引", "missing"]
            ),
            "max_tokens": rng.choice([1, 128, 512]),
            "excerpt_mode": rng.choice(["full", "query_windows"]),
        }
        if index % 3 == 0:
            request["required"] = ["0"]
        if index % 5 == 0:
            request["allowed"] = ["0", "2", "3"]
        cases.append(
            {
                "domain": f"seed-{index}",
                "documents": documents,
                "edges": [
                    ["0", "1", "requires"],
                    ["2", "3", "contradicts"],
                    ["4", "5", "related"],
                ],
                "request": request,
            }
        )
    return cases
