---
name: threat-intel-triage
description: OSINT workflow for enriching hashes, domains, IPs, malware names, CVEs, and suspicious APIs during reverse engineering.
version: 1.0.0
metadata:
  hermes:
    tags: [reversing, osint, malware, cve, ioc]
    category: re
---

# Threat Intel Triage

## When to Use
Use this when a Kanban card asks for malware family context, hash/domain/IP enrichment, CVE research, API documentation, public sandbox reports, or YARA/signature context.

## Procedure
1. Read the full task with `kanban_show()` if running as a worker.
2. Extract observables: hashes, domains, IPs, URLs, filenames, mutexes, registry keys, API names, strings, and CVE identifiers.
3. Search authoritative or high-signal sources first: vendor docs, NVD/CVE records, Microsoft/Apple/Linux API docs, VirusTotal-style public summaries when available, malware reports from known research teams.
4. Separate facts from inference. If attribution is weak, say so.
5. Produce a concise handoff with:
   - Observables checked
   - Source URLs or source names
   - Malware family or technique hypotheses
   - Confidence level
   - Recommended next static/dynamic checks
6. Complete with `kanban_complete(summary=..., metadata={...})`, or block with the missing credential/source if required.

## Guardrails
- Do not invent VirusTotal results if no API key or source is available.
- Do not claim a sample is malicious solely from one generic detection.
- Do not execute samples. Route execution to `sandbox_runner`.
