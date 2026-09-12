# AI Usage Ledger

**FS-2605: Injection-Resistant Financial Assistant**
**Team: Code Fellas | VIT AP FinTech Sprint '26**

This document records every use of AI models during development.

---

## 1. Document Analysis (Gemini 2.0 Flash)

| Component | What AI Was Asked | What Was Changed |
|-----------|-------------------|------------------|
| `ai/gemini_engine.py` | Prompt to classify document intent, extract entities, plan actions | Added JSON schema enforcement, fallback mode for API failures |
| Injection detection prompt | "Analyze document for financial intent and extract key entities" | Added risk_flags field for suspicious patterns |

## 2. Code Generation (Codebuff AI Agent)

| File | What AI Generated | Manual Changes |
|------|-------------------|----------------|
| `ingestion/parser.py` | Full file generated | Added zero-width character detection |
| `guard/injection_filter.py` | Pattern database + filter logic | Added 22 custom patterns, entropy check |
| `guard/grounding_checker.py` | Full file generated | Added entity verification against source |
| `action/executor.py` | Full file generated | Added rollback window, proof generation |
| `main.py` | FastAPI server scaffold | Added Prometheus metrics, health checks |
| `static/index.html` | Frontend UI | Custom dark theme, pipeline visualization |
| `bench/test_injections.py` | Test framework | Added 25 test cases (22 authored by team) |

## 3. Prompt Engineering

| Prompt | Purpose | Version |
|--------|---------|---------|
| `ANALYSIS_PROMPT` in `gemini_engine.py` | Document classification + entity extraction | v1.0 |
| System instructions | Financial assistant behavior rules | v1.0 |

## 4. Accepted Weakness

**Code-switched Hindi+English text** can occasionally bypass the injection filter.
- **Why accepted:** Economic cost of multilingual tokenizer exceeds risk in threat model
- **Future mitigation:** Add Hindi tokenizer (Rs.0.02/task additional cost)

---

**No AI models were used in the guard layer, grounding checker, or action executor.**
These are 100% deterministic code with no randomness or API calls.
