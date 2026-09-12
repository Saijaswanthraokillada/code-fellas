# 🛡️ GuardFi — Injection-Resistant Financial Assistant

**FS-2605 | FinTech Sprint '26 | VIT AP**

AI financial assistant that reads invoices and executes payments, with a deterministic security layer that blocks prompt injection attacks.

---

## 3-Command Run

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Set API key
cp .env.example .env
# Edit .env and add your GEMINI_API_KEY

# 3. Start server
python main.py
```

Open **http://localhost:8080** in your browser.

---

## Architecture

```
Document → Ingestion → Gemini AI → Injection Filter → Grounding Check → Execute → Proof
                                        ↑ BLOCKED                    ↑ BLOCKED
                                   (deterministic)              (deterministic)
```

### Three Layers

| Layer | Type | Purpose |
|-------|------|---------|
| **Ingestion** | Deterministic | Parse PDF/email/text documents |
| **AI Analysis** | Gemini 2.0 Flash | Classify intent, extract entities, plan actions |
| **Guard Layer** | Deterministic | Block injection attacks, verify grounding |

---

## Key Features

- **22 injection attack patterns** detected deterministically
- **Zero hallucination tolerance** — every figure traced to source
- **30-second rollback window** for all executed actions
- **Cryptographic proof** generated for every action
- **/healthz** and **/metrics** endpoints for monitoring

---

## Project Structure

```
FS2605/
├── main.py                 # FastAPI server
├── ingestion/
│   └── parser.py           # Document parsing (PDF/email/text)
├── ai/
│   └── gemini_engine.py    # Gemini 2.0 Flash analysis
├── guard/
│   ├── injection_filter.py # Deterministic injection detection
│   └── grounding_checker.py # Fact verification
├── action/
│   └── executor.py         # Action execution + rollback
├── proofs/                  # Generated proof files
├── bench/
│   └── test_injections.py  # 25 attack test cases
├── static/
│   └── index.html          # Frontend UI
├── AI_LEDGER.md            # AI usage documentation
├── requirements.txt
└── .env
```

---

## Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| p95 latency | < 4s | Automated benchmark |
| Hallucination rate | 0% | Cross-check every figure |
| Injection detection | > 95% | 25 attack test cases |
| Cost per 1000 tasks | < Rs.50 | Gemini API pricing |

---

## Team

**Code Fellas** — Vignan's Lara Institute of Technology
