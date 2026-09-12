"""
Gemini AI Analysis Engine
Uses Google Gemini 2.0 Flash to analyze documents.
Classifies intent, extracts entities, and generates action plans.
"""

import os
import json
import time
from dataclasses import dataclass, field
from typing import Optional
from dotenv import load_dotenv

load_dotenv()


@dataclass
class AnalysisResult:
    """Structured output from Gemini analysis"""
    intent: str  # invoice_payment, budget_report, vendor_approval, etc.
    confidence: float  # 0.0 to 1.0
    entities: dict  # extracted entities (amount, vendor, date, etc.)
    actions: list  # list of proposed actions
    raw_response: str  # raw Gemini response
    latency_ms: int  # analysis time in milliseconds
    model_used: str
    error: Optional[str] = None


ANALYSIS_PROMPT = """You are a financial document analyzer. Analyze the following document and return a JSON object with:
{
  "intent": "<one of: invoice_payment, budget_report, vendor_approval, expense_claim, tax_filing, general_query>",
  "confidence": <0.0 to 1.0>,
  "entities": {
    "amount": "<monetary amount if present>",
    "vendor": "<vendor/payee name if present>",
    "date": "<date if present>",
    "invoice_number": "<invoice number if present>",
    "description": "<brief description of the document>"
  },
  "actions": [
    {
      "type": "<action type>",
      "description": "<what the action does>",
      "requires_approval": <true/false>,
      "amount": "<if monetary action>"
    }
  ],
  "risk_flags": ["<any suspicious patterns detected>"]
}

DOCUMENT:
{document_text}

Return ONLY valid JSON, no markdown, no explanation."""


class GeminiAnalyzer:
    """Gemini 2.0 Flash-based document analyzer"""
    
    def __init__(self):
        self.api_key = os.getenv("GEMINI_API_KEY", "")
        self.model_name = "gemini-2.0-flash"
        self.client = None
        
        if self.api_key:
            try:
                import google.generativeai as genai
                genai.configure(api_key=self.api_key)
                self.client = genai.GenerativeModel(self.model_name)
            except Exception as e:
                print(f"[WARN] Gemini client init failed: {e}")
    
    def analyze(self, document_text: str, document_metadata: dict = None) -> AnalysisResult:
        """
        Analyze a document using Gemini AI.
        
        Args:
            document_text: The text content of the document
            document_metadata: Optional metadata from ingestion layer
            
        Returns:
            AnalysisResult with structured output
        """
        start_time = time.perf_counter()
        
        if not self.client:
            return self._fallback_analysis(document_text, start_time)
        
        try:
            prompt = ANALYSIS_PROMPT.format(document_text=document_text[:8000])
            response = self.client.generate_content(prompt)
            latency_ms = int((time.perf_counter() - start_time) * 1000)
            
            # Parse JSON response
            raw_text = response.text.strip()
            # Remove markdown code blocks if present
            if raw_text.startswith("```"):
                raw_text = raw_text.split("\n", 1)[1]
                if raw_text.endswith("```"):
                    raw_text = raw_text[:-3]
            
            parsed = json.loads(raw_text)
            
            return AnalysisResult(
                intent=parsed.get("intent", "general_query"),
                confidence=min(max(parsed.get("confidence", 0.5), 0.0), 1.0),
                entities=parsed.get("entities", {}),
                actions=parsed.get("actions", []),
                raw_response=raw_text,
                latency_ms=latency_ms,
                model_used=self.model_name,
            )
            
        except json.JSONDecodeError as e:
            latency_ms = int((time.perf_counter() - start_time) * 1000)
            return AnalysisResult(
                intent="general_query",
                confidence=0.3,
                entities={},
                actions=[],
                raw_response=str(e),
                latency_ms=latency_ms,
                model_used=self.model_name,
                error=f"JSON parse error: {str(e)}"
            )
        except Exception as e:
            latency_ms = int((time.perf_counter() - start_time) * 1000)
            return AnalysisResult(
                intent="general_query",
                confidence=0.0,
                entities={},
                actions=[],
                raw_response="",
                latency_ms=latency_ms,
                model_used=self.model_name,
                error=f"API error: {str(e)}"
            )
    
    def _fallback_analysis(self, document_text: str, start_time: float) -> AnalysisResult:
        """Fallback analysis when Gemini is unavailable (deterministic)"""
        latency_ms = int((time.perf_counter() - start_time) * 1000)
        
        # Simple keyword-based fallback
        text_lower = document_text.lower()
        
        if any(w in text_lower for w in ["invoice", "bill", "payment", "₹", "rs."]):
            intent = "invoice_payment"
            confidence = 0.4
        elif any(w in text_lower for w in ["budget", "forecast", "quarterly"]):
            intent = "budget_report"
            confidence = 0.4
        elif any(w in text_lower for w in ["approve", "vendor", "contract"]):
            intent = "vendor_approval"
            confidence = 0.4
        else:
            intent = "general_query"
            confidence = 0.3
        
        return AnalysisResult(
            intent=intent,
            confidence=confidence,
            entities={"source": "fallback_analyzer"},
            actions=[{
                "type": "flag_for_review",
                "description": "Fallback mode - requires human review",
                "requires_approval": True,
                "amount": "unknown"
            }],
            raw_response="fallback_mode",
            latency_ms=latency_ms,
            model_used="fallback_keyword",
            error="Gemini unavailable - using deterministic fallback"
        )
