"""
Deterministic Injection Filter (Guard Layer)
Uses pattern matching and entropy analysis to detect prompt injection attacks.
100% deterministic - same input always produces same output.
"""

import re
import math
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class FilterResult:
    """Result from injection filter"""
    verdict: str  # "approved", "blocked", "suspicious"
    confidence: float  # 0.0 to 1.0
    reasons: List[str]  # list of reasons for the verdict
    patterns_matched: List[str]  # which patterns were triggered
    risk_score: float  # 0.0 (safe) to 1.0 (dangerous)
    latency_ms: int  # processing time
    checks_performed: int  # number of checks run


# ============ PATTERN DATABASE ============
# Each pattern has: name, regex, severity, description

INJECTION_PATTERNS = [
    # === OVERRIDE / RESET ATTACKS ===
    {
        "name": "ignore_previous",
        "pattern": r'(?i)(ignore|disregard|forget|override|negate|cancel|reset)\s+(all\s+)?(previous|prior|above|earlier|preceding|former|last|above\s+mentioned)',
        "severity": "critical",
        "description": "Attempts to override previous instructions"
    },
    {
        "name": "ignore_all_instructions",
        "pattern": r'(?i)(ignore|disregard|forget)\s+(all\s+)?instructions',
        "severity": "critical",
        "description": "Attempts to override all system instructions"
    },
    {
        "name": "new_instructions",
        "pattern": r'(?i)(new|updated|revised|replaced?)\s+instructions?\s*[:=]',
        "severity": "critical",
        "description": "Attempts to inject new instructions"
    },
    {
        "name": "system_prompt_inject",
        "pattern": r'(?i)(system\s*prompt|system\s*message|system\s*instruction|you\s*are\s*now|act\s*as|pretend\s*to\s*be|roleplay\s*as)',
        "severity": "critical",
        "description": "Attempts to override system prompt"
    },
    
    # === FINANCIAL ACTION ATTACKS ===
    {
        "name": "transfer_instruction",
        "pattern": r'(?i)(transfer|send|pay|remit|wire|deposit|move)\s+(Rs\.?|₹|INR|amount|funds?|money|payment)\s*(of\s*)?(Rs\.?|₹|INR)?\s*[\d,]+\.?\d*',
        "severity": "critical",
        "description": "Hidden financial transfer instruction"
    },
    {
        "name": "approve_instruction",
        "pattern": r'(?i)(auto|automatically|immediately|without\s+review|no\s+questions)\s+(approve|authori[sz]e|confirm|process|execute)',
        "severity": "critical",
        "description": "Attempts to bypass approval process"
    },
    {
        "name": "account_details",
        "pattern": r'(?i)(account\s*(no|number|#|num)?\s*[:=]?\s*\d{8,12}|IFSC\s*[:=]?\s*[A-Z]{4}\d{7}|UPI\s*[:=]?\s*\S+@\S+)',
        "severity": "high",
        "description": "Contains account/payment details in suspicious context"
    },
    
    # === PROMPT ESCAPE ATTACKS ===
    {
        "name": "role_override",
        "pattern": r'(?i)(you\s*are\s*(now|a|an|the)\s+(?:assistant|bot|AI|system|admin|root|developer|god))',
        "severity": "critical",
        "description": "Attempts to change AI role/identity"
    },
    {
        "name": "output_manipulation",
        "pattern": r'(?i)(respond\s*with|output\s*:|return\s*:|print|display|show|reveal)\s*["\']?(ignore|transfer|pay|approve|execute)',
        "severity": "high",
        "description": "Attempts to manipulate output format"
    },
    {
        "name": "delimiter_escape",
        "pattern": r'(?i)(---+\s*(end|new|system|admin|root)\s+---|===+\s*(prompt|instruction|command)\s*===+)',
        "severity": "high",
        "description": "Attempts to escape delimiter boundaries"
    },
    
    # === SOCIAL ENGINEERING IN TEXT ===
    {
        "name": "urgency_pressure",
        "pattern": r'(?i)(urgent|emergency|immediate|asap|right\s+now|within\s+\d+\s*(min|hour|sec)|time\s+sensitive|deadline\s+(today|now|passed))',
        "severity": "medium",
        "description": "Uses urgency to pressure quick action"
    },
    {
        "name": "authority_claim",
        "pattern": r'(?i)(i\s+am\s+(the\s+)?(CEO|CFO|director|manager|admin|owner|boss)|this\s+is\s+(a\s+)?(directive|order|command|mandate))',
        "severity": "medium",
        "description": "Claims false authority"
    },
    {
        "name": "confidentiality_bypass",
        "pattern": r'(?i)(do\s+not\s+(tell|show|reveal|share|disclose|log|record)|keep\s+(this\s+)?(secret|hidden|confidential)|off[\s-]?the[\s-]?record|process\s+.*quietly|without\s+(logging|audit|review))',
        "severity": "critical",
        "description": "Attempts to hide the action from audit"
    },
    
    # === TECHNICAL INJECTION ===
    {
        "name": "code_execution",
        "pattern": r'(?i)(exec|eval|system|subprocess|os\.system|__import__|import\s+os|require\s*\(|fetch\s*\(|curl\s+|wget\s+)',
        "severity": "critical",
        "description": "Attempts code execution"
    },
    {
        "name": "api_key_harvest",
        "pattern": r'(?i)(api[_\s]*key|secret[_\s]*key|access[_\s]*token|password|credential|auth[_\s]*token)\s*[:=]\s*\S+',
        "severity": "high",
        "description": "Attempts to harvest credentials"
    },
    {
        "name": "sql_injection",
        "pattern": r'(?i)(drop\s+table|delete\s+from|insert\s+into|update\s+\w+\s+set|union\s+select|;\s*--)',
        "severity": "critical",
        "description": "SQL injection attempt"
    },
    
    # === ZERO-WIDTH / INVISIBLE TEXT ===
    {
        "name": "zero_width_chars",
        "pattern": r'[\u200b-\u200f\u2028-\u202f\u2060-\u2064\ufeff]{3,}',
        "severity": "high",
        "description": "Contains zero-width/invisible characters"
    },
    {
        "name": "unicode_confusion",
        "pattern": r'[\u00ad\u034f\u061c\u17b4\u17b5\u180e\ufeff]{2,}',
        "severity": "medium",
        "description": "Contains Unicode confusable characters"
    },
    
    # === DATA EXFILTRATION ===
    {
        "name": "exfiltration_url",
        "pattern": r'(?i)(https?://\S+\.(tk|ml|ga|cf|gq|bit\.ly|tinyurl|t\.co)/\S+)',
        "severity": "high",
        "description": "Contains suspicious shortened/short-domain URLs"
    },
    {
        "name": "data_leak_request",
        "pattern": r'(?i)(send\s+(all\s+)?(data|info|details|records|passwords|keys|tokens)\s+to|exfiltrate|dump\s+(database|records|all))',
        "severity": "critical",
        "description": "Attempts data exfiltration"
    },
]


class InjectionFilter:
    """
    Deterministic injection filter.
    Same input ALWAYS produces same output.
    No randomness, no ML, no API calls.
    """
    
    def __init__(self, strict_mode: bool = True):
        self.strict_mode = strict_mode
        self.patterns = INJECTION_PATTERNS
        self._compiled_patterns = []
        for p in self.patterns:
            try:
                compiled = re.compile(p["pattern"])
                self._compiled_patterns.append((p, compiled))
            except re.error:
                pass  # Skip invalid patterns
    
    def check(self, text: str, source: str = "document") -> FilterResult:
        """
        Check text for injection attacks.
        
        Args:
            text: Text to analyze
            source: Source identifier for logging
            
        Returns:
            FilterResult with verdict and reasons
        """
        import time
        start = time.perf_counter()
        
        reasons = []
        patterns_matched = []
        risk_score = 0.0
        checks_performed = 0
        
        # Run all pattern checks
        for pattern_info, compiled in self._compiled_patterns:
            checks_performed += 1
            matches = compiled.findall(text)
            if matches:
                patterns_matched.append(pattern_info["name"])
                reasons.append(f"{pattern_info['description']} [{pattern_info['severity']}]")
                
                # Weight by severity
                if pattern_info["severity"] == "critical":
                    risk_score += 0.4
                elif pattern_info["severity"] == "high":
                    risk_score += 0.25
                elif pattern_info["severity"] == "medium":
                    risk_score += 0.15
        
        # Entropy check - high entropy in short segments may indicate obfuscation
        checks_performed += 1
        segments = re.split(r'\s+', text)
        for seg in segments:
            if len(seg) > 20:
                entropy = self._calculate_entropy(seg)
                if entropy > 4.5:  # High entropy threshold
                    risk_score += 0.1
                    if "high_entropy_segment" not in patterns_matched:
                        patterns_matched.append("high_entropy_segment")
                        reasons.append("High entropy text segment detected (possible obfuscation)")
        
        # Length anomaly check
        checks_performed += 1
        lines = text.split('\n')
        for line in lines:
            if len(line) > 500:
                risk_score += 0.05
                if "long_line" not in patterns_matched:
                    patterns_matched.append("long_line")
                    reasons.append("Unusually long line detected")
        
        # Cap risk score at 1.0
        risk_score = min(risk_score, 1.0)
        
        # Determine verdict
        if risk_score >= 0.6:
            verdict = "blocked"
        elif risk_score >= 0.3:
            verdict = "suspicious"
        else:
            verdict = "approved"
        
        # Strict mode: block anything suspicious too
        if self.strict_mode and verdict == "suspicious":
            verdict = "blocked"
            reasons.append("Strict mode: suspicious content blocked")
        
        latency_ms = int((time.perf_counter() - start) * 1000)
        
        return FilterResult(
            verdict=verdict,
            confidence=1.0 - risk_score,  # Higher risk = lower confidence in safety
            reasons=reasons,
            patterns_matched=patterns_matched,
            risk_score=risk_score,
            latency_ms=latency_ms,
            checks_performed=checks_performed
        )
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text:
            return 0.0
        freq = {}
        for c in text:
            freq[c] = freq.get(c, 0) + 1
        length = len(text)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy
