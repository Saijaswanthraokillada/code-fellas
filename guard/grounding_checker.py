"""
Grounding Checker (Deterministic)
Verifies that AI-generated claims can be traced back to the source document.
Every numeric figure in AI output must have a source in the original text.
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional


@dataclass
class GroundingResult:
    """Result from grounding verification"""
    is_grounded: bool  # All claims traceable to source
    grounded_claims: List[str]  # Claims that ARE grounded
    ungrounded_claims: List[str]  # Claims that are NOT grounded
    hallucinated_figures: List[Dict]  # Numbers in AI output not in source
    confidence: float  # 0.0 to 1.0
    latency_ms: int
    details: str


class GroundingChecker:
    """
    Deterministic grounding checker.
    Verifies AI output against source document.
    Zero hallucination tolerance for numeric figures.
    """
    
    def check(self, source_text: str, ai_output: dict, original_text: str = "") -> GroundingResult:
        """
        Check if AI output is grounded in the source document.
        
        Args:
            source_text: The original document text
            ai_output: The AI's structured output (dict with entities, actions, etc.)
            original_text: Raw original text for additional verification
            
        Returns:
            GroundingResult
        """
        import time
        start = time.perf_counter()
        
        grounded_claims = []
        ungrounded_claims = []
        hallucinated_figures = []
        
        # Extract all numbers from source document
        source_numbers = set(re.findall(r'[\d,]+\.?\d*', source_text))
        source_numbers_clean = set()
        for n in source_numbers:
            clean = n.replace(',', '')
            try:
                source_numbers_clean.add(float(clean))
            except ValueError:
                pass
        
        # Extract all numbers from AI output
        ai_text = str(ai_output)
        ai_numbers = re.findall(r'[\d,]+\.?\d*', ai_text)
        
        # Check each number in AI output against source
        for num_str in ai_numbers:
            clean = num_str.replace(',', '')
            try:
                num_val = float(clean)
                if num_val in source_numbers_clean or num_val == 0:
                    grounded_claims.append(f"Number {num_str} found in source")
                else:
                    hallucinated_figures.append({
                        "figure": num_str,
                        "location": "ai_output",
                        "in_source": False
                    })
                    ungrounded_claims.append(f"Number {num_str} NOT found in source document")
            except ValueError:
                pass
        
        # Check entities against source
        if isinstance(ai_output, dict):
            entities = ai_output.get("entities", {})
            for key, value in entities.items():
                if value and isinstance(value, str) and len(value) > 2:
                    if value.lower() in source_text.lower():
                        grounded_claims.append(f"Entity '{key}: {value}' found in source")
                    else:
                        ungrounded_claims.append(f"Entity '{key}: {value}' NOT found in source")
        
        # Check action descriptions
        if isinstance(ai_output, dict):
            actions = ai_output.get("actions", [])
            for action in actions:
                desc = action.get("description", "")
                if desc:
                    # Check if action description references source content
                    words = desc.lower().split()
                    source_lower = source_text.lower()
                    matches = sum(1 for w in words if len(w) > 3 and w in source_lower)
                    if matches >= 2:
                        grounded_claims.append(f"Action '{desc[:50]}...' grounded in source")
                    else:
                        ungrounded_claims.append(f"Action '{desc[:50]}...' not fully grounded")
        
        # Calculate grounding score
        total_claims = len(grounded_claims) + len(ungrounded_claims)
        if total_claims > 0:
            grounding_score = len(grounded_claims) / total_claims
        else:
            grounding_score = 1.0  # No claims to verify = grounded
        
        # Hallucinated figures are critical
        hallucination_penalty = len(hallucinated_figures) * 0.3
        confidence = max(0.0, grounding_score - hallucination_penalty)
        
        # Grounded = no hallucinated figures AND high grounding score
        is_grounded = len(hallucinated_figures) == 0 and grounding_score >= 0.7
        
        latency_ms = int((time.perf_counter() - start) * 1000)
        
        details = f"Grounded: {len(grounded_claims)}/{total_claims} claims. Hallucinated: {len(hallucinated_figures)} figures."
        
        return GroundingResult(
            is_grounded=is_grounded,
            grounded_claims=grounded_claims,
            ungrounded_claims=ungrounded_claims,
            hallucinated_figures=hallucinated_figures,
            confidence=confidence,
            latency_ms=latency_ms,
            details=details
        )
