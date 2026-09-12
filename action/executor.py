"""
Action Execution Layer (Deterministic)
Executes approved actions with rollback capability.
Every action produces a cryptographic proof.
"""

import os
import json
import time
import hashlib
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Optional, Dict
from enum import Enum


class ActionStatus(Enum):
    PENDING = "pending"
    EXECUTING = "executing"
    COMPLETED = "completed"
    ROLLED_BACK = "rolled_back"
    BLOCKED = "blocked"
    FAILED = "failed"


@dataclass
class ExecutionResult:
    """Result of executing an action"""
    action_id: str
    status: ActionStatus
    action_type: str
    description: str
    timestamp: str
    proof_hash: str
    rollback_available: bool
    rollback_deadline: str  # ISO timestamp
    details: str
    latency_ms: int


class ActionExecutor:
    """
    Deterministic action executor with rollback capability.
    Every execution produces a cryptographic proof.
    Actions can be rolled back within the configured window.
    """
    
    def __init__(self, rollback_window_seconds: int = 30):
        self.rollback_window = rollback_window_seconds
        self.executed_actions: Dict[str, dict] = {}
        self.proof_dir = os.path.join(os.path.dirname(__file__), '..', 'proofs')
        os.makedirs(self.proof_dir, exist_ok=True)
    
    def execute(self, action: dict, filter_verdict: str, grounding_result: dict) -> ExecutionResult:
        """
        Execute an approved action.
        
        Args:
            action: Action dictionary with type, description, amount, etc.
            filter_verdict: The injection filter verdict ("approved", "blocked", etc.)
            grounding_result: The grounding check result
            
        Returns:
            ExecutionResult with status and proof
        """
        start = time.perf_counter()
        
        # Generate action ID
        action_id = self._generate_action_id(action)
        timestamp = datetime.utcnow().isoformat()
        
        # BLOCK if filter rejected
        if filter_verdict != "approved":
            result = ExecutionResult(
                action_id=action_id,
                status=ActionStatus.BLOCKED,
                action_type=action.get("type", "unknown"),
                description=action.get("description", ""),
                timestamp=timestamp,
                proof_hash=self._compute_proof(action_id, "blocked", timestamp),
                rollback_available=False,
                rollback_deadline="",
                details=f"Blocked by guard layer: {filter_verdict}",
                latency_ms=int((time.perf_counter() - start) * 1000)
            )
            self._save_proof(result, action)
            return result
        
        # BLOCK if grounding failed
        if not grounding_result.get("is_grounded", True):
            result = ExecutionResult(
                action_id=action_id,
                status=ActionStatus.BLOCKED,
                action_type=action.get("type", "unknown"),
                description=action.get("description", ""),
                timestamp=timestamp,
                proof_hash=self._compute_proof(action_id, "blocked_ungrounded", timestamp),
                rollback_available=False,
                rollback_deadline="",
                details=f"Blocked: ungrounded claims. {grounding_result.get('details', '')}",
                latency_ms=int((time.perf_counter() - start) * 1000)
            )
            self._save_proof(result, action)
            return result
        
        # Execute the action (simulated - in production, this would call real APIs)
        try:
            # Simulate execution
            time.sleep(0.01)  # Minimal execution time
            
            rollback_deadline_ts = time.time() + self.rollback_window
            rollback_deadline = datetime.utcfromtimestamp(rollback_deadline_ts).isoformat()
            
            result = ExecutionResult(
                action_id=action_id,
                status=ActionStatus.COMPLETED,
                action_type=action.get("type", "unknown"),
                description=action.get("description", ""),
                timestamp=timestamp,
                proof_hash=self._compute_proof(action_id, "completed", timestamp),
                rollback_available=True,
                rollback_deadline=rollback_deadline,
                details=f"Action executed successfully. Rollback available until {rollback_deadline}",
                latency_ms=int((time.perf_counter() - start) * 1000)
            )
            
        except Exception as e:
            result = ExecutionResult(
                action_id=action_id,
                status=ActionStatus.FAILED,
                action_type=action.get("type", "unknown"),
                description=action.get("description", ""),
                timestamp=timestamp,
                proof_hash=self._compute_proof(action_id, "failed", timestamp),
                rollback_available=False,
                rollback_deadline="",
                details=f"Execution failed: {str(e)}",
                latency_ms=int((time.perf_counter() - start) * 1000)
            )
        
        # Store for rollback tracking
        self.executed_actions[action_id] = {
            "result": result,
            "action": action,
            "executed_at": time.time()
        }
        
        # Save proof
        self._save_proof(result, action)
        
        return result
    
    def rollback(self, action_id: str) -> Optional[ExecutionResult]:
        """
        Rollback a completed action within the rollback window.
        
        Args:
            action_id: The action to rollback
            
        Returns:
            ExecutionResult with rollback status, or None if not found/expired
        """
        if action_id not in self.executed_actions:
            return None
        
        stored = self.executed_actions[action_id]
        result = stored["result"]
        
        # Check if rollback window has expired
        elapsed = time.time() - stored["executed_at"]
        if elapsed > self.rollback_window:
            return None
        
        # Check if action is rollback-eligible
        if result.status != ActionStatus.COMPLETED:
            return None
        
        # Perform rollback (simulated)
        timestamp = datetime.utcnow().isoformat()
        rollback_result = ExecutionResult(
            action_id=f"{action_id}_rollback",
            status=ActionStatus.ROLLED_BACK,
            action_type=result.action_type,
            description=f"Rollback of: {result.description}",
            timestamp=timestamp,
            proof_hash=self._compute_proof(action_id, "rolled_back", timestamp),
            rollback_available=False,
            rollback_deadline="",
            details=f"Action {action_id} rolled back after {elapsed:.1f}s",
            latency_ms=0
        )
        
        # Update original action status
        result.status = ActionStatus.ROLLED_BACK
        
        # Save rollback proof
        self._save_proof(rollback_result, stored["action"])
        
        return rollback_result
    
    def _generate_action_id(self, action: dict) -> str:
        """Generate unique action ID"""
        data = json.dumps(action, sort_keys=True, default=str)
        return hashlib.sha256(data.encode()).hexdigest()[:16]
    
    def _compute_proof(self, action_id: str, status: str, timestamp: str) -> str:
        """Compute cryptographic proof hash"""
        proof_data = f"{action_id}:{status}:{timestamp}"
        return hashlib.sha256(proof_data.encode()).hexdigest()
    
    def _save_proof(self, result: ExecutionResult, action: dict):
        """Save execution proof to disk"""
        proof_data = {
            "action_id": result.action_id,
            "status": result.status.value,
            "action_type": result.action_type,
            "description": result.description,
            "timestamp": result.timestamp,
            "proof_hash": result.proof_hash,
            "rollback_available": result.rollback_available,
            "rollback_deadline": result.rollback_deadline,
            "details": result.details,
            "original_action": action
        }
        
        proof_file = os.path.join(self.proof_dir, f"{result.proof_hash[:12]}.json")
        with open(proof_file, 'w') as f:
            json.dump(proof_data, f, indent=2, default=str)
