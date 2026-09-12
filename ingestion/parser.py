"""
Document Ingestion Layer
Handles PDF, email, and plain text document parsing.
Extracts text content and metadata for downstream analysis.
"""

import os
import re
import hashlib
from datetime import datetime
from typing import Optional
from dataclasses import dataclass, field


@dataclass
class DocumentContent:
    """Parsed document with metadata"""
    raw_text: str
    source_type: str  # pdf, email, text
    filename: str
    checksum: str
    byte_length: int
    parsed_at: str
    metadata: dict = field(default_factory=dict)
    visible_text: str = ""
    hidden_segments: list = field(default_factory=list)


def extract_text_from_pdf(file_path: str) -> str:
    """Extract text from PDF using PyPDF2"""
    try:
        from PyPDF2 import PdfReader
        reader = PdfReader(file_path)
        text_parts = []
        for page in reader.pages:
            page_text = page.extract_text()
            if page_text:
                text_parts.append(page_text)
        return "\n".join(text_parts)
    except Exception as e:
        return f"[PDF PARSE ERROR: {str(e)}]"


def extract_text_from_email(file_path: str) -> str:
    """Extract text from email file (.eml or .txt)"""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
        # Simple email parsing - get body after headers
        if '\n\n' in content:
            return content.split('\n\n', 1)[1]
        return content
    except Exception as e:
        return f"[EMAIL PARSE ERROR: {str(e)}]"


def extract_metadata(text: str, filename: str) -> dict:
    """Extract basic metadata from text content"""
    metadata = {
        "word_count": len(text.split()),
        "char_count": len(text),
        "line_count": text.count('\n') + 1,
        "has_indian_currency": bool(re.search(r'₹|Rs\.|INR|Rs\s', text)),
        "has_dates": bool(re.search(r'\d{1,2}[/-]\d{1,2}[/-]\d{2,4}', text)),
        "has_amounts": bool(re.search(r'₹\s*[\d,]+\.?\d*|Rs\.?\s*[\d,]+\.?\d*', text)),
    }
    # Detect potential hidden text patterns (zero-width chars, etc.)
    metadata["has_zero_width_chars"] = bool(re.search(r'[\u200b-\u200f\u2028-\u202f\u2060-\u2064\ufeff]', text))
    metadata["has_suspicious_encoding"] = bool(re.search(r'[\u00ad\u034f\u061c\u17b4\u17b5\u180e]', text))
    return metadata


def detect_hidden_segments(text: str) -> list:
    """Detect potential hidden/injected text segments"""
    segments = []
    
    # Zero-width characters
    zw_pattern = re.compile(r'([\u200b-\u200f\u2028-\u202f\u2060-\u2064\ufeff]+[^\n]{5,})')
    for match in zw_pattern.finditer(text):
        segments.append({
            "type": "zero_width_injection",
            "position": match.start(),
            "text": match.group()[:100],
            "severity": "high"
        })
    
    # Suspicious instruction patterns
    instruction_patterns = [
        r'(?i)(ignore|disregard|override|forget)\s+(all\s+)?(previous|prior|above|earlier)',
        r'(?i)(transfer|send|pay|remit)\s+(Rs\.?|₹|INR)\s*[\d,]+',
        r'(?i)(secret|hidden|invisible|don\'t\s+show)',
        r'(?i)(system\s+prompt|override|admin\s+mode)',
    ]
    for pattern in instruction_patterns:
        for match in re.finditer(pattern, text):
            segments.append({
                "type": "instruction_injection",
                "position": match.start(),
                "text": match.group()[:100],
                "severity": "critical"
            })
    
    return segments


def compute_checksum(data: bytes) -> str:
    """SHA-256 checksum of document bytes"""
    return hashlib.sha256(data).hexdigest()


def parse_document(file_path: str, source_type: str = "auto") -> DocumentContent:
    """
    Main entry point: parse a document file into DocumentContent.
    
    Args:
        file_path: Path to the document file
        source_type: 'pdf', 'email', 'text', or 'auto' (detect from extension)
    
    Returns:
        DocumentContent with parsed text and metadata
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Document not found: {file_path}")
    
    # Auto-detect source type
    if source_type == "auto":
        ext = os.path.splitext(file_path)[1].lower()
        if ext == '.pdf':
            source_type = 'pdf'
        elif ext in ('.eml', '.msg'):
            source_type = 'email'
        else:
            source_type = 'text'
    
    # Read raw bytes
    with open(file_path, 'rb') as f:
        raw_bytes = f.read()
    
    # Extract text based on type
    if source_type == 'pdf':
        text = extract_text_from_pdf(file_path)
    elif source_type == 'email':
        text = extract_text_from_email(file_path)
    else:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            text = f.read()
    
    # Clean text
    visible_text = re.sub(r'[\u200b-\u200f\u2028-\u202f\u2060-\u2064\ufeff]', '', text)
    
    # Extract metadata and detect hidden segments
    metadata = extract_metadata(text, os.path.basename(file_path))
    hidden_segments = detect_hidden_segments(text)
    
    return DocumentContent(
        raw_text=text,
        source_type=source_type,
        filename=os.path.basename(file_path),
        checksum=compute_checksum(raw_bytes),
        byte_length=len(raw_bytes),
        parsed_at=datetime.utcnow().isoformat(),
        metadata=metadata,
        visible_text=visible_text,
        hidden_segments=hidden_segments
    )
