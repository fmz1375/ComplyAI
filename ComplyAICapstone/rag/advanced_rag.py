import re
import json
import os
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FutureTimeoutError
from dataclasses import dataclass
from typing import List, Tuple, Dict, Any
import pysbd  # Sentence boundary detection (better than simple period splitting)
from difflib import SequenceMatcher  # Legacy fallback for backward compatibility
from langchain_community.document_loaders import PyPDFLoader  # Load PDF files
from langchain_community.vectorstores import FAISS  # Dense vector search
from langchain_ollama import OllamaEmbeddings  # Generate embeddings locally
from rank_bm25 import BM25Okapi  # Sparse/keyword-based search
import ollama  # Local LLM interface
import numpy as np  # Numerical operations

# ============================================
# DATA STRUCTURES
# ============================================

@dataclass
class GapFinding:
    """
    SINGLE FINDING: Represents one potential compliance gap found by LLM.
    
    This is the raw finding BEFORE consolidation.
    Multiple findings for the same NIST control will be grouped together later.
    """
    non_compliant_sentence: str  # The actual sentence from policy that's problematic
    page_number: int  # Which page of the policy PDF
    source_quote: str  # Verbatim excerpt from policy (required for grounding)
    control_id: str  # NIST control ID (AC-2, SC-7, etc.)
    control_summary: str  # What that NIST control requires
    risk_level: str  # Critical, High, Moderate, Low
    risk_reason: str  # Why this policy statement fails the control
    recommendation: str  # How to fix this specific gap
    confidence: float  # 0.0-1.0, how confident the LLM is in this finding
    exact_quote: str  # Exact sentence from the PDF used for Ctrl+F style lookup
    source_references: List[Dict[str, Any]]  # Traceability metadata for UI highlighting

@dataclass
class GroupedFinding:
    """
    CONSOLIDATED FINDING: Groups multiple related findings by NIST control.
    
    This is what the frontend displays - one card per NIST control issue.
    If policy violates AC-2 in 3 different ways, they get consolidated into 1 card.
    """
    control_id: str  # NIST control ID
    control_summary: str  # What the control requires
    risk_level: str  # Highest risk level among all findings in this group (Critical > High > Moderate > Low)
    affected_sentences: list  # List of all problematic statements (deduplicated)
    affected_pages: list  # Which pages contain this issue (e.g., [1, 2, 3])
    consolidated_reason: str  # Summary combining all risk_reasons (separated by |)
    consolidated_recommendation: str  # Summary combining all recommendations (separated by |)
    confidence: float  # Average confidence across all findings in this group
    exact_quote: str  # Best exact evidence sentence for frontend search/highlighting
    source_references: List[Dict[str, Any]]  # Aggregated traceability metadata for grouped finding

# ============================================
# ADVANCED RAG ENGINE CLASS
# ============================================

class AdvancedRAGEngine:
    """
    The main RAG system that analyzes policy documents for NIST compliance gaps.
    
    Combines:
    - FAISS vector search (semantic meaning)
    - BM25 keyword search (exact terms)
    - Ollama LLM (understanding context)
    - pysbd sentence segmentation (accurate text splitting)
    """
    
    def __init__(
        self,
        embedding_model: str = "qwen3-embedding",
        llm_model: str = "saki007ster/CybersecurityRiskAnalyst",
        vector_store_path: str = "./faiss_index",
        batch_size: int = 20,
        llm_temperature: float = 0.0,
        llm_timeout_seconds: int = 60,
        max_parallel_batches: int = 3,
        min_retrieval_score: float = 0.0,
    ):
        """
        Initialize the RAG engine.
        
        Args:
            embedding_model: Ollama embedding model (qwen3-embedding is fast, accurate)
            llm_model: Ollama LLM model for analysis (cybersecurity-focused model)
            vector_store_path: Path to pre-built FAISS index (created by nist_embedding.py)
            batch_size: Number of sentences to process per batch (default 20)
            llm_temperature: LLM temperature for reproducibility (0=deterministic, 1=creative)
        """
        self.embedding_model = embedding_model
        self.llm_model = llm_model
        self.vector_store_path = vector_store_path
        self.batch_size = batch_size
        self.llm_temperature = llm_temperature
        self.llm_timeout_seconds = llm_timeout_seconds
        self.max_parallel_batches = max(1, int(max_parallel_batches or 1))
        self.min_retrieval_score = float(min_retrieval_score)
        self.feedback_db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "project.db")
        self.dismissed_feedback = []
        self.dismissed_control_counts = {}
        self.control_rrf_penalties = {}
        self.base_false_positive_threshold = 0.90

        # Initialize pysbd segmenter once (expensive operation, reuse for all pages)
        self.segmenter = pysbd.Segmenter(language="en", clean=False)

        # Initialize Ollama embedding model
        # This will generate embeddings for policy sentences at runtime
        self.embeddings = OllamaEmbeddings(model=embedding_model)
        self.ollama_client = ollama.Client(timeout=self.llm_timeout_seconds)

        # Load pre-built FAISS index (contains 820 NIST control embeddings)
        # This enables fast semantic search: "find controls most similar to policy text"
        try:
            self.faiss_store = FAISS.load_local(
                vector_store_path,
                self.embeddings,
                allow_dangerous_deserialization=True
            )
            print(f"✓ Loaded FAISS vectorstore from {vector_store_path}")
        except Exception as e:
            print(f"⚠ Could not load FAISS store: {e}")
            self.faiss_store = None

        # Build BM25 index
        # BM25 = Okapi BM25 algorithm, keyword-based ranking
        # Works alongside FAISS for hybrid retrieval
        # Example: if policy mentions "password", BM25 finds password-related controls
        self.bm25_index = None
        self.control_corpus = []  # List of all NIST control texts
        self._build_bm25_index()

    def _extract_control_id(self, control_text: str) -> str:
        """Extract a likely NIST control id from control text."""
        if not control_text:
            return ""
        match = re.search(r"\b([A-Z]{1,4}-\d+(?:\(\d+\))?)\b", control_text)
        return match.group(1) if match else ""

    def _normalize_control_id(self, control_id: str) -> str:
        """Normalize control IDs so variants like SC-12(1) and sc-12 map together."""
        if not control_id:
            return ""
        cid = str(control_id).strip().upper()
        # Keep base id for matching (e.g. SC-12 from SC-12(1)).
        cid = re.sub(r"\(\d+\)", "", cid)
        return cid

    def _refresh_feedback_memory(self, framework_version_id: str = None):
        """Load dismissed-gap embeddings and per-control dismissal stats from SQLite."""
        self.dismissed_feedback = []
        self.dismissed_control_counts = {}
        self.control_rrf_penalties = {}

        if not os.path.exists(self.feedback_db_path):
            return

        try:
            conn = sqlite3.connect(self.feedback_db_path)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()

            cur.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='gap_feedback'"
            )
            table_exists = cur.fetchone() is not None
            if not table_exists:
                conn.close()
                return

            if framework_version_id:
                rows = cur.execute(
                    """
                    SELECT framework_version, control_id, chunk_text, embedding_blob, embedding_dim, reason
                    FROM gap_feedback
                    WHERE framework_version = ? OR framework_version IS NULL OR framework_version = ''
                    ORDER BY dismissed_at DESC
                    LIMIT 2000
                    """,
                    (framework_version_id,),
                ).fetchall()
            else:
                rows = cur.execute(
                    """
                    SELECT framework_version, control_id, chunk_text, embedding_blob, embedding_dim, reason
                    FROM gap_feedback
                    ORDER BY dismissed_at DESC
                    LIMIT 2000
                    """
                ).fetchall()
            conn.close()

            for row in rows:
                emb_blob = row["embedding_blob"]
                emb_dim = int(row["embedding_dim"] or 0)
                if not emb_blob or emb_dim <= 0:
                    continue

                emb = np.frombuffer(emb_blob, dtype=np.float32)
                if emb.shape[0] != emb_dim:
                    continue

                norm = float(np.linalg.norm(emb))
                if norm == 0.0:
                    continue

                control_id = self._normalize_control_id((row["control_id"] or "").strip())
                self.dismissed_feedback.append(
                    {
                        "framework_version": row["framework_version"],
                        "control_id": control_id,
                        "chunk_text": row["chunk_text"] or "",
                        "reason": row["reason"] or "Dismissed by auditor",
                        "embedding": emb,
                        "norm": norm,
                    }
                )
                if control_id:
                    self.dismissed_control_counts[control_id] = self.dismissed_control_counts.get(control_id, 0) + 1

            for control_id, dismiss_count in self.dismissed_control_counts.items():
                # Penalize controls with frequent dismissals, capped to avoid over-suppression.
                self.control_rrf_penalties[control_id] = min(0.35, dismiss_count * 0.03)

        except Exception as e:
            print(f"DEBUG: Failed to refresh feedback memory: {e}", flush=True)

    def _find_similar_dismissals(self, text: str, top_k: int = 3, threshold: float = 0.86):
        """Return semantically similar dismissed examples for negative prompting."""
        if not text or not self.dismissed_feedback:
            return []

        try:
            q = np.asarray(self.embeddings.embed_query(text), dtype=np.float32)
            q_norm = float(np.linalg.norm(q))
            if q_norm == 0.0:
                return []

            scored = []
            for item in self.dismissed_feedback:
                sim = float(np.dot(q, item["embedding"]) / (q_norm * item["norm"]))
                if sim >= threshold:
                    scored.append((sim, item))

            scored.sort(key=lambda x: x[0], reverse=True)
            out = []
            for sim, item in scored[:top_k]:
                out.append(
                    {
                        "similarity": sim,
                        "control_id": item.get("control_id", ""),
                        "chunk_text": item.get("chunk_text", ""),
                        "reason": item.get("reason", "Dismissed by auditor"),
                    }
                )
            return out
        except Exception as e:
            print(f"DEBUG: Similar dismissal lookup failed: {e}", flush=True)
            return []

    def _build_negative_context(self, similar_dismissals) -> str:
        """Format negative examples for few-shot anti-false-positive prompting."""
        if not similar_dismissals:
            return ""

        lines = [
            "NEGATIVE EXAMPLES (human dismissed false positives):",
            "Do not flag similar patterns as gaps unless there is explicit contradictory evidence.",
        ]
        for idx, d in enumerate(similar_dismissals, start=1):
            control = d.get("control_id") or "UNKNOWN_CONTROL"
            quote = (d.get("chunk_text") or "")[:220].replace("\n", " ").strip()
            reason = (d.get("reason") or "Dismissed by auditor").strip()
            lines.append(
                f"{idx}. Previously flagged for {control}, then dismissed as compliant. "
                f"Reason: {reason}. Example text: \"{quote}\""
            )
        return "\n".join(lines)

    def _is_dismissed_pattern(self, text: str, control_id: str, threshold: float = 0.82) -> bool:
        """
        Hard suppression check: if a finding is very similar to a previously dismissed
        example for the same control, skip it.
        """
        if not text or not control_id or not self.dismissed_feedback:
            return False

        target_control_id = self._normalize_control_id(control_id)
        if not target_control_id:
            return False

        try:
            q = np.asarray(self.embeddings.embed_query(text), dtype=np.float32)
            q_norm = float(np.linalg.norm(q))
            if q_norm == 0.0:
                return False

            for item in self.dismissed_feedback:
                if self._normalize_control_id(item.get("control_id") or "") != target_control_id:
                    continue
                sim = float(np.dot(q, item["embedding"]) / (q_norm * item["norm"]))
                if sim >= threshold:
                    print(
                        f"DEBUG: Suppressed dismissed pattern for {control_id} (similarity={sim:.3f})",
                        flush=True,
                    )
                    return True
            return False
        except Exception as e:
            print(f"DEBUG: Dismissed-pattern check failed: {e}", flush=True)
            return False

    def _get_false_positive_threshold(self, control_id: str) -> float:
        """Dynamic threshold tuning: stricter filtering for frequently dismissed controls."""
        dismiss_count = self.dismissed_control_counts.get(self._normalize_control_id(control_id or ""), 0)
        # Raise threshold gradually up to +0.08 to avoid recurring false positives.
        adjusted = self.base_false_positive_threshold + min(0.08, dismiss_count * 0.01)
        return min(0.98, adjusted)

    def _consolidate_findings(self, findings: List[GapFinding]) -> List[GroupedFinding]:
        """
        GROUP RELATED FINDINGS: Convert raw findings into consolidated results.
        
        Purpose: If the same NIST control is violated in 3 different ways,
        group them into 1 finding card instead of 3.
        
        Process:
        1. Group all GapFindings by control_id
        2. For each group:
           - Determine highest risk level (Critical beats High beats Moderate beats Low)
           - Collect all affected pages and sentences
           - Combine risk reasons (delimited by |)
           - Combine recommendations (delimited by |)
           - Calculate average confidence
        3. Sort by risk level (Critical first) then confidence (descending)
        """
        if not findings:
            return []
        
        # STEP 1: Group by control_id
        groups = {}
        for f in findings:
            if f.control_id not in groups:
                groups[f.control_id] = []
            groups[f.control_id].append(f)
        
        # STEP 2: Consolidate each group
        consolidated = []
        for control_id, group_findings in groups.items():
            # Determine highest risk level in this group
            # Risk hierarchy: Critical(4) > High(3) > Moderate(2) > Low(1)
            risk_levels = {"Critical": 4, "High": 3, "Moderate": 2, "Low": 1}
            max_risk = max(risk_levels.get(f.risk_level, 0) for f in group_findings)
            risk_level_map = {4: "Critical", 3: "High", 2: "Moderate", 1: "Low"}
            highest_risk = risk_level_map.get(max_risk, "Moderate")
            
            # Collect source references and ensure metadata survives grouping.
            source_references = []
            for finding in group_findings:
                refs = finding.source_references or []
                if refs:
                    source_references.extend(refs)
                else:
                    source_references.append({
                        "page": finding.page_number,
                        "text_snippet": finding.source_quote or finding.non_compliant_sentence,
                        "source_index": f"p{finding.page_number}_fallback",
                        "unique_index": f"p{finding.page_number}_fallback",
                    })

            deduped_refs = []
            seen_refs = set()
            for ref in source_references:
                page = int(ref.get("page", 0) or 0)
                snippet = str(ref.get("text_snippet", "") or "").strip()
                source_index = str(ref.get("source_index", "") or "")
                key = (source_index, page, snippet)
                if key in seen_refs:
                    continue
                seen_refs.add(key)
                deduped_refs.append({
                    "page": page,
                    "text_snippet": snippet,
                    "source_index": source_index,
                    "unique_index": source_index,
                })

            # Collect affected pages (sorted, unique)
            affected_pages = sorted(set(int(r.get("page", 0) or 0) for r in deduped_refs if int(r.get("page", 0) or 0) > 0))
            if not affected_pages:
                affected_pages = sorted(set(f.page_number for f in group_findings if f.page_number > 0))

            # Collect affected sentences/quotes
            affected_sentences = [r.get("text_snippet", "") for r in deduped_refs if r.get("text_snippet")]
            if not affected_sentences:
                affected_sentences = [f.source_quote or f.non_compliant_sentence for f in group_findings]
            
            # Smart deduplication: remove near-duplicates (similar strings)
            def deduplicate_reasons(items):
                """Remove exact duplicates and near-duplicates (substring matches)"""
                if not items:
                    return []
                unique = []
                for item in items:
                    # Check if this item or a similar one already exists
                    is_duplicate = False
                    for existing in unique:
                        # If one is a substring of the other or they're very similar, skip
                        if item.lower() in existing.lower() or existing.lower() in item.lower():
                            is_duplicate = True
                            break
                    if not is_duplicate:
                        unique.append(item)
                return unique
            
            # Consolidate reasons with smart deduplication
            reasons = deduplicate_reasons([f.risk_reason for f in group_findings if f.risk_reason])
            consolidated_reason = " ".join(reasons) if reasons else "Compliance gap detected"
            
            # Consolidate recommendations similarly
            recommendations = deduplicate_reasons([f.recommendation for f in group_findings if f.recommendation])
            consolidated_recommendation = " ".join(recommendations) if recommendations else "Implement required NIST control"
            
            # Average confidence across all findings in this group
            avg_confidence = sum(f.confidence for f in group_findings) / len(group_findings)
            
            # Get control summary from first finding (all should have same control_summary)
            control_summary = group_findings[0].control_summary or f"NIST Control {control_id}"
            
            # Create consolidated finding
            consolidated.append(GroupedFinding(
                control_id=control_id,
                control_summary=control_summary,
                risk_level=highest_risk,
                affected_sentences=affected_sentences,
                affected_pages=affected_pages,
                consolidated_reason=consolidated_reason,
                consolidated_recommendation=consolidated_recommendation,
                confidence=avg_confidence,
                exact_quote=deduped_refs[0].get("text_snippet", "") if deduped_refs else (group_findings[0].exact_quote or group_findings[0].source_quote or group_findings[0].non_compliant_sentence),
                source_references=deduped_refs,
            ))
        
        # STEP 3: Sort by risk level (Critical first) then confidence (highest first)
        risk_order = {"Critical": 0, "High": 1, "Moderate": 2, "Low": 3}
        consolidated.sort(key=lambda x: (risk_order.get(x.risk_level, 99), -x.confidence))
        
        return consolidated

    def _normalize_text(self, text: str) -> str:
        return re.sub(r"\s+", " ", str(text or "").strip()).lower()

    def _segment_to_reference(self, segment: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "page": int(segment.get("page_number", 0) or 0),
            "text_snippet": str(segment.get("sentence_text", "") or ""),
            "source_index": str(segment.get("source_index", "") or ""),
            "unique_index": str(segment.get("source_index", "") or ""),
        }

    def _match_source_references(self, finding: GapFinding, batch: List[Dict[str, Any]], max_matches: int = 3) -> List[Dict[str, Any]]:
        candidates = []
        if finding.source_quote:
            candidates.append(finding.source_quote)
        if finding.non_compliant_sentence:
            candidates.append(finding.non_compliant_sentence)

        # Try exact/substring matches first (pysbd sentence output should align closely).
        matched = []
        for candidate in candidates:
            candidate_norm = self._normalize_text(candidate)
            if not candidate_norm:
                continue
            for segment in batch:
                sentence_norm = self._normalize_text(segment.get("sentence_text", ""))
                if not sentence_norm:
                    continue
                if candidate_norm in sentence_norm or sentence_norm in candidate_norm:
                    matched.append(self._segment_to_reference(segment))
                if len(matched) >= max_matches:
                    break
            if len(matched) >= max_matches:
                break

        if matched:
            return matched[:max_matches]

        # Fallback fuzzy match when LLM truncates or paraphrases minimally.
        scored = []
        for segment in batch:
            sentence_text = str(segment.get("sentence_text", "") or "")
            if not sentence_text:
                continue
            best_ratio = 0.0
            for candidate in candidates:
                ratio = SequenceMatcher(None, self._normalize_text(candidate), self._normalize_text(sentence_text)).ratio()
                if ratio > best_ratio:
                    best_ratio = ratio
            if best_ratio >= 0.6:
                scored.append((best_ratio, segment))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [self._segment_to_reference(seg) for _, seg in scored[:max_matches]]

    def _attach_source_references(self, findings: List[GapFinding], batch: List[Dict[str, Any]]) -> List[GapFinding]:
        if not findings:
            return findings
        for finding in findings:
            refs = self._match_source_references(finding, batch)
            if refs:
                finding.source_references = refs
                if finding.page_number <= 0:
                    finding.page_number = int(refs[0].get("page", 0) or 0)
                if not finding.source_quote:
                    finding.source_quote = str(refs[0].get("text_snippet", "") or "")
                finding.exact_quote = str(refs[0].get("text_snippet", "") or finding.exact_quote or finding.source_quote or finding.non_compliant_sentence)
            else:
                finding.source_references = finding.source_references or [{
                    "page": finding.page_number,
                    "text_snippet": finding.source_quote or finding.non_compliant_sentence,
                    "source_index": f"p{finding.page_number}_fallback",
                    "unique_index": f"p{finding.page_number}_fallback",
                }]
                if not finding.exact_quote:
                    finding.exact_quote = finding.source_quote or finding.non_compliant_sentence
        return findings

    def _build_bm25_index(self):
        """
        BUILD BM25 INDEX: Create keyword-based search index.
        
        BM25 (Best Matching 25) is an algorithm that ranks documents by relevance
        to a query based on term frequency, document length, and other factors.
        
        Purpose: Hybrid retrieval combines dense (FAISS) and sparse (BM25) search
        - FAISS handles semantic meaning: "authenticate users" finds AC-2
        - BM25 handles exact keywords: "password" finds SC-2
        - Together they catch more relevant controls
        
        Process:
        1. Extract all control texts from FAISS docstore
        2. Tokenize (split into words and lowercase)
        3. Build BM25 index using these tokens
        """
        if self.faiss_store:
            try:
                # Extract all NIST control texts from the FAISS store
                # self.faiss_store.docstore._dict is a dict of {id: Document}
                self.control_corpus = [doc.page_content for doc in self.faiss_store.docstore._dict.values()]
                
                # Tokenize: split each control into words and convert to lowercase
                # Example: "Implement access control measures" → ["implement", "access", "control", "measures"]
                tokenized = [d.lower().split() for d in self.control_corpus]
                
                # Build BM25 index on tokenized corpus
                self.bm25_index = BM25Okapi(tokenized)
                print(f"✓ Built BM25 index with {len(self.control_corpus)} controls")
            except Exception as e:
                print(f"⚠ BM25 build error: {e}")

    def _is_false_positive(self, sentence: str, control_id: str, threshold: float = 0.90) -> bool:
        """
        DETECT FALSE POSITIVES: Is this finding just repeating the control?
        
        Problem: Sometimes the LLM outputs findings where the policy just MENTIONS
        a control but doesn't violate it. For example:
        - Control: "Implement access control" (AC-2)
        - Policy: "We follow NIST AC-2: Implement access control measures"
        - The policy is COMPLIANT (just stating the requirement)
        
        Solution: Use the FAISS embeddings that are already loaded. Embed the sentence,
        then check if it's semantically identical to the control (>0.90 similarity).
        This means the policy is just restating the control, not violating it.
        
        Why Semantic > String Matching:
        - String matching fails on "Protect Function" vs "PR (Protect)" - different words
        - Semantic analysis recognizes they mean the same thing conceptually
        
        Args:
            sentence: The policy statement from the finding
            control_id: The NIST control ID (e.g., "AC-2") to check against
            threshold: Semantic similarity (0-1) above which it's a false positive
                      0.90 = 90% semantically similar (policy just restating control)
        
        Returns:
            True if this is likely a false positive (should be filtered out)
            False if this is a real gap (keep it)
        """
        if not sentence or not control_id or not self.faiss_store:
            return False
        
        try:
            # Embed the sentence using the same embedding model as FAISS
            sentence_embedding = self.embeddings.embed_query(sentence)
            sentence_embedding = np.array(sentence_embedding).reshape(1, -1)
            
            # Search FAISS for this specific control to get its embedding
            # The FAISS store contains metadata with control IDs
            results = self.faiss_store.similarity_search_with_score(sentence, k=100)
            
            # Find the matching control in results and check similarity
            for doc, score in results:
                # FAISS score is distance (lower = more similar), convert to similarity (0-1)
                # Typically: similarity = 1 / (1 + distance)
                doc_control_id = doc.metadata.get("control_id", "")
                if doc_control_id == control_id:
                    # Found the control - check if similarity is high
                    # Lower score = higher similarity in FAISS
                    similarity = 1 / (1 + score)  # Convert distance to similarity
                    
                    if similarity >= threshold:
                        print(f"DEBUG: Detected false positive (similarity={similarity:.3f}): '{sentence[:50]}...' matches {control_id}", flush=True)
                        return True
                    return False
            
            # Control not found in top results - not a false positive
            return False
            
        except Exception as e:
            # If FAISS lookup fails, be conservative and don't filter
            print(f"DEBUG: FAISS similarity check failed: {e}, keeping finding", flush=True)
            return False

    # ============================================
    # PDF ANALYSIS MAIN FUNCTION
    # ============================================
    
    def analyze_policy_pdf(self, pdf_path: str, progress_callback=None, framework_version_id=None, cancel_check=None, cancel_event=None) -> List[dict]:
        """
        MAIN FUNCTION: Analyze a policy PDF for NIST compliance gaps.
        
        This is the entry point called by app.py when user uploads a PDF.
        
        Args:
            pdf_path: Path to the PDF file to analyze
            progress_callback: Optional callback function for progress updates
            framework_version_id: Optional framework version ID (for future use with multiple frameworks)
            cancel_check: Callable that returns True when user requested cancellation.
            cancel_event: threading.Event instance used to interrupt long-running batch processing.
        
        Returns: List of consolidated findings [{control_id, risk_level, ...}]
        
        WORKFLOW:
        1. Load PDF and extract sentences
        2. Analyze sentences in batches with LLM
        3. Deduplicate findings
        4. Filter by confidence
        5. Remove false positives
        6. Consolidate by control
        7. Return to frontend
        """
        self._refresh_feedback_memory(framework_version_id=framework_version_id)

        # Load PDF file
        loader = PyPDFLoader(pdf_path)
        documents = loader.load()  # Returns list of Document (one per page)
        total_pages = len(documents)
        all_sentences: List[Dict[str, Any]] = []

        # STEP 1: LOAD & SEGMENT PDF
        print(f"DEBUG: Loading {total_pages} pages", flush=True)
        
        for page_idx, doc in enumerate(documents):
            # For each page, extract sentences and filter out headings
            all_sentences.extend(self._segment_page(doc.page_content, page_idx + 1))
        
        print(f"DEBUG: Loaded {len(all_sentences)} sentences", flush=True)
        
        # STEP 2: BATCH ANALYSIS
        # This calls _analyze_all_sentences which processes in chunks
        # of 20 sentences, with progress callbacks after each batch completes
        findings = self._analyze_all_sentences(
            all_sentences,
            progress_callback=progress_callback,
            cancel_check=cancel_check,
            cancel_event=cancel_event,
        )

        if callable(cancel_check) and cancel_check():
            raise RuntimeError("Analysis cancelled by user")
        
        # STEP 3: DEDUPLICATE
        # If the same sentence appears in multiple batches (overlap from sentence splitting),
        # keep only one copy
        unique_findings = []
        seen = {}
        for f in findings:
            key = (
                f.control_id.strip(),
                f.non_compliant_sentence.strip(),
                f.page_number,
                f.source_quote.strip(),
            )
            if key not in seen:
                seen[key] = f
                unique_findings.append(f)
            else:
                existing = seen[key]
                merged = (existing.source_references or []) + (f.source_references or [])
                dedup = []
                dedup_keys = set()
                for ref in merged:
                    r_key = (
                        str(ref.get("source_index", "") or ""),
                        int(ref.get("page", 0) or 0),
                        str(ref.get("text_snippet", "") or "").strip(),
                    )
                    if r_key in dedup_keys:
                        continue
                    dedup_keys.add(r_key)
                    dedup.append({
                        "page": r_key[1],
                        "text_snippet": r_key[2],
                        "source_index": r_key[0],
                        "unique_index": r_key[0],
                    })
                existing.source_references = dedup
        
        # Sort by page number for readable output
        unique_findings.sort(key=lambda x: x.page_number)
        
        # STEP 4: FILTER BY CONFIDENCE
        # Only keep findings where LLM was confident (>=0.5)
        # 0.5 = 50% confidence threshold (reasonable balance)
        filtered_findings = [f for f in unique_findings if f.confidence >= 0.5]
        
        # STEP 5: REMOVE FALSE POSITIVES
        # Filter out findings where policy just repeats the control description
        # Uses FAISS embeddings already in memory (no re-embedding of controls)
        # With 0.90 threshold: only removes if >90% semantically similar
        # This catches cases like "Protect Function" being identified as a gap when it's just a heading
        print(f"DEBUG: Filtering false positives (sentences that just mention control, not violate it)...", flush=True)
        real_findings = []
        for f in filtered_findings:
            # Hard-negative suppression: if user previously dismissed a very similar
            # finding for this same control, do not surface it again.
            candidate_text = f.source_quote or f.non_compliant_sentence
            if self._is_dismissed_pattern(candidate_text, f.control_id, threshold=0.72):
                continue

            dynamic_threshold = self._get_false_positive_threshold(f.control_id)
            if not self._is_false_positive(f.non_compliant_sentence, f.control_id, threshold=dynamic_threshold):
                real_findings.append(f)
            else:
                print(f"DEBUG: Filtered false positive: '{f.non_compliant_sentence[:60]}...' (too similar to {f.control_id})", flush=True)
        
        # STEP 6: CONSOLIDATE FINDINGS
        # Group by control_id, determine highest risk, combine reasons/recommendations
        grouped_findings = self._consolidate_findings(real_findings)
        
        print(f"DEBUG: Total findings: {len(findings)} → dedup: {len(unique_findings)} → confidence: {len(filtered_findings)} → false positives removed: {len(real_findings)} → consolidated: {len(grouped_findings)}", flush=True)
        
        # STEP 7: CONVERT TO JSON-SERIALIZABLE DICTS
        # Format each grouped finding as a dict for JSON response
        return [
            {
                "control_id": gf.control_id,
                "control_summary": gf.control_summary,
                "risk_level": gf.risk_level,
                "affected_pages": gf.affected_pages,
                "num_occurrences": len(gf.affected_sentences),
                "example_quote": gf.affected_sentences[0] if gf.affected_sentences else "",
                "exact_quote": gf.exact_quote,
                "consolidated_reason": gf.consolidated_reason,
                "consolidated_recommendation": gf.consolidated_recommendation,
                "confidence": round(gf.confidence, 2),
                "source_references": gf.source_references,
            }
            for gf in grouped_findings
        ]

    def _segment_page(self, text: str, page_num: int) -> List[Dict[str, Any]]:
        """
        SENTENCE SEGMENTATION: Split page text into sentences.
        
        Uses pysbd (Python Sentence Boundary Detector) which is smarter than
        simple regex splitting - handles abbreviations, decimals, URLs, etc.
        
        Also filters out headings (section titles) since we only want policy content.
        
        Args:
            text: Raw text from one PDF page
            page_num: Page number (1-indexed)
        
        Returns:
            List of (sentence, page_number, sentence_index) tuples
        """
        try:
            # Segment text into sentences using pre-initialized segmenter
            # pysbd handles: abbreviations (Mr. Smith), numbers (1.5), URLs, etc.
            sentences = self.segmenter.segment(text)
            
            # Filter: keep only non-empty, non-heading sentences
            filtered = []
            for idx, s in enumerate(sentences):
                s = s.strip()
                # Keep sentence only if:
                # 1. It's not empty
                # 2. It's not a heading (filtered by _is_heading)
                if s and not self._is_heading(s):
                    filtered.append({
                        "sentence_text": s,
                        "raw_sentence_text": s,
                        "page_number": page_num,
                        "sentence_index": idx,
                        "source_index": f"p{page_num}_s{idx}",
                    })
            return filtered
        except Exception:
            # Fallback: if pysbd fails, return whole page as one sentence
            fallback_text = str(text or "").strip()
            return [{
                "sentence_text": fallback_text,
                "raw_sentence_text": fallback_text,
                "page_number": page_num,
                "sentence_index": 0,
                "source_index": f"p{page_num}_s0",
            }] if fallback_text else []

    def _is_heading(self, text: str) -> bool:
        """
        HEADING DETECTION: Is this text a section title, not policy content?
        
        Purpose: We only want to analyze actual policy statements, not section headers.
        Sending "Security Requirements" to the LLM wastes tokens and causes false positives.
        
        Detection heuristics:
        1. Too short (<20 chars) → likely heading
        2. All CAPS → likely heading (SECURITY, PASSWORD POLICY)
        3. Few words (<5) → likely heading
        4. Ends with colon → likely label (Results: Introduction:)
        5. Starts with number → numbered heading (1. Overview, A. Summary)
        6. Common heading keywords → introduction, appendix, index, etc.
        7. Title case with few words → "Security Requirements"
        
        Returns:
            True if this is likely a heading (should be ignored)
            False if this is policy content (should be analyzed)
        """
        text = text.strip()
        if not text:
            return True
        
        # Heuristic 1: Too short - likely a heading
        if len(text) < 20:
            return True
        
        # Heuristic 2: All caps - SECURITY, PASSWORD POLICY, etc.
        if text.isupper():
            return True
        
        # Heuristic 3: Very few words - likely a title
        if len(text.split()) < 5:
            return True
        
        # Heuristic 4: Ends with colon - "Results:" "Introduction:" "Parameters:"
        if text.rstrip().endswith(':'):
            return True
        
        # Heuristic 5: Numbered heading - "1. Overview" "A. Summary" "i. Introduction"
        if text[0].isdigit() and len(text) > 1 and text[1] in '.):':
            return True
        
        # Heuristic 6: Common heading keywords
        # Match if text STARTS with these keywords (case-insensitive)
        heading_keywords = ['table of contents', 'appendix', 'chapter', 'section', 'introduction', 
                           'conclusion', 'summary', 'references', 'index', 'page', 'document', 
                           'policy', 'procedure', 'standard', 'guideline', 'overview', 'purpose']
        text_lower = text.lower()
        for keyword in heading_keywords:
            if text_lower.startswith(keyword) and len(text) < 100:
                return True
        
        # Heuristic 7: Title case with few words and no punctuation
        # "Security Requirements" but not "The company requires strong passwords"
        if len(text.split()) <= 4 and text[0].isupper() and text.count('.') == 0 and text.count(',') == 0:
            return True
        
        return False

    # ============================================
    # BATCH ANALYSIS WITH LLM
    # ============================================
    
    def _serialize_finding(self, finding: GapFinding) -> Dict[str, Any]:
        """Convert one finding to a JSON-safe shape for progress updates."""
        return {
            "control_id": finding.control_id,
            "control_summary": finding.control_summary,
            "risk_level": finding.risk_level,
            "page_number": finding.page_number,
            "non_compliant_sentence": finding.non_compliant_sentence,
            "source_quote": finding.source_quote,
            "risk_reason": finding.risk_reason,
            "recommendation": finding.recommendation,
            "confidence": finding.confidence,
            "source_references": finding.source_references or [],
        }

    def _build_batch_prompt(self, batch: List[Dict[str, Any]], context: str, negative_context: str) -> str:
        statements_block = "\n".join([
            f"{i+1}. (Page {seg.get('page_number', 0)}, Source {seg.get('source_index', '')}) {seg.get('sentence_text', '')}"
            for i, seg in enumerate(batch)
        ])

        return f"""SYSTEM: You are a Senior Cybersecurity Consultant evaluating compliance. Your goal is to identify REAL, actionable gaps-not to be overly strict or invent problems.

NIST CONTROL DEFINITIONS (for reference):
{context}

POLICY TEXT (analyze each statement below):
{statements_block}

{negative_context}

Your Task: Identify only GENUINE compliance gaps. A gap exists only when:
1. A NIST control requirement is completely unaddressed in the policy, OR
2. The policy explicitly describes a weak/broken practice that violates the control

CRITICAL RULES FOR BALANCED JUDGMENT:
1. CONTEXTUAL LINKING: If a policy mentions a high-level goal (e.g., "We protect PII"), look in the surrounding text for technical controls (e.g., "encryption", "MFA"). If a mitigating control is mentioned ANYWHERE in the batch, DO NOT flag it as a gap.
2. FREQUENCY STANDARDS: Do NOT flag gaps based on frequency alone. Quarterly risk assessments, annual training, and semi-annual audits are industry standard. Only flag if frequency is completely absent or explicitly inadequate.
3. NO INVENTED REQUIREMENTS: Do NOT suggest requirements not in NIST (e.g., "implement IoT security" for a software-only product, "monthly checks" when quarterly is compliant).
4. REAL GAPS ONLY: Only report gaps where the policy is silent or explicitly non-compliant. Do not report neutral statements like "we use password authentication" as gaps.
5. PROPER CONTROL MAPPING (CRITICAL): Each distinct gap must map to its own correct NIST Control. NEVER group unrelated technical issues under a single control.
6. VERBATIM EVIDENCE: Your 'source_quote' MUST be copied word-for-word from the policy. If you cannot find explicit evidence, use "NOT FOUND" and skip the finding.

Return JSON array:
```json
[
  {{
    "compliant": false,
    "non_compliant_sentence": "the specific problematic statement from the policy",
    "source_quote": "short verbatim excerpt from the policy",
    "control_id": "NIST control ID that specifically addresses THIS gap (e.g., SC-8 for encryption, AT-1 for training)",
    "control_summary": "what this specific control requires",
    "risk_level": "Critical|High|Moderate|Low",
    "risk_reason": "exactly why this source_quote fails THIS control",
    "recommendation": "specific, actionable fix for THIS gap",
    "confidence": 0.85,
    "page_number": {batch[0].get('page_number', 1) if batch else 1}
  }}
]
```

Return ONLY valid JSON. Empty array [] if no real gaps found."""

    def _analyze_single_batch(self, batch: List[Dict[str, Any]], current_batch: int, total_batches: int, cancel_check=None, cancel_event=None) -> Tuple[int, List[GapFinding], List[Dict[str, Any]]]:
        if cancel_event and cancel_event.is_set():
            return current_batch, [], []
        if callable(cancel_check) and cancel_check():
            return current_batch, [], []

        print(f"DEBUG: Processing batch {current_batch}/{total_batches} ({len(batch)} sentences)", flush=True)
        batch_text = " ".join([str(s.get("sentence_text", "") or "") for s in batch])
        retrieved = self._hybrid_retrieve(batch_text, top_k=5, return_scores=True)
        top_score = float(retrieved[0][1]) if retrieved else 0.0

        if self.min_retrieval_score > 0 and top_score < self.min_retrieval_score:
            print(
                f"DEBUG: Skipping batch {current_batch} due to low retrieval score ({top_score:.4f})",
                flush=True,
            )
            return current_batch, [], []

        relevant_controls = [control for control, _ in retrieved]
        context = "\n".join(relevant_controls[:4]) if relevant_controls else "No NIST controls retrieved."
        similar_dismissals = self._find_similar_dismissals(batch_text, top_k=5, threshold=0.78)
        negative_context = self._build_negative_context(similar_dismissals)
        prompt = self._build_batch_prompt(batch, context, negative_context)

        try:
            print(f"DEBUG: Calling LLM for batch {current_batch}", flush=True)
            with ThreadPoolExecutor(max_workers=1) as llm_executor:
                future = llm_executor.submit(
                    self.ollama_client.generate,
                    model=self.llm_model,
                    prompt=prompt,
                    options={"temperature": self.llm_temperature},
                )
                resp = future.result(timeout=self.llm_timeout_seconds)

            raw_text = resp.get("response", "")
            batch_findings = self._extract_findings_from_response(raw_text, batch)
            batch_findings = self._attach_source_references(batch_findings, batch)
            return current_batch, batch_findings, [self._serialize_finding(f) for f in batch_findings]
        except FutureTimeoutError:
            print(f"Batch {current_batch} timed out after {self.llm_timeout_seconds}s", flush=True)
            return current_batch, [], []
        except Exception as e:
            print(f"Batch {current_batch} LLM error: {e}", flush=True)
            return current_batch, [], []

    def _analyze_all_sentences(self, all_sentences: List[Dict[str, Any]], progress_callback=None, cancel_check=None, cancel_event=None) -> List[GapFinding]:
        if not all_sentences:
            return []

        all_findings = []
        batch_size = self.batch_size
        total_batches = (len(all_sentences) + batch_size - 1) // batch_size

        if progress_callback:
            progress_callback(0, total_batches)

        batches = [
            all_sentences[idx: idx + batch_size]
            for idx in range(0, len(all_sentences), batch_size)
        ]

        completed_batches = 0
        next_batch_to_submit = 0
        in_flight = {}

        with ThreadPoolExecutor(max_workers=self.max_parallel_batches) as executor:
            while next_batch_to_submit < total_batches or in_flight:
                if cancel_event and cancel_event.is_set():
                    break
                while len(in_flight) < self.max_parallel_batches and next_batch_to_submit < total_batches:
                    if cancel_event and cancel_event.is_set():
                        break
                    if callable(cancel_check) and cancel_check():
                        break

                    batch = batches[next_batch_to_submit]
                    batch_number = next_batch_to_submit + 1
                    fut = executor.submit(
                        self._analyze_single_batch,
                        batch,
                        batch_number,
                        total_batches,
                        cancel_check,
                        cancel_event,
                    )
                    in_flight[fut] = batch_number
                    next_batch_to_submit += 1

                if not in_flight:
                    break

                done_future = next(as_completed(in_flight))
                in_flight.pop(done_future)

                try:
                    _, batch_findings, raw_batch_findings = done_future.result()
                except Exception as e:
                    print(f"Batch processing error: {e}", flush=True)
                    batch_findings, raw_batch_findings = [], []

                all_findings.extend(batch_findings)
                completed_batches += 1

                if progress_callback:
                    progress_callback(completed_batches, total_batches, raw_batch_findings)

                if cancel_event and cancel_event.is_set():
                    break
                if callable(cancel_check) and cancel_check():
                    break

        if progress_callback and not (cancel_event and cancel_event.is_set()) and not (callable(cancel_check) and cancel_check()):
            progress_callback(total_batches, total_batches)

        return all_findings

    def _extract_findings_from_response(self, text: str, batch: List[Dict[str, Any]] = None) -> List[GapFinding]:
        """
        EXTRACT STRUCTURED FINDINGS: Parse LLM's JSON response.
        
        The LLM returns findings in JSON format. This function:
        1. Finds JSON in the response (handles markdown code blocks)
        2. Parses JSON arrays
        3. Creates GapFinding objects
        
        Robust error handling for:
        - Markdown code blocks: ```json ... ```
        - Raw JSON arrays: [ { ... } ]
        - Multiple arrays in one response
        - Malformed JSON (skip and continue)
        
        Args:
            text: Raw text response from LLM
        
        Returns:
            List of GapFinding objects extracted from JSON
        """
        findings = []
        try:
            # Try to find JSON in markdown code block first
            # LLM often wraps JSON in ```json ... ``` blocks
            match = re.search(r'```json\s*(.*?)\s*```', text, re.DOTALL)
            if match:
                json_text = match.group(1).strip()
            else:
                # Fallback: try to extract raw JSON array
                match = re.search(r'\[\s*\{.*?\}\s*\]', text, re.DOTALL)
                json_text = match.group(0) if match else text
            
            # Sometimes LLM returns multiple arrays (one per statement)
            # Find all separate arrays
            arrays = re.findall(r'\[\s*\{[^\[]*?\}\s*\]', json_text, re.DOTALL)
            
            # If no arrays found but text starts with [, treat entire text as one array
            if not arrays and json_text.strip().startswith('['):
                arrays = [json_text]
            
            # Parse each array
            for array_text in arrays:
                try:
                    # Parse JSON array
                    arr = json.loads(array_text)
                    
                    # Ensure arr is a list (sometimes single object)
                    if not isinstance(arr, list):
                        arr = [arr]
                    
                    # Process each finding in the array
                    for item in arr:
                        # Only process items marked as non-compliant
                        # item.get("compliant", True) defaults to True if missing
                        if not item.get("compliant", True):
                            # Get source quote (with fallback to sentence)
                            source_quote = str(item.get("source_quote", "")).strip()
                            if not source_quote:
                                source_quote = str(item.get("non_compliant_sentence", "")).strip()
                            
                            # Create GapFinding object from JSON data
                            findings.append(GapFinding(
                                non_compliant_sentence=str(item.get("non_compliant_sentence","")),
                                page_number=int(item.get("page_number",0)),
                                source_quote=source_quote,
                                control_id=str(item.get("control_id","")),
                                control_summary=str(item.get("control_summary","")),
                                risk_level=str(item.get("risk_level","Moderate")),
                                risk_reason=str(item.get("risk_reason","")),
                                recommendation=str(item.get("recommendation","")),
                                confidence=float(item.get("confidence",0.5)),
                                exact_quote="",
                                source_references=[],
                            ))
                except json.JSONDecodeError:
                    # If JSON parsing fails, skip this array and continue
                    continue
        except Exception as e:
            print(f"Extract findings error: {e}")

        # Fill missing pages from batch fallback for robustness.
        if batch and findings:
            fallback_page = int(batch[0].get("page_number", 0) or 0)
            for finding in findings:
                if finding.page_number <= 0:
                    finding.page_number = fallback_page
        return findings

    # ============================================
    # HYBRID RETRIEVAL (FAISS + BM25)
    # ============================================
    
    def _hybrid_retrieve(self, query: str, top_k: int = 3, return_scores: bool = False):
        """
        HYBRID RETRIEVAL: Combine dense (FAISS) and sparse (BM25) search with RRF scoring.
        
        RRF (Reciprocal Rank Fusion) combines rankings from FAISS and BM25:
        - Get top 5 from FAISS (dense semantic search)
        - Get top 5 from BM25 (sparse keyword search)
        - Apply RRF formula: score = sum(1 / (k + rank)) for each method
        - Rank combined results by RRF score
        - Return top_k controls
        
        RRF formula: RRF(d) = sum_{r ∈ R} 1 / (k + r(d))
        where k = 60 (constant), r(d) = rank of document d in ranking r
        
        Example:
        Query: "We don't use multi-factor authentication"
        
        FAISS returns (ranks 1-5):
        - Rank 1: SC-7: Network segmentation
        - Rank 2: AC-3: Access control
        - Rank 3: AC-2: Authentication (HIT!)
        
        BM25 returns (ranks 1-5):
        - Rank 1: IA-2: Authentication
        - Rank 2: IA-5: Password policy
        - Rank 3: SC-7: Cryptography (HIT!)
        
        RRF Scoring:
        - AC-2: 1/(60+3) + 0 = 0.0159 (only in FAISS)
        - SC-7: 1/(60+1) + 1/(60+3) = 0.0159 + 0.0159 = 0.0317 (in both!)
        - IA-2: 0 + 1/(60+1) = 0.0159 (only in BM25)
        
        Final ranking by RRF score (highest first):
        1. SC-7 (0.0317) - appeared in both methods
        2. AC-2 (0.0159)
        3. IA-2 (0.0159)
        
        Returns:
            List of control texts (strings) that are relevant to the query
            These are passed to the LLM as context for analysis
        """
        # RRF constant (standard value from literature)
        k_constant = 60
        
        # Store rankings: {control_content: {'faiss_rank': rank, 'bm25_rank': rank}}
        # rank = 0 means not found in that method (will be excluded from RRF)
        rankings = {}

        # ========== DENSE RETRIEVAL (FAISS) ==========
        # Semantic similarity: find controls by meaning
        
        if self.faiss_store:
            try:
                # similarity_search() finds k documents most similar to query
                # FAISS automatically converts query to embedding and searches
                docs = self.faiss_store.similarity_search(query, k=5)
                
                for rank, d in enumerate(docs, start=1):
                    content = d.page_content  # Control text
                    
                    # Format control if needed (ensure "ID: Summary" format)
                    if ':' not in content[:20]:
                        # Extract first sentence as ID/summary if no colon
                        parts = content.split('\n', 1)
                        formatted = parts[0] if len(parts) > 0 else content
                    else:
                        formatted = content
                    
                    # Initialize ranking dict for this control
                    if formatted not in rankings:
                        rankings[formatted] = {'faiss_rank': 0, 'bm25_rank': 0}
                    
                    # Store FAISS rank
                    rankings[formatted]['faiss_rank'] = rank
                    
                print(f"DEBUG: FAISS returned {len([c for c in rankings.values() if c['faiss_rank'] > 0])} controls", flush=True)
            except Exception as e:
                print(f"Dense retrieval error: {e}")

        # ========== SPARSE RETRIEVAL (BM25) ==========
        # Keyword matching: find controls by terms
        
        if self.bm25_index and self.control_corpus:
            try:
                # Tokenize query (lowercase and split)
                tokens = query.lower().split()
                
                # Get BM25 scores for all controls
                scores = self.bm25_index.get_scores(tokens)
                
                # Get top 5 indices by score
                top_idx = np.argsort(scores)[-5:][::-1]  # Reverse to get highest first
                
                for rank, i in enumerate(top_idx, start=1):
                    # Only include if score > 0 (actually matched some terms)
                    if scores[i] > 0:
                        content = self.control_corpus[i]
                        
                        # Format control if needed
                        if ':' not in content[:20]:
                            parts = content.split('\n', 1)
                            formatted = parts[0] if len(parts) > 0 else content
                        else:
                            formatted = content
                        
                        # Initialize ranking dict if not already present
                        if formatted not in rankings:
                            rankings[formatted] = {'faiss_rank': 0, 'bm25_rank': 0}
                        
                        # Store BM25 rank
                        rankings[formatted]['bm25_rank'] = rank
                
                print(f"DEBUG: BM25 returned {len([c for c in rankings.values() if c['bm25_rank'] > 0])} controls", flush=True)
            except Exception as e:
                print(f"BM25 retrieval error: {e}")

        # ========== RRF SCORING ==========
        # Calculate RRF score for each control: sum of 1/(k + rank) for each method
        rrf_scores = {}
        for control, ranks in rankings.items():
            rrf_score = 0.0
            
            # Add FAISS contribution: 1 / (k + faiss_rank)
            if ranks['faiss_rank'] > 0:
                rrf_score += 1.0 / (k_constant + ranks['faiss_rank'])
            
            # Add BM25 contribution: 1 / (k + bm25_rank)
            if ranks['bm25_rank'] > 0:
                rrf_score += 1.0 / (k_constant + ranks['bm25_rank'])

            # Dynamic RRF penalty from dismissed history for this control.
            control_id = self._normalize_control_id(self._extract_control_id(control))
            penalty = self.control_rrf_penalties.get(control_id, 0.0)
            if penalty > 0:
                rrf_score *= (1.0 - penalty)
            
            rrf_scores[control] = rrf_score
        
        # Sort controls by RRF score (highest first)
        sorted_controls = sorted(rrf_scores.items(), key=lambda x: x[1], reverse=True)
        
        # Debug: Log RRF scores
        print(f"DEBUG: RRF Scores (top {min(top_k, len(sorted_controls))}):", flush=True)
        for control, score in sorted_controls[:top_k]:
            faiss_r = rankings[control]['faiss_rank']
            bm25_r = rankings[control]['bm25_rank']
            control_preview = control[:80] + "..." if len(control) > 80 else control
            print(f"  {control_preview}", flush=True)
            print(f"    FAISS rank: {faiss_r if faiss_r > 0 else 'N/A'}, BM25 rank: {bm25_r if bm25_r > 0 else 'N/A'}, RRF: {score:.4f}", flush=True)
        
        if return_scores:
            return sorted_controls[:top_k]

        # Return top_k controls by RRF score
        return [control for control, score in sorted_controls[:top_k]]
