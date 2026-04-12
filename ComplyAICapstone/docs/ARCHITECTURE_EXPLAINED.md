# ComplyAI Advanced RAG Architecture - Complete Explanation

## Overview

ComplyAI is a **Retrieval-Augmented Generation (RAG)** system that analyzes security policy documents to identify NIST compliance gaps. It combines vector search, keyword matching, and LLM understanding to provide accurate, grounded compliance findings.

---

## System Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         FRONTEND (index.html)                            │
│  - Upload PDF form                                                      │
│  - Real-time progress bar (1-second polling)                           │
│  - Display consolidated findings in sidebar                            │
└──────────────────────────────┬──────────────────────────────────────────┘
                               │ HTTP Requests
                               ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    FLASK BACKEND (app.py)                               │
│  - /upload: Save PDF to disk                                           │
│  - /analyze: Trigger RAG pipeline, receive findings                    │
│  - /progress: Poll for batch progress updates                          │
│  - ANALYSIS_STATUS: In-memory tracking of analysis state               │
└──────────────────────────────┬──────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────────┐
│              ADVANCED RAG ENGINE (rag/advanced_rag.py)                  │
│                                                                          │
│  1. PDF LOADING & SEGMENTATION                                          │
│     - Load PDF → Extract text per page                                 │
│     - Sentence segmentation using pysbd (smart boundary detection)     │
│     - Filter out headings/section titles                               │
│                                                                          │
│  2. HYBRID RETRIEVAL (Dense + Sparse)                                  │
│     ┌────────────────────────────────────────────────────────────────┐ │
│     │ FAISS (Dense Vector Search)                                    │ │
│     │ - 820 NIST controls pre-embedded (semantic meaning)            │ │
│     │ - Given batch text, find top 5 semantically similar controls  │ │
│     │ - Example: "weak auth" → finds AC-2, AC-3                     │ │
│     └────────────────────────────────────────────────────────────────┘ │
│     ┌────────────────────────────────────────────────────────────────┐ │
│     │ BM25 (Sparse/Keyword Search)                                  │ │
│     │ - Keyword-based ranking (TF-IDF style)                        │ │
│     │ - Given batch text, find top 5 keyword-matching controls      │ │
│     │ - Example: "password" → finds SC-2, IA-5                      │ │
│     └────────────────────────────────────────────────────────────────┘ │
│     → Deduplicate and return top 5 combined controls                  │
│                                                                          │
│  3. BATCH PROCESSING                                                    │
│     - Split all sentences into batches of 20 (not 8!)                 │
│     - Reason: Larger context window reduces hallucinations            │
│     - For each batch:                                                 │
│       a) Hybrid retrieve relevant controls                            │
│       b) Send batch + controls to LLM                                 │
│       c) LLM returns findings as JSON                                 │
│       d) Extract and collect findings                                 │
│       e) Update progress callback                                     │
│                                                                          │
│  4. EXTRACTIVE PROMPTING                                               │
│     - "Copy EXACT text from policy as evidence"                      │
│     - "NO INVENTIONS: Don't assume risks not mentioned"              │
│     - "REAL GAPS ONLY: Flag explicit gaps, not neutral statements"   │
│     - LLM returns: {compliant, source_quote, control_id, risk_level} │
│                                                                          │
│  5. POST-PROCESSING & FILTERING                                        │
│     ┌────────────────────────────────────────────────────────────────┐ │
│     │ a) Deduplication                                              │ │
│     │    Remove duplicate findings (same sentence, page, quote)     │ │
│     │    Keeps findings from different contexts separate            │ │
│     └────────────────────────────────────────────────────────────────┘ │
│     ┌────────────────────────────────────────────────────────────────┐ │
│     │ b) Confidence Filtering (threshold: 0.5)                      │ │
│     │    Only keep findings where LLM confidence ≥ 50%              │ │
│     │    Removes low-confidence/uncertain findings                  │ │
│     └────────────────────────────────────────────────────────────────┘ │
│     ┌────────────────────────────────────────────────────────────────┐ │
│     │ c) False Positive Filtering (0.80 similarity)                 │ │
│     │    Detects: "Policy says implement MFA" (just restating control)│ │
│     │    Removes findings >80% similar to control definition        │ │
│     │    Keeps real gaps: "MFA not required" (actual non-compliance) │ │
│     └────────────────────────────────────────────────────────────────┘ │
│     ┌────────────────────────────────────────────────────────────────┐ │
│     │ d) Consolidation (Group by control_id)                        │ │
│     │    Multiple findings for same NIST control → 1 card           │ │
│     │    Highest risk level: Critical > High > Moderate > Low       │ │
│     │    Combine reasons & recommendations with pipes (|)           │ │
│     │    Average confidence across group                            │ │
│     └────────────────────────────────────────────────────────────────┘ │
│                                                                          │
│  6. OUTPUT FORMATTING                                                   │
│     Return list of consolidated findings:                             │
│     [                                                                  │
│       {                                                                │
│         "control_id": "AC-2(1)",                                       │
│         "control_summary": "...",                                      │
│         "risk_level": "Critical",                                      │
│         "affected_pages": [1, 2, 3],                                   │
│         "example_quote": "exact text from policy",                     │
│         "consolidated_reason": "reason | another reason",             │
│         "consolidated_recommendation": "fix | alternative fix",        │
│         "confidence": 0.85                                             │
│       }                                                                │
│     ]                                                                  │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Key Components Explained

### 1. app.py - Flask Backend

**Purpose**: HTTP server handling user requests and managing analysis state.

**Key Functions**:
- `upload_file()`: Saves uploaded PDF securely
- `analyze_file()`: Triggers RAG analysis via callback mechanism
- `progress()`: Returns real-time batch progress (enables progress bar)
- `progress_callback()`: Called by RAG engine after each batch completes

**Flow**:
```
User clicks "Analyze" 
  → POST /analyze {filename}
  → Initialize ANALYSIS_STATUS[filename] = {processed_batches: 0, total_batches: X}
  → Call rag.analyze_policy_pdf(pdf_path, progress_callback)
  
While analysis runs:
  Frontend polls /progress every 1 second
  → Returns {processed_batches: N, total_batches: X, percentage: N/X*100}
  
When LLM finishes each batch:
  progress_callback(current_batch, total_batches) updates ANALYSIS_STATUS
  Frontend sees progress bar increment
  
When all batches done:
  Consolidation completes
  POST /analyze returns results as JSON
  Frontend displays findings in sidebar
```

---

### 2. advanced_rag.py - RAG Engine (Core Logic)

#### Class: AdvancedRAGEngine

**Initialization**:
```python
rag = AdvancedRAGEngine(
    embedding_model="qwen3-embedding",    # Generate embeddings
    llm_model="saki007ster/...",          # Analyze with LLM
    vector_store_path="./faiss_index"     # Load pre-built FAISS
)
```

**Loads**:
- FAISS index: 820 NIST controls with embeddings
- BM25 index: Built from same 820 controls (tokenized)
- Ollama models: Local embedding + LLM models

#### Main Methods

##### `analyze_policy_pdf(pdf_path, progress_callback)`

**Entry point** called by app.py. Orchestrates entire analysis pipeline.

**Steps**:
1. Load PDF and extract sentences (pysbd segmentation)
2. Call `_analyze_all_sentences()` with batch processing
3. Deduplicate findings (by sentence, page, quote)
4. Filter by confidence (≥ 0.5)
5. Remove false positives (>80% similar to control)
6. Consolidate findings (group by control_id)
7. Return JSON array of consolidated findings

**Returns**: List[dict] with consolidated findings for frontend

---

##### `_analyze_all_sentences(all_sentences, progress_callback)`

**Batch Processing Engine** - The heart of Advanced RAG.

**Key Variables**:
- `batch_size = 20`: Process 20 sentences per batch (not 8!)
- `total_batches = ceil(len(all_sentences) / 20)`

**For each batch**:

1. **Hybrid Retrieval**:
   ```python
   batch_text = " ".join(sentences)  # Combine 20 sentences
   relevant_controls = self._hybrid_retrieve(batch_text, top_k=5)
   # Returns: [AC-2: "...", SC-7: "...", ...] (top 5 controls)
   ```

2. **Format Batch for LLM**:
   ```
   1. (Page 1) We authenticate users with username and password.
   2. (Page 1) Multi-factor authentication is not required.
   3. (Page 1) Password reuse is allowed for user convenience.
   ```

3. **Extractive Prompt** (ensures grounding):
   ```
   SYSTEM: You are a strict NIST auditor analyzing ONLY explicit policy text.
   
   NIST CONTROL DEFINITIONS:
   AC-2: Implement authentication mechanisms...
   SC-7: Implement cryptographic controls...
   
   POLICY TEXT:
   [batch of 20 statements]
   
   RULES:
   1. VERBATIM QUOTES: Must copy exact text from policy
   2. NO INVENTIONS: Don't assume risks not mentioned
   3. NO INFERENCE: Only flag explicit gaps
   4. REAL GAPS ONLY: Ignore neutral statements
   
   Return JSON array: [{"compliant": false, "source_quote": "...", ...}]
   ```

4. **Call Local LLM**:
   ```python
   resp = ollama.generate(model=self.llm_model, prompt=prompt)
   raw_text = resp.get("response", "")
   ```

5. **Extract Findings**:
   ```python
   batch_findings = self._extract_findings_from_response(raw_text)
   # Returns: [GapFinding(...), GapFinding(...), ...]
   ```

6. **Update Progress** (THIS HAPPENS AFTER BATCH COMPLETES):
   ```python
   progress_callback(current_batch, total_batches)
   # Tells frontend: "Batch 5/13 complete, show 38% progress"
   ```

---

##### `_hybrid_retrieve(query, top_k=5)`

**Combines Dense + Sparse Search** for better control matching.

```
Input: "Multi-factor authentication is not required for users"

FAISS Query (Dense/Semantic):
  - Converts query to embedding (768-dim vector)
  - Finds 5 controls most semantically similar
  - Returns: [AC-2, AC-3, IA-2, IA-5, SC-7]

BM25 Query (Sparse/Keyword):
  - Tokenizes: ["multi", "factor", "authentication", "required", "users"]
  - Matches controls containing these terms
  - Returns: [IA-2, IA-5, SC-2, AC-3, AC-1]

Deduplicate & Return Top 5:
  [AC-2, AC-3, IA-2, IA-5, SC-7]
```

**Why Both Methods?**
- FAISS alone: Misses acronyms (AC-2 vs "access control")
- BM25 alone: Misses synonyms (authentication vs identity management)
- Together: Catch semantics AND keywords

---

##### `_extract_findings_from_response(raw_text)`

**Parse LLM JSON Output** with error handling.

**Handles**:
- Markdown code blocks: ` ```json ... ``` `
- Raw JSON arrays: `[ { ... } ]`
- Multiple arrays in one response
- Malformed JSON (skip, continue)

**Output**: List[GapFinding] with extracted structured findings

---

##### `_consolidate_findings(findings)`

**Group Related Findings** by NIST control.

**Before Consolidation**:
```
Findings:
1. AC-2: "Users aren't authenticated" (confidence: 0.85)
2. AC-2: "Password reuse allowed" (confidence: 0.80)
3. SC-7: "No encryption" (confidence: 0.90)
```

**After Consolidation**:
```
GroupedFinding AC-2:
  - Highest risk: High (from both findings)
  - Affected pages: [1, 2]
  - Affected sentences: ["Users aren't authenticated", "Password reuse allowed"]
  - Consolidated reason: "Users aren't authenticated | Password reuse allowed"
  - Average confidence: 0.825

GroupedFinding SC-7:
  - Highest risk: Critical
  - Affected pages: [3]
  - ...
```

**Result**: Fewer, more digestible findings for frontend display

---

##### `_is_false_positive(sentence, control_summary, threshold=0.80)`

**Detect Control Restating** (not actual gaps).

**Example**:
```
Control: "Implement access control mechanisms"
Policy: "We follow NIST AC-2: Implement access control mechanisms"

Similarity: 95% similar → False positive (just stating compliance, not a gap)
→ Filtered out
```

**Example of Real Gap**:
```
Control: "Implement access control mechanisms"
Policy: "All users have access to all systems"

Similarity: 10% similar → Real gap
→ Kept
```

---

##### `_is_heading(text)`

**Detect Section Titles** (don't analyze).

**Heuristics**:
1. Too short (< 20 chars): "Policy" → likely heading
2. All caps: "SECURITY REQUIREMENTS" → likely heading
3. Few words (< 5): "Access Control" → likely heading
4. Ends with colon: "Results:" → likely heading
5. Numbered: "1. Overview", "A. Summary" → likely heading
6. Common keywords: starts with "Appendix", "Introduction", etc.
7. Title case + few words: "Security Requirements" → likely heading

**Purpose**: Avoid sending titles to LLM (wastes tokens, causes false positives)

---

### 3. nist_embedding.py - One-Time Setup

**Purpose**: Pre-build FAISS index of NIST controls.

**Process**:
1. Load all NIST PDF controls from `nist_docs/` folder
2. Split into 1000-char chunks (with 200-char overlap)
3. Generate embeddings using `qwen3-embedding` model
4. Build FAISS index from embeddings
5. Save to `faiss_index/` folder

**Run Once**: `python nist_embedding.py`

**Result**: 
- `faiss_index/index.faiss` (vector search structure)
- `faiss_index/index.pkl` (metadata)

This index is loaded at runtime by `AdvancedRAGEngine.__init__()`

---

## Advanced RAG Features Explained

### Why Batch Processing (20 sentences)?

**Problem with Single-Sentence Analysis**:
```
Sentence 1: "We use password authentication"
→ LLM sees only this
→ Marks as COMPLIANT (standard practice)
→ Misses the context

Sentence 2: "Multi-factor authentication is not required"
→ LLM would see only this
→ Also marks as COMPLIANT (just stating fact)
→ But together with Sentence 1, it's a GAP!
```

**Solution - Batch Processing (20 sentences)**:
```
Batch:
1. "We use password authentication"
2. "Multi-factor authentication is not required"
3. "Users log in from untrusted networks"
4. "Compliance is not checked on login"
...

LLM sees FULL CONTEXT:
→ Weak auth (password only) + no MFA + untrusted networks = HIGH RISK
→ Correctly identifies compliance gap
→ Reduces hallucinations (invented requirements)
```

### Why Hybrid Retrieval?

**Example Query**: "No multi-factor authentication"

**FAISS Alone**:
- Finds: AC-2, AC-3, IA-2 (semantic match)
- Misses: IA-5 (password policy - keyword-matched with BM25)

**BM25 Alone**:
- Finds: IA-5, IA-2, SC-2 (keyword match)
- Misses: AC-2 (semantic match but fewer keywords)

**Hybrid**:
- Combines both approaches
- Catches both semantic AND keyword matches
- More comprehensive control suggestions

### Why Extractive Prompting?

**Problem with Generative Prompts**:
```
Prompt: "Analyze this policy for compliance gaps"
→ LLM: "The policy lacks a 72-hour password hashing requirement"
→ But policy NEVER mentions this!
→ Hallucination (made-up requirement)
```

**Solution - Extractive Prompt**:
```
Prompt: "Copy EXACT text from policy that indicates non-compliance"
→ LLM must find actual quote
→ LLM: "Policy says 'passwords can be reused'"
→ No hallucination (grounded in text)
```

### Why Multi-Stage Filtering?

**Stage 1 - Confidence (≥ 0.5)**:
- Removes uncertain findings
- Only keeps findings LLM is reasonably confident about

**Stage 2 - False Positives (0.80 similarity)**:
- Detects findings that just repeat control definitions
- Removes noise while keeping real gaps

**Stage 3 - Consolidation**:
- Groups related findings by NIST control
- Shows highest risk level + combined recommendations
- Much cleaner output for user

---

## Progress Bar Flow

### How Frontend Shows Progress

**Polling Loop** (1-second intervals):
```javascript
// Every 1 second:
fetch("/progress?filename=xyz.pdf")
  .then(data => {
    // data = {status: "running", processed_batches: 5, total_batches: 13, percentage: 38}
    progressBar.style.width = "38%"
    progressText = "Processing batch 5/13 (38%)"
  })
```

### How Backend Updates Progress

**In Batch Loop**:
```python
for batch in batches:
    # ... process batch with LLM ...
    
    # After batch completes:
    progress_callback(current_batch, total_batches)
    # → Updates ANALYSIS_STATUS[filename]["processed_batches"] = current_batch
    # → Frontend polls and sees new value
    # → Progress bar increments
```

**Key Point**: Progress updates AFTER batch completes (not before)
- Before: "About to process batch 5"
- After: "Batch 5 finished, results received"

---

## Performance Metrics

**For 3-page policy (138 sentences)**:

| Metric | Value |
|--------|-------|
| Batches | ~7 (138 / 20 per batch) |
| Time per batch | 5-15 seconds (LLM inference) |
| Total analysis time | 45-105 seconds |
| Typical findings | 20-40 gaps |
| Consolidated findings | 10-20 groups |
| Progress granularity | ~14% per batch (1/7) |

---

## Error Handling

### LLM Failure
```python
try:
    resp = ollama.generate(model=llm_model, prompt=prompt)
except Exception as e:
    # Still update progress so frontend doesn't hang
    progress_callback(current_batch, total_batches)
    # Continue to next batch
```

### JSON Parse Failure
```python
try:
    arr = json.loads(array_text)
except json.JSONDecodeError:
    # Skip this array, continue with next
    continue
```

### FAISS Load Failure
```python
try:
    self.faiss_store = FAISS.load_local(...)
except:
    print("⚠ Could not load FAISS store")
    self.faiss_store = None
    # System still works with BM25 only (degraded mode)
```

---

## Security Considerations

1. **File Upload**: Uses `secure_filename()` to prevent path traversal
2. **File Type**: Only PDF files allowed
3. **Temporary Storage**: Files saved to `uploads/` folder (isolated)
4. **No API Keys**: All models run locally (Ollama)
5. **No Data Transmission**: Everything stays on local machine

---

## Future Enhancements

1. **Batch Size Optimization**: Auto-adjust based on GPU memory
2. **Caching**: Cache embeddings to avoid re-computing
3. **Custom Prompts**: Allow users to customize analysis rules
4. **Export**: PDF/CSV report generation
5. **Multi-Model Support**: Allow users to choose different LLMs
6. **Fine-tuning**: Train on org-specific policies
7. **Continuous Analysis**: Monitor policies for compliance over time

---

## Glossary

| Term | Definition |
|------|-----------|
| RAG | Retrieval-Augmented Generation - combine search + LLM |
| FAISS | Facebook AI Similarity Search - vector database |
| BM25 | Okapi BM25 - probabilistic ranking function |
| pysbd | Python Sentence Boundary Detector |
| Embedding | Vector representation of text (768-dim for qwen3) |
| Hybrid | Combining multiple approaches (dense + sparse) |
| Consolidation | Grouping related findings by NIST control |
| False Positive | Finding that's actually compliant (not a real gap) |
| Grounding | Using actual text as evidence (not hallucinating) |
| Extractive | Copying from source (vs. generative/creating new) |
| Batch | Group of sentences processed together (20 in this system) |
| Progress Callback | Function called after each batch completes |

---

## Questions?

Each Python file is now fully commented with detailed explanations of how Advanced RAG works.

Look at:
- `app.py` for HTTP request handling
- `nist_embedding.py` for FAISS setup
- `advanced_rag.py` for RAG pipeline details
