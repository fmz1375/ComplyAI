# ComplyAI

A NIST CSF Cybersecurity Compliance Assessment Platform with AI-Powered Analysis

---

## Quick Start Guide 

### Prerequisites

- **Python 3.10+** installed
- **Ollama** installed and running (https://ollama.com)
- Git (for cloning the repository)

### Installation Steps

1. **Clone the repository**
   ```bash
   git clone https://github.com/YOUR_USERNAME/complyai.git
   cd complyai
   ```

2. **Create and activate a virtual environment**
   ```bash
   # Windows
   python -m venv .venv
   .venv\Scripts\activate

   # macOS/Linux
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install Python dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Pull required Ollama models** (run these commands in a separate terminal)
   ```bash
   ollama pull qwen2.5:3b
   ollama pull saki007ster/CybersecurityRiskAnalyst
   ```

5. **Start the application**
   ```bash
   python appOne.py
   ```

6. **Open your browser** and navigate to:
   ```
   http://127.0.0.1:5005
   ```

### Default Login Credentials

| Role  | Email              | Password  |
|-------|--------------------|-----------|
| Admin | admin@example.com  | admin123  |
| User  | bob@example.com    | bob123    |

**Admin** can do everything User can, plus:
- View all users' documents
- Review and approve/reject documents
- Manage users (add/delete)
- Framework management
- Access admin dashboard

**User** capabilities:
- Upload and manage own documents
- Run compliance analysis
- Generate reports (PDF/Word)
- Use calendar, notes, and chat
- Access shared documents

### Key Features to Test

1. **Upload a Policy Document**
   - Navigate to "Upload Document" from the sidebar
   - Select a PDF security policy document (e.g., Information Security Policy, Incident Response Plan)
   - Fill in metadata: document name, category, priority, and due date
   - The system extracts text and prepares for AI analysis

2. **Run Compliance Analysis**
   - After upload, click "Analyze" to start the AI-powered gap detection
   - Watch real-time progress as the system processes your document
   - Uses Advanced RAG with FAISS + BM25 hybrid retrieval to identify NIST CSF gaps
   - Review identified gaps with severity ratings (Critical, High, Medium, Low)
   - Provide feedback on findings to improve future accuracy

3. **Complete NIST CSF Questionnaire**
   - Access from the document analysis page or dashboard
   - Choose which NIST CSF functions to assess (Govern, Identify, Protect, Detect, Respond, Recover)
   - Answer structured questions about your organization's security posture
   - Supports multiple question types: multiple choice, yes/no, scale ratings, and text responses
   - Progress is saved automatically

4. **Generate Reports**
   - After completing questionnaire and/or analysis, generate comprehensive reports
   - Choose export format: PDF or Word (DOCX)
   - Reports include: executive summary, compliance gaps, risk assessment, and recommendations
   - Edit report content before finalizing using the built-in editor
   - Share reports with team members or download for offline use

5. **Risk Heat Map**
   - Access from the document viewer or report page
   - Complete the Risk Appetite questionnaire to set your organization's risk tolerance
   - View 5x5 matrix showing likelihood vs. impact for each identified risk
   - Items exceeding risk appetite are clearly highlighted
   - Download heat map as PNG image for presentations

6. **Real-time Collaboration**
   - Share documents with team members via email invitation or shareable link
   - Set permissions: view-only, comment, or full edit access
   - Use real-time chat within document assessment rooms
   - Direct messaging (DM) for private conversations with colleagues
   - See who's online and typing indicators

### Project Structure Overview

```
complyai/
├── appOne.py              # Main Flask application (entry point)
├── requirements.txt       # Python dependencies
├── project.db            # SQLite database (auto-created)
├── templates/            # HTML templates (Jinja2)
├── services/             # Business logic services
│   ├── llm_service.py           # LLM integration
│   ├── questionnaire_engine.py  # NIST questionnaire logic
│   ├── report_exporter.py       # PDF/Word export
│   └── risk_heatmap_service.py  # Risk visualization
├── rag/                  # RAG (Retrieval-Augmented Generation)
│   └── advanced_rag.py          # Hybrid retrieval + gap analysis
├── models/               # Pydantic data models
├── faiss_index/          # Vector store indexes
├── uploads/              # Uploaded documents
└── exports/              # Generated reports and artifacts
```

### Troubleshooting

- **"Ollama not available" warning**: Make sure Ollama is running (`ollama serve`)
- **Port already in use**: Change the port in `appOne.py` or kill the existing process
- **Missing dependencies**: Run `pip install -r requirements.txt` again

---

## Security Features

ComplyAI implements comprehensive security hardening to protect against common attack vectors:

### 🛡️ Attack Prevention

| Attack Type | Protection Method | Implementation |
|-------------|-------------------|----------------|
| **SQL Injection** | Parameterized queries + table whitelist | `security_utils.SQLInjectionDefense` |
| **Prompt Injection** | Input sanitization + pattern detection | `security_utils.PromptInjectionDefense` |
| **Buffer Overflow** | Input length limits (5000 chars max) | `security_utils.InputValidation` |
| **SSRF** | URL validation + private IP blocking | `security_utils.InputValidation.validate_url()` |
| **XSS** | Jinja2 auto-escaping | Flask templates |

### Security Utilities (`security_utils.py`)

```python
# Prompt Injection Defense
from security_utils import PromptInjectionDefense
safe_input = PromptInjectionDefense.sanitize_user_input(user_input)

# SQL Injection Defense  
from security_utils import SQLInjectionDefense
SQLInjectionDefense.validate_table_name(table_name)  # Whitelist validation

# Input Validation
from security_utils import InputValidation
InputValidation.validate_string(value, max_length=5000)
InputValidation.validate_url(url)  # Blocks localhost, private IPs, AWS metadata
```

### Protected Components

- **LLM Service** - All user inputs sanitized before prompt inclusion
- **Context Builder** - Prompt injection patterns detected and neutralized
- **RAG Chatbot** - User queries and conversation history sanitized
- **Database Operations** - Parameterized queries throughout
- **Framework Service** - URL validation for external framework sources

### Password Security

- Passwords hashed using `werkzeug.security.generate_password_hash`
- Secure session management with Flask sessions
- Optional Auth0 SSO integration for enterprise authentication

---

## Technical Documentation

ComplyAI is a Flask-based cybersecurity assessment platform that combines:

- policy document analysis with Advanced RAG
- structured NIST CSF questionnaires
- LLM-generated compliance reporting
- risk appetite and risk heat-map workflows
- real-time collaboration and direct messaging
- framework versioning with dynamic FAISS index switching

This README is a full technical walkthrough of how the system is implemented.

## 1. Architecture At A Glance

### Runtime layers

1. Presentation/UI layer
- Jinja templates in `templates/`
- HTML/JS clients call REST APIs and Socket.IO channels

2. HTTP/API layer
- Single Flask application in `appOne.py`
- Route groups: auth, upload/analysis, questionnaire/reporting, frameworks, heat-map, DM/collab

3. Realtime layer
- Flask-SocketIO events implemented in `appOne.py`
- Presence, room chat, typing events, direct messaging

4. Domain services layer
- `services/questionnaire_engine.py`
- `services/context_builder.py`
- `services/llm_service.py`
- `services/risk_heatmap_service.py`
- `services/report_exporter.py`
- `services/framework_service.py`
- `services/collaboration_service.py`

5. AI/RAG layer
- `rag/advanced_rag.py` for hybrid retrieval + gap extraction
- `rag_chatbot.py` for standalone policy chatbot

6. Persistence layer
- SQLite database: `project.db`
- FAISS indexes: `faiss_index/`
- uploads: `uploads/`
- generated artifacts: `exports/`

### Main runtime entrypoint

- App process starts from `appOne.py`
- Socket server starts with:

```python
if __name__ == "__main__":
		socketio.run(app, debug=True, host="127.0.0.1", port=5005)
```

## 2. Startup And Boot Sequence

During startup, `appOne.py` performs the following major actions:

1. Flask app setup and API-safe exception handlers
- API routes return JSON errors for `HTTPException` and unhandled errors.

2. DB initialization for collaboration tables
- `init_db()` creates base collaboration and feedback tables if missing.

3. Default admin seeding
- `ensure_default_admin_user()` enforces a default admin account (`admin@example.com` / `admin123`).

4. Framework migration + framework service init
- framework migration called from `migrations/create_framework_table.py`
- `FrameworkService.init()` ensures required directories and config tables

5. Service object creation
- `AdvancedRAGEngine`, `QuestionnaireEngine`, `LLMService`, `ReportExporter`, `RiskHeatMapService`

6. SocketIO initialization
- CORS enabled and threading async mode used

## 2.1 Auth0 SSO Setup (Optional)

ComplyAI supports Single Sign-On (SSO) authentication via Auth0. To enable SSO:

1. Create an Auth0 account and application at https://auth0.com
2. Configure the following environment variables in a `.env` file:

```bash
# Auth0 Configuration
AUTH0_DOMAIN=your-domain.auth0.com
AUTH0_CLIENT_ID=your-client-id
AUTH0_CLIENT_SECRET=your-client-secret
AUTH0_CALLBACK_URL=http://localhost:5000/callback
AUTH0_AUDIENCE=your-api-identifier

# Flask Configuration
FLASK_SECRET_KEY=your-secure-secret-key-here
FLASK_ENV=development
```

3. Copy `.env.example` to `.env` and fill in your Auth0 credentials
4. Install dependencies: `pip install -r requirements.txt`
5. Run the application: `python appOne.py`

When Auth0 is configured, users will see an SSO login button. If Auth0 credentials are missing, the app falls back to local username/password authentication.

## 3. Core Technical Components

### 3.1 Advanced RAG Engine (`rag/advanced_rag.py`)

`AdvancedRAGEngine` is the core compliance-gap extractor.

Implementation behavior:

1. PDF loading and sentence segmentation
- Uses `PyPDFLoader` (LangChain Community) for page extraction.
- Uses `pysbd` sentence boundary detection (better than naive splitting).

2. Batch analysis
- Default `batch_size=20` sentences.
- Each batch is analyzed against retrieved control candidates.

3. Hybrid retrieval
- Dense retrieval via FAISS (`langchain_community.vectorstores.FAISS`)
- Sparse retrieval via BM25 (`rank_bm25.BM25Okapi`)

4. RRF fusion
- Retrieval results are merged with Reciprocal Rank Fusion (RRF).
- Controls that rank well in both FAISS and BM25 are prioritized.

5. LLM extraction
- Batch text + retrieved controls are sent to Ollama model.
- Engine extracts structured findings and parses JSON payloads.

6. Post-processing pipeline
- deduplicate findings
- confidence threshold filtering
- false-positive filtering by semantic similarity
- consolidation by `control_id` into grouped findings

7. Human feedback suppression loop
- Reads dismissed-gap embeddings from SQLite (`gap_feedback`).
- Applies control-specific penalties and pattern suppression to reduce recurring false positives.

Primary output objects:

- `GapFinding` (raw finding)
- `GroupedFinding` (frontend/report-friendly consolidated finding)

### 3.2 Framework Lifecycle And Dynamic Retrieval (`services/framework_service.py`)

`FrameworkService` supports active framework version management, ingestion, and atomic activation.

Key responsibilities:

1. Framework config/version resolution
- `get_config()`, `get_framework_version()`, `get_active_framework_version()`, `resolve_framework()`

2. Source ingestion
- PDF and JSON ingestion paths
- URL download support

3. Index build
- splits source docs via `RecursiveCharacterTextSplitter`
- generates embeddings via `OllamaEmbeddings`
- builds FAISS index and saves to versioned/"shadow" folder

4. Activation and status transitions
- processing/ready-style status updates in `framework_config`
- audit logging to `framework_audit_log`

5. Concurrency guard
- class-level lock to prevent concurrent rebuild collisions

When framework activation changes the vector-store path, the app reloads/uses the updated RAG configuration for new analyses.

### 3.3 Questionnaire Engine (`services/questionnaire_engine.py`)

`QuestionnaireEngine` manages NIST CSF question generation and answer validation.

Important implementation details:

1. Question source strategy
- attempts to load `NIST CSF Compliance Questionnaire.html`
- falls back to built-in sample catalog if parsing fails

2. Function-scoped generation
- supports NIST CSF functions:
	- Govern
	- Identify
	- Protect
	- Detect
	- Respond
	- Recover

3. Question metadata
- each question carries function/category/subcategory/type/order and required flag

4. Answer processing
- converts incoming payloads to typed `QuestionAnswer` models
- enforces answer validity and normalized structure

### 3.4 Context Construction (`services/context_builder.py`)

`ContextBuilder` creates prompt-ready analysis context for report generation.

How context is built:

1. questionnaire normalization and risk-indicator extraction
2. organization metadata flattening
3. NIST context injection (default context if none supplied)
4. dynamic analysis instruction composition
5. final single prompt assembly with schema expectations

Configuration switch:

- `COMPLYAI_COMPACT_PROMPT` toggles compact vs full instruction style

### 3.5 LLM Report Synthesis (`services/llm_service.py`)

`LLMService` generates `FinalReport` objects from document + questionnaire context.

Pipeline:

1. model readiness validation (`ollama.list()`)
2. fallback model selection if configured model unavailable
3. prompt generation through `ContextBuilder`
4. LLM call with retry + exponential backoff
5. JSON extraction and schema section checks
6. Pydantic model mapping into `FinalReport`

Key technical behaviors:

- default model: `qwen2.5:3b`
- max tokens controlled by `COMPLYAI_MAX_TOKENS` (default 4096)
- strict JSON response handling and parsing safeguards

### 3.6 Risk Heat Map Service (`services/risk_heatmap_service.py`)

`RiskHeatMapService` generates risk matrices and visual artifacts.

Capabilities:

1. Convert compliance gaps into `HeatMapItem` objects
2. Calculate risk levels from likelihood x impact scores
3. Evaluate whether item exceeds appetite profile
4. Generate 5x5 matrix PNG using matplotlib (`Agg` backend)
5. Return typed `HeatMapReport` with summary and image path

Artifacts are written under `exports/`.

### 3.7 Collaboration And DM Service (`services/collaboration_service.py`)

`CollaborationService` encapsulates DB-backed chat/collab operations.

Supported domains:

1. assessment room messaging
2. participant management and online state updates
3. invite lifecycle tracking
4. report version tracking metadata
5. direct messages (DM) + conversation summaries + read status

## 4. API And Event Surface

High-value route groups are all implemented in `appOne.py`.

### 4.1 Document + analysis endpoints

- `POST /upload`
- `POST /analyze`
- `GET /progress`

`ANALYSIS_STATUS` keeps process-local analysis progress and result metadata.

### 4.2 Questionnaire + reporting endpoints

- `GET /api/nist-functions`
- `POST /api/generate-questions`
- `POST /api/submit-answers`
- `GET /api/report-progress`
- `GET /api/reports/<report_id>`

`QUESTIONNAIRE_SESSIONS`, `REPORT_STATUS`, and `REPORTS` are in-memory runtime stores.

### 4.3 Risk appetite + heat-map endpoints

- `GET /api/risk-appetite-questions`
- `GET /api/heatmap-template`
- `POST /api/submit-risk-appetite`
- `POST /api/submit-heatmap-items`
- `POST /api/generate-heatmap`
- `POST /api/generate-heatmap-from-gaps`
- `GET /api/heatmap-report/<report_id>`

`HEATMAP_REPORTS` caches generated heat-map report objects in-process.

### 4.4 Framework management endpoints

- `GET /api/framework/status`
- `POST /api/framework/upload`
- `GET /api/framework/versions`
- `POST /api/framework/activate`
- `GET /api/framework/audit_logs`

### 4.5 Collaboration + DM endpoints

- room collaboration and finding calibration endpoints
- DM REST endpoints:
	- `GET /api/dm/users`
	- `GET /api/dm/conversations`
	- `GET /api/dm/messages/<other_user_id>`
	- `POST /api/dm/messages`
	- `POST /api/dm/messages/<other_user_id>/read`

### 4.6 Socket.IO events

Room collaboration events:

- `join_session`
- `send_message`
- `typing`
- `mark_read`
- `disconnect`

Direct messaging events:

- `dm_connect`
- `dm_send_message`
- `dm_typing`
- `dm_stop_typing`

## 5. Data Architecture

### 5.1 Persistent stores

1. SQLite (`project.db`)
- user/auth/doc tables (legacy app area)
- collaboration tables
- framework config/version/audit tables
- feedback calibration tables (`finding_feedback`, `gap_feedback`)

2. Vector storage
- FAISS index folders in `faiss_index/`
- active index path can be switched via framework activation

3. Filesystem artifacts
- uploaded PDFs: `uploads/`
- generated report/heatmap exports: `exports/`

### 5.2 Key tables created/used

Collaboration and sharing:

- `collaborators`
- `share_links`
- `share_link_access_log`
- `chat_messages`
- `assessment_participants`
- `assessment_invites`
- `report_versions`
- `message_read_status`
- `direct_messages`
- `dm_conversations`

Framework and control lifecycle:

- `framework_config`
- `framework_versions`
- `framework_audit_log`

Feedback and tuning:

- `finding_feedback`
- `gap_feedback`

### 5.3 In-memory runtime state

Process-local structures in `appOne.py`:

- `ANALYSIS_STATUS`
- `REPORT_STATUS`
- `REPORTS`
- `QUESTIONNAIRE_SESSIONS`
- `HEATMAP_REPORTS`
- socket presence maps for chat and DM

Important limitation:

- all in-memory state resets on process restart
- multi-instance deployment needs shared state (for example Redis + shared session backend)

## 6. End-To-End Processing Flows

### 6.1 Policy analysis flow

1. User uploads PDF
2. `POST /analyze` initializes progress state
3. Advanced RAG runs batch analysis with callback updates
4. UI polls `GET /progress`
5. Consolidated findings returned for UI and later report merge

### 6.2 Questionnaire-to-report flow

1. UI fetches function metadata (`/api/nist-functions`)
2. UI creates questionnaire session (`/api/generate-questions`)
3. UI submits answers (`/api/submit-answers`)
4. answers are validated/typed by `QuestionnaireEngine`
5. optional document text extraction is performed from uploaded PDF
6. `LLMService` generates structured report content
7. prior RAG findings are merged into gap set
8. report cached in `REPORTS` and exposed through report APIs

### 6.3 Heat-map generation flow

1. submit appetite profile
2. submit heat-map items (or derive from compliance gaps)
3. classify risk and appetite exceedance
4. render and persist PNG matrix in `exports/`
5. return `HeatMapReport`

### 6.4 Collaboration flow

1. client joins room with `join_session`
2. history + participant data emitted in `session_joined`
3. messages persisted to DB and broadcast with `new_message`
4. typing and presence events synchronize active users
5. DM subsystem handles private channels and read states

## 7. Data Models And Contracts

Typed report contracts are defined in `models/report_models.py` with Pydantic.

Major model groups:

1. Questionnaire models
- `QuestionAnswer`, `QuestionType`, `NISTFunction`

2. Compliance/risk models
- `ComplianceGap`, `RiskItem`, `Recommendation`, `ComplianceSummary`

3. Final report
- `FinalReport`

4. Risk appetite and heat-map models
- `RiskAppetiteProfile`, `HeatMapItem`, `HeatMapAnalysis`, `HeatMapReport`

These types provide schema consistency between service logic and API responses.

## 8. Dependencies And AI Models

Python package dependencies are declared in `requirements.txt`.

Core dependencies include:

- `flask`, `flask-cors`, `flask-socketio`
- `langchain`, `langchain-community`, `langchain-ollama`
- `faiss-cpu`, `rank-bm25`, `pysbd`, `pypdf`
- `pydantic`, `beautifulsoup4`
- `reportlab`, `python-docx`, `matplotlib`, `pandas`

Expected Ollama models:

- `qwen2.5:3b`
- `qwen3-embedding`
- `saki007ster/CybersecurityRiskAnalyst`

## 9. Local Setup

### Windows

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
ollama pull qwen2.5:3b
ollama pull qwen3-embedding
ollama pull saki007ster/CybersecurityRiskAnalyst
python appOne.py
```

### macOS/Linux

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
ollama pull qwen2.5:3b
ollama pull qwen3-embedding
ollama pull saki007ster/CybersecurityRiskAnalyst
python appOne.py
```

Default URL: `http://127.0.0.1:5005`

## 10. Operational Notes

### Monitoring and diagnostics

Useful checks:

1. Verify Ollama service/models
- `ollama serve`
- `ollama list`

2. Validate framework status and active version
- `/api/framework/status`
- `/api/framework/versions`

3. Confirm artifacts and directories
- `uploads/` for inbound docs
- `exports/` for report/heat-map outputs
- `faiss_index/` for vector assets

### Performance characteristics

- batch analysis reduces LLM calls versus sentence-by-sentence evaluation
- FAISS + BM25 improves retrieval recall and precision
- framework switching can trigger index reload overhead
- in-memory stores are fast but not durable

## 11. Security And Production Hardening

Current implementation is functional for local/dev, but production hardening is required.

Priority actions:

1. Replace hardcoded Flask secret key in `appOne.py`
2. Remove default admin seeding or gate it to local-only mode
3. Hash and salt credentials robustly (avoid plain text patterns)
4. Restrict CORS and Socket.IO origins
5. Add rate limiting for API and socket abuse controls
6. Externalize sessions/state (Redis or equivalent)
7. Move long-running analysis/report tasks to worker queue
8. Add centralized structured logging, metrics, and alerting
9. Apply least-privilege authorization checks consistently across admin APIs

## 12. Repository Guide

Primary implementation files:

- `appOne.py` - monolithic Flask app, routes, Socket.IO handlers
- `rag/advanced_rag.py` - Advanced RAG and post-processing logic
- `services/framework_service.py` - framework ingestion/version activation
- `services/questionnaire_engine.py` - question generation and answer processing
- `services/context_builder.py` - LLM context/prompt assembly
- `services/llm_service.py` - report generation and JSON validation
- `services/risk_heatmap_service.py` - heat-map analysis and rendering
- `services/collaboration_service.py` - collaboration and DM persistence
- `models/report_models.py` - typed contracts

Supporting docs:

- `docs/ARCHITECTURE_EXPLAINED.md`
- `API_DOCUMENTATION.md`
- `HEATMAP_API_REFERENCE.md`
- `RAG_INTEGRATION_SUMMARY.md`

## 13. Known Architectural Constraints

1. `appOne.py` is large and contains mixed concerns (UI, API, realtime, orchestration).
2. Several runtime stores are in-memory and non-durable.
3. Default credentials and secret management are not production-safe.
4. Single-process assumptions impact horizontal scaling.
5. LLM behavior depends on local Ollama runtime/model availability.

## 14. Suggested Refactor Direction

1. Split `appOne.py` into blueprints (auth, analysis, reports, frameworks, collab, heat-map).
2. Extract orchestration into service layer and keep routes thin.
3. Move background workloads to queue workers.
4. Replace process-local caches with shared state and persistent sessions.
5. Add automated integration tests for full pipeline routes and socket events.

