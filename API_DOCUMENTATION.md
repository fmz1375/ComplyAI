# NIST CSF Questionnaire Pipeline API Documentation

## Overview

This document describes the new NIST CSF questionnaire pipeline API endpoints that extend the existing ComplyAI application with structured questionnaire-based compliance assessments.

## New API Endpoints

### 1. Get Available NIST Functions
**GET** `/api/nist-functions`

Returns all available NIST CSF functions with question counts and metadata.

**Response:**
```json
{
  "functions": [
    {
      "function": "Identify",
      "total_questions": 15,
      "question_types": {
        "yes_no": 8,
        "multiple_choice": 4,
        "text": 3
      },
      "estimated_time_minutes": 30,
      "categories": ["Asset Management", "Risk Assessment", "Governance"]
    }
  ],
  "total_available": 5
}
```

### 2. Generate Questionnaire Questions
**POST** `/api/generate-questions`

Generate questions for selected NIST functions.

**Request:**
```json
{
  "selected_functions": ["Identify", "Protect"],
  "organization_info": {
    "organization_name": "Acme Corp",
    "industry": "Financial Services",
    "size": "Medium (100-1000 employees)",
    "contact_person": "John Doe",
    "contact_email": "john.doe@acme.com",
    "scope": "Enterprise-wide cybersecurity assessment"
  }
}
```

**Response:**
```json
{
  "session_id": "session_a1b2c3d4e5f6",
  "questions": [
    {
      "question_id": "Identify_001",
      "question_text": "Do you maintain an inventory of all physical devices and systems within your organization?",
      "question_type": "yes_no",
      "nist_function": "Identify",
      "category": "Asset Management",
      "subcategory": "Hardware Assets",
      "options": null,
      "required": true,
      "order": 1
    }
  ],
  "total_questions": 25,
  "estimated_time_minutes": 50
}
```

### 3. Submit Questionnaire Answers
**POST** `/api/submit-answers`

Submit answers and generate compliance report.

**Request:**
```json
{
  "session_id": "session_a1b2c3d4e5f6",
  "filename": "policy_document.pdf",
  "answers": [
    {
      "question_id": "Identify_001",
      "answer": "No",
      "evidence": "We only track servers but not workstations and mobile devices",
      "confidence": 0.9
    }
  ]
}
```

**Response:**
```json
{
  "report_id": "report_f6e5d4c3b2a1",
  "report": {
    "report_id": "report_f6e5d4c3b2a1",
    "organization_info": {
      "organization_name": "Acme Corp",
      "industry": "Financial Services",
      "size": "Medium (100-1000 employees)",
      "contact_person": "John Doe",
      "contact_email": "john.doe@acme.com",
      "assessment_date": "2024-01-15T10:30:00",
      "scope": "Enterprise-wide cybersecurity assessment"
    },
    "compliance_summary": {
      "total_gaps": 12,
      "gaps_by_function": {
        "Identify": 5,
        "Protect": 4,
        "Detect": 2,
        "Respond": 1,
        "Recover": 0
      },
      "gaps_by_risk_level": {
        "Critical": 2,
        "High": 4,
        "Medium": 5,
        "Low": 1
      },
      "overall_risk_score": 7.2,
      "compliance_percentage": 65.5,
      "critical_findings": 2,
      "high_priority_recommendations": 6
    },
    "compliance_gaps": [
      {
        "gap_id": "gap_001",
        "control_id": "ID.AM-1",
        "control_title": "Hardware devices are physically managed and protected",
        "nist_function": "Identify",
        "category": "Asset Management",
        "subcategory": "Hardware Assets",
        "description": "Organization lacks comprehensive inventory of all hardware assets including workstations and mobile devices",
        "reasoning": "Questionnaire response indicates no inventory tracking for workstations and mobile devices, which violates NIST control ID.AM-1 requiring physical management of all hardware devices",
        "risk_level": "High",
        "affected_assets": ["Workstations", "Mobile Devices", "Laptops"],
        "evidence_sources": ["Questionnaire Answer: Identify_001"],
        "related_questions": ["Identify_001"],
        "confidence_score": 0.9
      }
    ],
    "risk_assessment": [
      {
        "risk_id": "risk_001",
        "title": "Unauthorized Hardware Access Risk",
        "description": "Lack of complete hardware inventory increases risk of unauthorized devices on network",
        "risk_level": "High",
        "likelihood": "Medium",
        "impact": "High",
        "nist_function": "Identify",
        "related_gaps": ["gap_001"],
        "mitigation_status": "Unmitigated",
        "business_impact": "Potential data breach and regulatory non-compliance"
      }
    ],
    "recommendations": [
      {
        "recommendation_id": "rec_001",
        "title": "Implement Comprehensive Hardware Inventory System",
        "description": "Deploy automated asset management solution to track all hardware devices",
        "priority": "High",
        "nist_function": "Identify",
        "related_gaps": ["gap_001"],
        "related_risks": ["risk_001"],
        "implementation_steps": [
          "Evaluate and select asset management solution",
          "Deploy agents to all workstations and mobile devices",
          "Establish centralized inventory database",
          "Implement regular inventory reconciliation process"
        ],
        "estimated_effort": "3-6 months",
        "dependencies": ["Network infrastructure upgrade", "Budget approval"],
        "success_criteria": [
          "100% hardware asset coverage",
          "Real-time inventory updates",
          "Automated alerts for unauthorized devices"
        ]
      }
    ],
    "questionnaire_answers": [...],
    "document_analysis": {...},
    "metadata": {...},
    "generated_at": "2024-01-15T11:45:00",
    "version": "1.0"
  },
  "validation": {
    "is_valid": true,
    "warnings": ["No compliance gaps identified for Recover function"],
    "errors": [],
    "quality_score": 0.85
  },
  "message": "Compliance report generated successfully"
}
```

### 4. Get Report
**GET** `/api/reports/{report_id}`

Retrieve a previously generated report.

**Response:** Same report structure as above.

### 5. Download Report
**GET** `/api/download-report/{report_id}/{format}`

Download report in PDF or Word format.

**Parameters:**
- `report_id`: Report identifier
- `format`: Export format (`pdf` or `docx`)

**Response:** File download

## Pipeline Flow

### Step 1: Upload Document (Existing)
```
POST /upload
```

### Step 2: Get Available Functions
```
GET /api/nist-functions
```

### Step 3: Generate Questions
```
POST /api/generate-questions
```

### Step 4: Submit Answers
```
POST /api/submit-answers
```

### Step 5: Download Reports
```
GET /api/download-report/{report_id}/pdf
GET /api/download-report/{report_id}/docx
```

## Frontend Integration

### UI Flow

1. **Document Upload**: Use existing `/upload` endpoint
2. **Function Selection**: Call `/api/nist-functions` and display available functions
3. **Questionnaire**: Display questions from `/api/generate-questions` response
4. **Answer Submission**: Submit answers to `/api/submit-answers`
5. **Report Display**: Show generated report from response
6. **Export**: Provide download links for PDF/Word formats

### Example Frontend Integration

```javascript
// Step 1: Get available functions
const functions = await fetch('/api/nist-functions').then(r => r.json());

// Step 2: Generate questions
const session = await fetch('/api/generate-questions', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    selected_functions: ['Identify', 'Protect'],
    organization_info: { /* organization details */ }
  })
}).then(r => r.json());

// Step 3: Submit answers
const report = await fetch('/api/submit-answers', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    session_id: session.session_id,
    filename: 'policy.pdf',
    answers: [/* answer objects */]
  })
}).then(r => r.json());

// Step 4: Download report
window.open(`/api/download-report/${report.report_id}/pdf`);
```

## Error Handling

All endpoints return consistent error format:

```json
{
  "error": "Error description",
  "details": "Additional error information (optional)"
}
```

Common HTTP status codes:
- `400`: Bad Request (invalid input)
- `404`: Not Found (session/report not found)
- `500`: Internal Server Error

## Data Models

### QuestionAnswer
```json
{
  "question_id": "string",
  "question_text": "string",
  "question_type": "yes_no|multiple_choice|text|scale",
  "nist_function": "Identify|Protect|Detect|Respond|Recover",
  "category": "string",
  "subcategory": "string",
  "answer": "string",
  "evidence": "string|null",
  "confidence": "number|null",
  "timestamp": "ISO datetime"
}
```

### OrganizationInfo
```json
{
  "organization_name": "string",
  "industry": "string",
  "size": "string",
  "contact_person": "string",
  "contact_email": "string",
  "scope": "string",
  "assessor_name": "string|null"
}
```

## Installation

Install new dependencies:

```bash
pip install -r requirements.txt
```

New dependencies added:
- `pydantic`: Data validation and settings management
- `beautifulsoup4`: HTML parsing for questionnaire extraction
- `reportlab`: PDF generation
- `python-docx`: Word document generation

## File Structure

```
ComplyAI_V2/
├── models/
│   ├── __init__.py
│   └── report_models.py          # Pydantic data models
├── services/
│   ├── __init__.py
│   ├── questionnaire_engine.py    # Question generation and processing
│   ├── context_builder.py        # LLM context building
│   ├── llm_service.py           # LLM integration and report generation
│   └── report_exporter.py       # PDF/Word export functionality
├── app.py                       # Updated with new endpoints
├── requirements.txt              # Updated with new dependencies
└── NIST CSF Compliance Questionnaire.html  # Question source
```

## Testing

Example test flow:

```bash
# 1. Start the application
python app.py

# 2. Test endpoints
curl -X GET http://localhost:5002/api/nist-functions

curl -X POST http://localhost:5002/api/generate-questions \
  -H "Content-Type: application/json" \
  -d '{"selected_functions": ["Identify"], "organization_info": {...}}'
```

## Production Considerations

1. **Session Management**: Current implementation uses in-memory storage. For production, consider Redis or database storage.
2. **File Storage**: Reports are stored in memory. Consider persistent storage for large-scale deployments.
3. **Error Recovery**: Implement retry logic for LLM calls and report generation.
4. **Rate Limiting**: Add rate limiting for API endpoints.
5. **Security**: Validate all inputs and implement proper authentication/authorization.
