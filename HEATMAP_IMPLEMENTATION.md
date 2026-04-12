# Risk Appetite & Heat Map Implementation Guide

## Overview

This implementation adds two key features to ComplyAI:

1. **Risk Appetite Assessment** - Capture organizational risk tolerance across 5 dimensions
2. **Risk Heat Map** - Visualize and analyze risks across documents/systems against appetite

## Features

### 1. Risk Appetite Profile
Captures organization's approach to risk across:
- **Overall Risk Posture**: Conservative to Very Aggressive
- **Maximum Acceptable Risk**: What risk levels the org will tolerate
- **Impact Sensitivity**: Which types of harm the org least tolerates
- **Prioritization Rules**: Timeline for mitigating High risks
- **Treatment Preference**: How the org typically handles risks (Reduce/Transfer/Avoid/Accept)

### 2. Heat Map Risk Assessment
For each document/policy/system, captures:
- **Name & Description**: What does it govern?
- **Impact Score** (1-5): Severity if fails/misused
- **Likelihood Score** (1-5): Probability of a harmful event
- **Risk Type**: Safety, Regulatory, Privacy, Financial, Operational, or Fairness
- **Residual Risk Level**: Expert judgment after considering controls

### 3. Risk Matrix Classification
Automatically calculates risk level using:
```
          Likelihood: 1   2   3   4   5
Impact: 1            Low  Low  Low  Med Med
        2            Low  Low  Med  Med High
        3            Low  Med  Med  High High
        4            Med  Med  High High High
        5            Med  High High High High
```

### 4. Heat Map Visualization
- **Scatter plot** with items plotted on Likelihood × Impact grid
- **Color-coded** by risk level (Green=Low, Yellow=Medium, Red=High)
- **Identifies items above appetite** with warning marker (⚠️)
- **PNG export** for reports and presentations

## Data Models

### RiskAppetiteProfile
```python
{
    "profile_id": "appetite_abc123",
    "session_id": "session_xyz",
    "organization_name": "UOWD",
    "overall_risk_posture": "Balanced",           # RiskApproach enum
    "max_acceptable_risk": "Medium with High mitigation",  # MaxAcceptableRisk enum
    "impact_sensitivities": ["Regulatory", "Financial"],    # List[ImpactType]
    "high_risk_mitigation_timeline": "3 months",  # MitigationTimeline enum
    "preferred_risk_treatment": "Reduce"          # RiskTreatment enum
}
```

### HeatMapItem
```python
{
    "item_id": "item_001_abc123",
    "name": "AI Hiring Policy",
    "description": "Controls use of AI in hiring decisions",
    "impact_score": 5,                    # 1-5: minimal to critical
    "likelihood_score": 3,                # 1-5: very unlikely to very likely
    "primary_risk_type": "Fairness",
    "residual_risk_level": "High"
}
```

### HeatMapAnalysis (Generated)
```python
{
    "item_id": "item_001_abc123",
    "name": "AI Hiring Policy",
    "impact": 5,
    "likelihood": 3,
    "risk_level": "High",                 # Calculated from matrix
    "color_code": "#e74c3c",              # Red for High
    "above_appetite": true,               # Exceeds org appetite
    "reasoning": "Item exceeds org appetite..."
}
```

### HeatMapReport (Final Output)
```python
{
    "report_id": "heatmap_abc123",
    "session_id": "session_xyz",
    "organization": "UOWD",
    "risk_appetite_profile": {...},      # RiskAppetiteProfile
    "heat_map_items": [...],             # List[HeatMapAnalysis]
    "items_above_appetite": 3,
    "visualization_path": "/exports/risk_heatmap_20260217_120000.png",
    "generated_at": "2026-02-17T12:00:00"
}
```

## API Endpoints

### 1. Get Risk Appetite Questions

**Endpoint:** `GET /api/risk-appetite-questions`

**Description:** Retrieve the 5 risk appetite assessment questions

**Response:**
```json
{
    "questions": [
        {
            "question_id": "RA_001",
            "question_text": "How would you describe your organization's...",
            "question_type": "multiple_choice",
            "category": "Risk Appetite",
            "subcategory": "Overall Risk Posture",
            "options": [
                "Very conservative – avoid almost all non-essential risk",
                "Conservative – accept only well-understood, low risks",
                ...
            ]
        },
        ...
    ],
    "total_questions": 5,
    "estimated_time_minutes": 15
}
```

### 2. Get Heat Map Template

**Endpoint:** `GET /api/heatmap-template`

**Description:** Retrieve heat-map input field definitions

**Response:**
```json
{
    "fields": [
        {
            "field_id": "HM_NAME",
            "field_text": "Item Name & Description",
            "field_type": "text",
            "required": true,
            "help_text": "Name of document/policy/system..."
        },
        ...
    ]
}
```

### 3. Submit Risk Appetite Profile

**Endpoint:** `POST /api/submit-risk-appetite`

**Request:**
```json
{
    "session_id": "session_xyz",
    "organization_name": "UOWD",
    "overall_risk_posture": "Balanced",
    "max_acceptable_risk": "Medium is acceptable; High must be mitigated",
    "impact_sensitivities": [
        "Regulatory / legal breaches",
        "Financial loss"
    ],
    "high_risk_mitigation_timeline": "3 months",
    "preferred_risk_treatment": "Reduce (add controls)"
}
```

**Response:**
```json
{
    "profile_id": "appetite_abc123",
    "message": "Risk appetite profile saved successfully"
}
```

### 4. Submit Heat Map Items

**Endpoint:** `POST /api/submit-heatmap-items`

**Request:**
```json
{
    "session_id": "session_xyz",
    "items": [
        {
            "name": "AI Hiring Policy",
            "description": "Controls use of AI in hiring decisions",
            "impact_score": 5,
            "likelihood_score": 3,
            "primary_risk_type": "Fairness / Bias / Ethics",
            "residual_risk_level": "High"
        },
        {
            "name": "Customer Data Retention",
            "description": "Policy for retaining customer data",
            "impact_score": 4,
            "likelihood_score": 4,
            "primary_risk_type": "Data privacy / Confidentiality",
            "residual_risk_level": "High"
        }
    ]
}
```

**Response:**
```json
{
    "items_count": 2,
    "message": "Stored 2 heat-map items successfully"
}
```

### 5. Generate Heat Map Report

**Endpoint:** `POST /api/generate-heatmap`

**Request:**
```json
{
    "session_id": "session_xyz"
}
```

**Response:**
```json
{
    "report_id": "heatmap_abc123",
    "session_id": "session_xyz",
    "summary": {
        "total_items": 4,
        "items_above_appetite": 2,
        "items_within_appetite": 2,
        "risk_distribution": {
            "Low": 1,
            "Medium": 1,
            "High": 2
        },
        "highest_risk_items": [
            ["AI Hiring Policy", "High"],
            ["Customer Data Retention", "High"]
        ],
        "organization_appetite": "Medium acceptable; High must be mitigated",
        "generated_at": "2026-02-17T12:00:00"
    },
    "visualization_path": "/exports/risk_heatmap_20260217_120000.png",
    "items_analyzed": 4,
    "generated_at": "2026-02-17T12:00:00"
}
```

### 6. Retrieve Heat Map Report

**Endpoint:** `GET /api/heatmap-report/<report_id>`

**Response:**
```json
{
    "report_id": "heatmap_abc123",
    "session_id": "session_xyz",
    "organization": "UOWD",
    "risk_appetite": {
        "overall_posture": "Balanced",
        "max_acceptable_risk": "Medium acceptable; High must be mitigated",
        "impact_sensitivities": ["Regulatory / legal breaches", "Financial loss"],
        "mitigation_timeline": "3 months"
    },
    "items": [
        {
            "item_id": "item_001_abc",
            "name": "AI Hiring Policy",
            "likelihood": 3,
            "impact": 5,
            "risk_level": "High",
            "color_code": "#e74c3c",
            "above_appetite": true,
            "reasoning": "Item: AI Hiring Policy\nLikelihood: 3/5 | Impact: 5/5\nRisk Classification: High\n⚠️  ABOVE ORGANIZATIONAL APPETITE\n..."
        },
        ...
    ],
    "items_above_appetite": 2,
    "total_items": 4,
    "visualization_path": "/exports/risk_heatmap_20260217_120000.png",
    "generated_at": "2026-02-17T12:00:00"
}
```

### 7. Download Heat Map Image

**Endpoint:** `GET /api/heatmap-image/<report_id>`

**Response:** PNG image file for download

## Usage Workflow

### Flow: Creating a Risk Assessment

```
1. User creates questionnaire session
   POST /api/generate-questions

2. User answers NIST CSF questions
   POST /api/submit-answers

3. (NEW) System provides risk appetite questions
   GET /api/risk-appetite-questions

4. (NEW) User completes risk appetite assessment
   POST /api/submit-risk-appetite

5. (NEW) System provides heat-map template
   GET /api/heatmap-template

6. (NEW) User submits heat-map items for each document/policy/system
   POST /api/submit-heatmap-items

7. (NEW) System generates heat-map report with visualization
   POST /api/generate-heatmap

8. User retrieves full heat-map report
   GET /api/heatmap-report/<report_id>

9. User downloads visualization
   GET /api/heatmap-image/<report_id>

10. (Optional) Export compliance report including heat-map
    GET /api/download-report/<report_id>/pdf
```

## Integration with Reports

The heat-map can be integrated into final compliance reports by:

1. Including heat-map analysis results in `report_exporter.py`
2. Adding visualization image to PDF/Word exports
3. Linking heat-map report to questionnaire session

## Configuration

### Risk Matrix Customization

Edit `RiskHeatMapService._build_risk_matrix()` to customize the matrix:

```python
def _build_risk_matrix(self) -> Dict[Tuple[int, int], str]:
    """Customize the risk classification matrix."""
    matrix = {
        # (likelihood, impact) -> risk_level
        (1, 1): "Low",   (2, 1): "Low",   ...
        # Add your organization's specific matrix
    }
    return matrix
```

### Color Scheme Customization

Edit `RiskHeatMapService.color_map`:

```python
self.color_map = {
    "Low": "#2ecc71",      # Green (customize hex codes)
    "Medium": "#f1c40f",   # Yellow
    "High": "#e74c3c"      # Red
}
```

## Enumerations

### RiskApproach
- `"Very conservative"` - avoid almost all non-essential risk
- `"Conservative"` - accept only well-understood, low risks
- `"Balanced"` - accept moderate risk for business value
- `"Aggressive"` - accept higher risk for innovation
- `"Very aggressive"` - prioritize speed/innovation

### MaxAcceptableRisk
- `"Only Low"`
- `"Low and some Medium"`
- `"Medium acceptable; High must be mitigated"`
- `"High acceptable with management sign-off"`

### ImpactType
- `"Harm to individuals (safety, rights, discrimination)"`
- `"Regulatory / legal breaches"`
- `"Financial loss"`
- `"Service downtime / operational disruption"`
- `"Reputational damage"`
- `"Environmental / societal harm"`

### RiskTreatment
- `"Reduce (add controls)"`
- `"Transfer (insurance, contracts)"`
- `"Avoid (change design, stop activity)"`
- `"Accept with justification"`

### MitigationTimeline
- `"1 month"`
- `"3 months"`
- `"Executive approval"`
- `"Other"`

## Example: Complete Flow

```python
# 1. Create session
session_id = "session_xyz"
org_info = OrganizationInfo(
    organization_name="UOWD",
    industry="Academic",
    size="small",
    contact_person="John Doe",
    contact_email="john@uow.edu.au"
)

# 2. Answer risk appetite questions
risk_appetite = {
    "overall_risk_posture": "Balanced",
    "max_acceptable_risk": "Medium is acceptable; High must be mitigated",
    "impact_sensitivities": ["Regulatory / legal breaches", "Financial loss"],
    "high_risk_mitigation_timeline": "3 months",
    "preferred_risk_treatment": "Reduce (add controls)"
}

# POST /api/submit-risk-appetite

# 3. Submit heat-map items
heatmap_items = [
    {
        "name": "AI Hiring Policy",
        "description": "Controls use of AI in hiring",
        "impact_score": 5,
        "likelihood_score": 3,
        "primary_risk_type": "Fairness / Bias / Ethics",
        "residual_risk_level": "High"
    },
    {
        "name": "Customer Data Retention",
        "description": "Data retention policy",
        "impact_score": 4,
        "likelihood_score": 4,
        "primary_risk_type": "Data privacy / Confidentiality",
        "residual_risk_level": "High"
    }
]

# POST /api/submit-heatmap-items

# 4. Generate report
# POST /api/generate-heatmap

# Returns:
# {
#     "report_id": "heatmap_abc123",
#     "items_above_appetite": 2,
#     "summary": {...},
#     "visualization_path": "/exports/risk_heatmap_20260217_120000.png"
# }
```

## Files Added/Modified

### New Files
- `services/risk_heatmap_service.py` - Heat-map generation logic
- `HEATMAP_IMPLEMENTATION.md` - This documentation

### Modified Files
- `models/report_models.py` - Added 8 new Pydantic models
- `services/questionnaire_engine.py` - Added risk appetite & heat-map questions
- `app.py` - Added 6 new API endpoints + service initialization

## Dependencies

Required packages (already in requirements.txt):
- `matplotlib` - for visualization
- `pandas` - for data handling
- `pydantic` - for data models
- `flask` - for API endpoints

If matplotlib not available, visualization is skipped gracefully.

## Troubleshooting

### "matplotlib not available"
Install matplotlib: `pip install matplotlib`

### Heat-map image not generating
- Check `/exports` directory exists and is writable
- Check matplotlib version: `python -c "import matplotlib; print(matplotlib.__version__)"`

### Invalid enum values
- Use exact values from enum definitions
- Check `RiskApproach`, `MaxAcceptableRisk`, etc. classes

### Session not found
- Ensure session_id matches a questionnaire session
- Create session first via `/api/generate-questions`

## Next Steps

1. Add heat-map integration to PDF/Word report exports
2. Create frontend UI for risk appetite questionnaire
3. Implement heat-map visualization on frontend  
4. Add filtering/sorting on heat-map dashboard
5. Create heat-map trend analysis (track changes over time)
