# Risk Heat Map - API Quick Reference

## Quick Start

### 1. Get Risk Appetite Questions
```bash
curl http://localhost:5002/api/risk-appetite-questions
```

### 2. Answer Risk Appetite Questions (in UI form)
```python
# In your form submission:
session_id: str           # From /api/generate-questions
organization_name: str    # "UOWD"
overall_risk_posture: str                # "Balanced"
max_acceptable_risk: str                 # "Medium is acceptable; High must be mitigated"
impact_sensitivities: List[str]          # ["Regulatory / legal breaches", "Financial loss"]
high_risk_mitigation_timeline: str       # "3 months"
preferred_risk_treatment: str            # "Reduce (add controls)"
```

### 3. Submit Risk Appetite
```bash
curl -X POST http://localhost:5002/api/submit-risk-appetite \
  -H "Content-Type: application/json" \
  -d '{
    "session_id": "session_abc123",
    "organization_name": "UOWD",
    "overall_risk_posture": "Balanced",
    "max_acceptable_risk": "Medium is acceptable; High must be mitigated",
    "impact_sensitivities": ["Regulatory / legal breaches", "Financial loss"],
    "high_risk_mitigation_timeline": "3 months",
    "preferred_risk_treatment": "Reduce (add controls)"
  }'
```

**Response:**
```json
{
  "profile_id": "appetite_abc123",
  "message": "Risk appetite profile saved successfully"
}
```

### 4. Get Heat Map Template
```bash
curl http://localhost:5002/api/heatmap-template
```

### 5. Submit Heat Map Items
```bash
curl -X POST http://localhost:5002/api/submit-heatmap-items \
  -H "Content-Type: application/json" \
  -d '{
    "session_id": "session_abc123",
    "items": [
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
        "description": "Policy for data retention",
        "impact_score": 4,
        "likelihood_score": 4,
        "primary_risk_type": "Data privacy / Confidentiality",
        "residual_risk_level": "High"
      }
    ]
  }'
```

**Response:**
```json
{
  "items_count": 2,
  "message": "Stored 2 heat-map items successfully"
}
```

### 6. Generate Heat Map Report
```bash
curl -X POST http://localhost:5002/api/generate-heatmap \
  -H "Content-Type: application/json" \
  -d '{"session_id": "session_abc123"}'
```

**Response:**
```json
{
  "report_id": "heatmap_xyz789",
  "session_id": "session_abc123",
  "summary": {
    "total_items": 2,
    "items_above_appetite": 2,
    "items_within_appetite": 0,
    "risk_distribution": {
      "Low": 0,
      "Medium": 0,
      "High": 2
    },
    "highest_risk_items": [
      ["AI Hiring Policy", "High"],
      ["Customer Data Retention", "High"]
    ],
    "organization_appetite": "Medium acceptable; High must be mitigated",
    "generated_at": "2026-02-17T12:30:00"
  },
  "visualization_path": "/exports/risk_heatmap_20260217_123000.png",
  "items_analyzed": 2,
  "generated_at": "2026-02-17T12:30:00"
}
```

### 7. Get Full Heat Map Report
```bash
curl http://localhost:5002/api/heatmap-report/heatmap_xyz789
```

**Response:**
```json
{
  "report_id": "heatmap_xyz789",
  "session_id": "session_abc123",
  "organization": "UOWD",
  "risk_appetite": {
    "overall_posture": "Balanced",
    "max_acceptable_risk": "Medium acceptable; High must be mitigated",
    "impact_sensitivities": ["Regulatory / legal breaches", "Financial loss"],
    "mitigation_timeline": "3 months"
  },
  "items": [
    {
      "item_id": "item_000_abc123",
      "name": "AI Hiring Policy",
      "likelihood": 3,
      "impact": 5,
      "risk_level": "High",
      "color_code": "#e74c3c",
      "above_appetite": true,
      "reasoning": "Item: AI Hiring Policy\n..."
    }
  ],
  "items_above_appetite": 2,
  "total_items": 2,
  "visualization_path": "/exports/risk_heatmap_20260217_123000.png",
  "generated_at": "2026-02-17T12:30:00"
}
```

### 8. Download Heat Map Image
```bash
curl -O http://localhost:5002/api/heatmap-image/heatmap_xyz789
```

## Enum Values

### RiskApproach Values
- `"Very conservative"`
- `"Conservative"`
- `"Balanced"`
- `"Aggressive"`
- `"Very aggressive"`

### MaxAcceptableRisk Values
- `"Only Low"`
- `"Low and some Medium"`
- `"Medium is acceptable; High must be mitigated"`
- `"High is acceptable with management sign-off"`

### ImpactType Values (can select multiple)
- `"Harm to individuals (safety, rights, discrimination)"`
- `"Regulatory / legal breaches"`
- `"Financial loss"`
- `"Service downtime / operational disruption"`
- `"Reputational damage"`
- `"Environmental / societal harm"`

### RiskType Values (pick one)
- `"Safety / Human harm"`
- `"Regulatory / Legal"`
- `"Data privacy / Confidentiality"`
- `"Financial / Fraud"`
- `"Operational / Availability"`
- `"Fairness / Bias / Ethics"`

### RiskTreatment Values
- `"Reduce (add controls)"`
- `"Transfer (insurance, contracts)"`
- `"Avoid (change design, stop activity)"`
- `"Accept with justification"`

### MitigationTimeline Values
- `"1 month"`
- `"3 months"`
- `"Executive approval"`
- `"Other"`

### ResidualRiskLevel Values
- `"Low"`
- `"Medium"`
- `"High"`

## Full Workflow Example

```python
import requests
import json

BASE_URL = "http://localhost:5002/api"

# Step 1: Create questionnaire session
response = requests.post(f"{BASE_URL}/generate-questions", json={
    "selected_functions": ["Identify", "Protect"],
    "organization_info": {
        "organization_name": "UOWD",
        "industry": "Academic",
        "size": "small",
        "contact_person": "John Doe",
        "contact_email": "john@uow.edu.au",
        "scope": "Risk assessment"
    }
})
session_id = response.json()["session_id"]
print(f"Created session: {session_id}")

# Step 2: Get risk appetite questions
response = requests.get(f"{BASE_URL}/risk-appetite-questions")
questions = response.json()["questions"]
print(f"Risk appetite questions: {len(questions)}")

# Step 3: Submit risk appetite answers
response = requests.post(f"{BASE_URL}/submit-risk-appetite", json={
    "session_id": session_id,
    "organization_name": "UOWD",
    "overall_risk_posture": "Balanced",
    "max_acceptable_risk": "Medium is acceptable; High must be mitigated",
    "impact_sensitivities": ["Regulatory / legal breaches", "Financial loss"],
    "high_risk_mitigation_timeline": "3 months",
    "preferred_risk_treatment": "Reduce (add controls)"
})
profile_id = response.json()["profile_id"]
print(f"Created risk appetite profile: {profile_id}")

# Step 4: Get heat-map template
response = requests.get(f"{BASE_URL}/heatmap-template")
template = response.json()["fields"]
print(f"Heat-map fields: {len(template)}")

# Step 5: Submit heat-map items
response = requests.post(f"{BASE_URL}/submit-heatmap-items", json={
    "session_id": session_id,
    "items": [
        {
            "name": "AI Hiring Policy",
            "description": "Controls use of AI in hiring",
            "impact_score": 5,
            "likelihood_score": 3,
            "primary_risk_type": "Fairness / Bias / Ethics",
            "residual_risk_level": "High"
        },
        {
            "name": "Customer Data",
            "description": "Customer data retention",
            "impact_score": 4,
            "likelihood_score": 4,
            "primary_risk_type": "Data privacy / Confidentiality",
            "residual_risk_level": "High"
        }
    ]
})
print(f"Items stored: {response.json()['items_count']}")

# Step 6: Generate heat-map
response = requests.post(f"{BASE_URL}/generate-heatmap", json={
    "session_id": session_id
})
report_id = response.json()["report_id"]
print(f"Heat-map report: {report_id}")
print(f"Items above appetite: {response.json()['summary']['items_above_appetite']}")

# Step 7: Get full report
response = requests.get(f"{BASE_URL}/heatmap-report/{report_id}")
report = response.json()
print("\nFull Report:")
print(json.dumps(report, indent=2))

# Step 8: Download image
response = requests.get(f"{BASE_URL}/heatmap-image/{report_id}")
with open("heat_map.png", "wb") as f:
    f.write(response.content)
print("Saved heat-map image: heat_map.png")
```

## Error Codes

| Status | Error | Solution |
|--------|-------|----------|
| 400 | "Invalid session ID" | Create session first with `/api/generate-questions` |
| 400 | "No heat-map items provided" | Submit items with `/api/submit-heatmap-items` |
| 400 | "Risk appetite profile not yet submitted" | Submit profile with `/api/submit-risk-appetite` |
| 404 | "Report not found" | Check report_id is correct |
| 500 | Various API errors | Check server logs for details |

## Integration Tips

### In Frontend (JavaScript/Vue/React)

```javascript
// 1. Get questions
async function getRiskAppetiteQuestions() {
  const response = await fetch('/api/risk-appetite-questions');
  return response.json();
}

// 2. Submit risk appetite
async function submitRiskAppetite(sessionId, formData) {
  const response = await fetch('/api/submit-risk-appetite', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      session_id: sessionId,
      ...formData
    })
  });
  return response.json();
}

// 3. Generate heat-map
async function generateHeatMap(sessionId) {
  const response = await fetch('/api/generate-heatmap', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ session_id: sessionId })
  });
  return response.json();
}

// 4. Display visualization
async function displayHeatMap(reportId) {
  const imagePath = await fetch(`/api/heatmap-image/${reportId}`);
  const imageUrl = imagePath.url;
  document.getElementById('heatmap-img').src = imageUrl;
}
```

## Rate Limiting

Currently no rate limiting. For production, consider adding:
- Rate limit: 10 requests/minute per session
- Timeout: 5 minutes for long-running analysis

## Data Retention

Heat-map data is stored in memory (`HEATMAP_REPORTS` dictionary) and will be lost on server restart. For persistence, implement database storage.
