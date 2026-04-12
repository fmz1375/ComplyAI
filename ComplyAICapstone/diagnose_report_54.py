#!/usr/bin/env python
import os, sys, sqlite3, json, traceback

PROJECT_DB = os.environ.get("PROJECT_DB_PATH", "project.db")
REPORT_ID = 54

print("Running diagnostics from", os.getcwd())
if not os.path.exists(PROJECT_DB):
    print("ERROR: cannot find", PROJECT_DB, "in this folder. cd into the project root and run again.")
    sys.exit(1)

# Print DB basics and attempt to read row
con = sqlite3.connect(PROJECT_DB)
con.row_factory = sqlite3.Row
cur = con.cursor()

print("\nRecent report ids (last 10):")
for r in cur.execute("SELECT id, organization_name, created_at FROM report ORDER BY id DESC LIMIT 10"):
    print(" ", r["id"], r["organization_name"], r["created_at"])

row = cur.execute("SELECT * FROM report WHERE id = ?", (REPORT_ID,)).fetchone()
if not row:
    print(f"\nERROR: No report row with id={REPORT_ID}")
    con.close()
    sys.exit(1)

def show(name, v):
    print("\n--", name, "--")
    if v is None:
        print("NULL")
        return
    s = v if isinstance(v, str) else (v.decode("utf-8", "replace") if isinstance(v, (bytes, bytearray)) else str(v))
    print("LEN:", len(s))
    try:
        parsed = json.loads(s)
        print("JSON type:", type(parsed))
        if isinstance(parsed, dict):
            print(" keys:", list(parsed.keys())[:40])
        elif isinstance(parsed, list):
            print(" list len:", len(parsed), "sample:", parsed[:3])
    except Exception:
        print("RAW (first 1000 chars):\n", s[:1000])

# Show fields that matter
show("questionnaire_answers", row.get("questionnaire_answers"))
show("metadata", row.get("metadata"))
show("compliance_summary", row.get("compliance_summary"))
show("gap_analysis", row.get("gap_analysis"))
if "compliance_gaps" in row.keys():
    show("compliance_gaps", row.get("compliance_gaps"))

# Now run the same computation logic locally
print("\nRunning local computation using QuestionnaireEngine and gaps fallback...")
try:
    # Import local modules from the project
    sys.path.insert(0, os.getcwd())
    from services.questionnaire_engine import QuestionnaireEngine
    from models.report_models import NISTFunction
    engine = QuestionnaireEngine()
    # Try parse questionnaire_answers
    answers_raw = row.get("questionnaire_answers")
    if answers_raw:
        try:
            answers = json.loads(answers_raw) if isinstance(answers_raw, str) else answers_raw
        except Exception:
            answers = []
    else:
        answers = []
    print("Parsed answers count:", len(answers))

    computed = engine.compute_compliance_by_function([a for a in answers], None)
    print("Engine computed per-function:", computed)

    # get total question counts per function
    totals = {}
    for f in [NISTFunction.GOVERN, NISTFunction.IDENTIFY, NISTFunction.PROTECT, NISTFunction.DETECT, NISTFunction.RESPOND, NISTFunction.RECOVER]:
        try:
            totals[f.value] = engine.get_function_summary(f).get("total_questions", 0)
        except Exception as e:
            totals[f.value] = 0
    print("Question totals per function:", totals)

    # compute gaps-based fallback if needed
    gaps_raw = row.get("gap_analysis") or row.get("compliance_gaps")
    gaps = []
    if gaps_raw:
        try:
            gaps = json.loads(gaps_raw) if isinstance(gaps_raw, str) else gaps_raw
        except Exception:
            gaps = []
    gaps_count = {k:0 for k in ["Govern","Identify","Protect","Detect","Respond","Recover"]}
    for g in gaps or []:
        try:
            if isinstance(g, dict):
                fn = g.get("nist_function")
            else:
                fn = getattr(g, "nist_function", None)
            if fn and fn in gaps_count:
                gaps_count[fn] += 1
        except Exception:
            continue
    print("Gaps count by function (from gap_analysis):", gaps_count)

    # Compute fallback percentages using totals if totals > 0; otherwise use overall if present
    per_func_pct = {}
    for name in ["Govern","Identify","Protect","Detect","Respond","Recover"]:
        tq = totals.get(name, 0) or 0
        gc = gaps_count.get(name, 0)
        if tq > 0:
            pct = round(max(0.0, 100.0 * (1.0 - (gc / tq))), 1)
        else:
            cs_raw = row.get("compliance_summary")
            pct = None
            try:
                cs = json.loads(cs_raw) if isinstance(cs_raw, str) else cs_raw
                if isinstance(cs, dict):
                    if name.lower() in cs:
                        pct = float(cs[name.lower()])
            except Exception:
                pct = None
            if pct is None:
                pct = 100.0 if (gc == 0 and (row.get('compliance_summary') and json.loads(row.get('compliance_summary') or '{}').get('compliance_percentage'))) else 0.0
        per_func_pct[name.lower()] = pct
    print("Computed per-function percentages (fallback):", per_func_pct)

except Exception as e:
    print("ERROR during local computation:", e)
    traceback.print_exc()

# Attempt to run the same exporter path the app uses to build the FinalReport -> PDF
print("\nAttempting to generate PDF via ReportExporter using the same construction path used by the app (will use gaps to build compliance_gaps)...")
try:
    sys.path.insert(0, os.getcwd())
    from services.report_exporter import ReportExporter
    from models.report_models import FinalReport, OrganizationInfo, ComplianceSummary, ComplianceGap
    # Minimal FinalReport build: mirror appOne.py build (questionnaire_answers left empty)
    org_name = row.get('organization_name') or 'org'
    cs = row.get('compliance_summary')
    if cs:
        try:
            cs_parsed = json.loads(cs) if isinstance(cs, str) else cs
            compliance_summary = ComplianceSummary(
                total_gaps = int(cs_parsed.get('total_gaps', 0)),
                gaps_by_function = cs_parsed.get('gaps_by_function', {}),
                gaps_by_risk_level = cs_parsed.get('gaps_by_risk_level', {}),
                overall_risk_score = float(cs_parsed.get('overall_risk_score', 0.0)),
                compliance_percentage = float(cs_parsed.get('compliance_percentage', 0.0)),
                critical_findings = int(cs_parsed.get('critical_findings', 0)),
                high_priority_recommendations = int(cs_parsed.get('high_priority_recommendations', 0))
            )
        except Exception:
            compliance_summary = ComplianceSummary(total_gaps=0, gaps_by_function={}, gaps_by_risk_level={}, overall_risk_score=0.0, compliance_percentage=0.0, critical_findings=0, high_priority_recommendations=0)
    else:
        compliance_summary = ComplianceSummary(total_gaps=0, gaps_by_function={}, gaps_by_risk_level={}, overall_risk_score=0.0, compliance_percentage=0.0, critical_findings=0, high_priority_recommendations=0)
    org_info = OrganizationInfo(
        organization_name = org_name,
        industry = row.get('industry') or 'n/a',
        size = row.get('size') or 'n/a',
        contact_person = '', contact_email='',
        assessment_date = __import__('datetime').datetime.now(),
        assessor_name = None,
        scope = row.get('scope') or 'N/A'
    )
    # Build compliance_gaps list
    gaps_list = []
    gaps_raw = row.get('gap_analysis') or row.get('compliance_gaps') or '[]'
    try:
        gaps_loaded = json.loads(gaps_raw) if isinstance(gaps_raw, str) else gaps_raw
    except Exception:
        gaps_loaded = []
    from models.report_models import RiskLevel, NISTFunction
    for gd in gaps_loaded or []:
        try:
            risk_str = gd.get('risk_level','Medium').capitalize()
            rl = RiskLevel(risk_str if risk_str in ['Low','Medium','High','Critical'] else 'Medium')
            try:
                nf = NISTFunction(gd.get('nist_function','Protect'))
            except Exception:
                nf = NISTFunction.PROTECT
            gap = ComplianceGap(
                gap_id = gd.get('gap_id', f"gap_{len(gaps_list)}"),
                control_id = gd.get('control_id',''),
                control_title = gd.get('control_title',''),
                nist_function = nf,
                category = gd.get('category',''),
                subcategory = gd.get('subcategory',''),
                description = gd.get('description',''),
                reasoning = gd.get('reasoning',''),
                risk_level = rl,
                affected_assets = gd.get('affected_assets', []),
                evidence_sources = gd.get('evidence_sources', []),
                related_questions = gd.get('related_questions', []),
                confidence_score = float(gd.get('confidence_score', 0.8))
            )
            gaps_list.append(gap)
        except Exception:
            continue

    report = FinalReport(
        report_id = f'report_{REPORT_ID}',
        organization_info = org_info,
        compliance_summary = compliance_summary,
        questionnaire_answers = [],
        compliance_gaps = gaps_list,
        risk_assessment = [],
        recommendations = [],
        heatmap = None,
        document_analysis = {},
        metadata = {}
    )

    exporter = ReportExporter()
    out_path = exporter.export_to_pdf(report, filename=f"diag_report_{REPORT_ID}.pdf")
    print('Exported PDF path:', out_path)
except Exception as e:
    print('ERROR exporting PDF:', e)
    traceback.print_exc()

print('\nDiagnostics complete.')
