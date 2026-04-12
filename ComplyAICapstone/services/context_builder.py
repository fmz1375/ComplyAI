# -*- coding: utf-8 -*-
"""
Context Builder for NIST CSF Compliance Analysis

This module handles:
- Building structured context for LLM analysis
- Combining document text with questionnaire answers
- Formatting organization metadata
- Creating comprehensive analysis prompts
"""

import json
import os
from typing import List, Dict, Any, Optional
from datetime import datetime

from models.report_models import (
    QuestionAnswer, AnalysisContext, OrganizationInfo,
    NISTFunction, RiskLevel
)
from security_utils import PromptInjectionDefense


class ContextBuilder:
    """Builds comprehensive context for NIST CSF compliance analysis."""
    
    def __init__(self):
        """Initialize the context builder."""
        self.compact_prompt = os.getenv("COMPLYAI_COMPACT_PROMPT", "0").lower() in ("1", "true", "yes")
        self.nist_framework_description = self._get_nist_framework_description()
        self.analysis_instructions = self._get_analysis_instructions()
    
    def build_analysis_context(
        self,
        document_text: str,
        questionnaire_answers: List[QuestionAnswer],
        organization_info: OrganizationInfo,
        nist_controls_context: Optional[Dict[str, Any]] = None,
        additional_metadata: Optional[Dict[str, Any]] = None
    ) -> AnalysisContext:
        """
        Build comprehensive analysis context for LLM.
        
        Args:
            document_text: Extracted text from uploaded documents
            questionnaire_answers: List of questionnaire responses
            organization_info: Organization metadata
            nist_controls_context: NIST controls reference data
            additional_metadata: Additional context information
            
        Returns:
            AnalysisContext object with all combined information
        """
        # Process questionnaire answers
        processed_answers = self._process_questionnaire_answers(questionnaire_answers)
        
        # Build organization metadata
        org_metadata = self._build_organization_metadata(organization_info, additional_metadata)
        
        # Build NIST controls context
        nist_context = nist_controls_context or self._get_default_nist_context()
        
        # Create analysis instructions
        analysis_instructions = self._build_analysis_instructions(processed_answers)
        
        return AnalysisContext(
            document_text=document_text,
            questionnaire_answers=questionnaire_answers,
            organization_metadata=org_metadata,
            nist_controls_context=nist_context,
            analysis_instructions=analysis_instructions,
            output_format="json"
        )
    
    def build_llm_prompt(self, context: AnalysisContext) -> str:
        """
        Build the complete LLM prompt from analysis context.
        
        Args:
            context: AnalysisContext object
            
        Returns:
            Formatted prompt string for LLM
        """
        prompt = f"""{self._get_system_prompt()}

## ORGANIZATION INFORMATION
{PromptInjectionDefense.sanitize_user_input(self._format_organization_info(context.organization_metadata))}

## QUESTIONNAIRE RESPONSES
{self._format_questionnaire_answers(context.questionnaire_answers)}

## DOCUMENT ANALYSIS
{self._format_document_text(context.document_text)}

## NIST CSF FRAMEWORK REFERENCE
{self._format_nist_context(context.nist_controls_context)}

## ANALYSIS INSTRUCTIONS
{context.analysis_instructions}

## EXPECTED OUTPUT FORMAT
{self._get_output_format_specification()}

Please analyze the provided information and generate a comprehensive NIST CSF compliance assessment following the specified format."""
        
        return prompt
    
    def _process_questionnaire_answers(self, answers: List[QuestionAnswer]) -> Dict[str, Any]:
        """
        Process questionnaire answers into structured format.
        
        Args:
            answers: List of QuestionAnswer objects
            
        Returns:
            Processed answers dictionary
        """
        processed = {
            "total_answers": len(answers),
            "answers_by_function": {},
            "answers_by_risk_indicators": {},
            "summary_statistics": {}
        }
        
        # Group answers by NIST function
        for answer in answers:
            function = answer.nist_function.value
            if function not in processed["answers_by_function"]:
                processed["answers_by_function"][function] = []
            processed["answers_by_function"][function].append({
                "question": answer.question_text,
                "answer": answer.answer,
                "category": answer.category,
                "subcategory": answer.subcategory,
                "evidence": answer.evidence
            })
        
        # Analyze risk indicators from answers
        risk_keywords = ["no", "none", "never", "lack", "missing", "inadequate", "insufficient"]
        for answer in answers:
            answer_lower = answer.answer.lower()
            has_risk_indicator = any(keyword in answer_lower for keyword in risk_keywords)
            
            if has_risk_indicator:
                function = answer.nist_function.value
                if function not in processed["answers_by_risk_indicators"]:
                    processed["answers_by_risk_indicators"][function] = []
                processed["answers_by_risk_indicators"][function].append({
                    "question": answer.question_text,
                    "answer": answer.answer,
                    "risk_indicator": True
                })
        
        # Calculate summary statistics
        processed["summary_statistics"] = {
            "functions_assessed": len(processed["answers_by_function"]),
            "total_risk_indicators": sum(len(answers) for answers in processed["answers_by_risk_indicators"].values()),
            "completion_rate": 100.0  # Assuming all required questions are answered
        }
        
        return processed
    
    def _build_organization_metadata(
        self, 
        org_info: OrganizationInfo, 
        additional_metadata: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Build organization metadata dictionary."""
        metadata = {
            "organization_name": org_info.organization_name,
            "industry": org_info.industry,
            "size": org_info.size,
            "contact_person": org_info.contact_person,
            "contact_email": org_info.contact_email,
            "assessment_date": org_info.assessment_date.isoformat(),
            "assessor_name": org_info.assessor_name,
            "scope": org_info.scope
        }
        
        if additional_metadata:
            metadata.update(additional_metadata)
        
        return metadata
    
    def _get_default_nist_context(self) -> Dict[str, Any]:
        """Get default NIST CSF framework context."""
        return {
            "framework_name": "NIST Cybersecurity Framework",
            "version": "1.1",
            "functions": {
                "Identify": "Develop organizational understanding to manage cybersecurity risk to systems, assets, data, and capabilities.",
                "Protect": "Develop and implement appropriate safeguards to ensure delivery of critical infrastructure services.",
                "Detect": "Develop and implement appropriate activities to identify the occurrence of a cybersecurity event.",
                "Respond": "Develop and implement appropriate activities to take action regarding a detected cybersecurity event.",
                "Recover": "Develop and implement appropriate activities to maintain plans for resilience and to restore any capabilities or services that were impaired due to a cybersecurity event."
            },
            "implementation_tiers": {
                "Tier 1": "Partial",
                "Tier 2": "Risk Informed",
                "Tier 3": "Repeatable",
                "Tier 4": "Adaptive"
            }
        }
    
    def _build_analysis_instructions(self, processed_answers: Dict[str, Any]) -> str:
        """Build specific analysis instructions based on questionnaire responses."""
        instructions = self.analysis_instructions
        
        # Add specific focus areas based on risk indicators
        if processed_answers.get("answers_by_risk_indicators"):
            high_risk_functions = list(processed_answers["answers_by_risk_indicators"].keys())
            instructions += f"\n\n## SPECIAL ATTENTION AREAS\nBased on questionnaire responses, pay special attention to these NIST functions: {', '.join(high_risk_functions)}"
        
        return instructions
    
    def _get_system_prompt(self) -> str:
        """Get the system prompt for the LLM."""
        if self.compact_prompt:
            return """You are a senior cybersecurity compliance auditor specializing in the NIST CSF.

Return concise, valid JSON only. Focus on key gaps, risks, and recommendations."""
        return """You are a senior cybersecurity compliance auditor with expertise in the NIST Cybersecurity Framework (CSF).

Your task is to conduct a comprehensive compliance assessment based on questionnaire responses and organizational documentation.

ASSESSMENT METHODOLOGY:
1. QUESTIONNAIRE-DRIVEN ANALYSIS: Maps questionnaire answers directly to NIST CSF controls
2. GAP IDENTIFICATION: Identifies missing or incomplete security controls based on "No" or negative answers
3. RISK EVALUATION: Assesses risk severity considering organization size and industry
4. REMEDIATION PLANNING: Provides specific, prioritized recommendations with implementation details

KEY ANALYSIS RULES:
- EVERY "No" answer likely represents a compliance gap - identify it
- Questions are pre-categorized by NIST Function, Category, and Subcategory
- Use this metadata to classify gaps correctly
- Generate meaningful gap_id values using the question ID as reference
- Create control_id from the category/subcategory hierarchy
- Assign risk levels based on NIST control criticality and organizational context

RISK ASSESSMENT CRITERIA:
- CRITICAL: Missing controls affecting identity, access, or incident response capabilities
- HIGH: Important protective or detective controls that are missing or incomplete
- MEDIUM: Gaps in complementary controls or maturity improvements needed
- LOW: Nice-to-have features or optimization recommendations

OUTPUT EXPECTATIONS:
- Minimum 1 gap per significant "No" answer
- Risk scores and percentages must be mathematically consistent
- Recommendations must directly address identified gaps
- All output must be valid JSON matching the specified schema"""

    def _get_analysis_instructions(self) -> str:
        """Get base analysis instructions."""
        if self.compact_prompt:
            return """ANALYSIS REQUIREMENTS:

1. Identify key compliance gaps tied to NIST functions
2. Assign risk level per gap (Critical/High/Medium/Low)
3. Provide short, actionable recommendations
4. Keep output minimal but schema-compliant"""
        return """ANALYSIS REQUIREMENTS:

1. QUESTIONNAIRE ANSWER ANALYSIS
   - Review each questionnaire answer carefully
   - Answers "No", "None", "Never", "Lack", "Missing" indicate potential gaps
   - Consider enterprise best practices for each NIST control category
   - Map answers to specific NIST CSF controls and categories identified in questions
   - Explanation: Questions are structured by NIST Function, Category, and Subcategory

2. COMPLIANCE GAPS IDENTIFICATION
   - For EACH "No" or negative answer, identify a specific compliance gap
   - Link gaps to the NIST function and category from the questionnaire
   - Provide specific control titles based on the question category
   - Generate gap_id, control_id (use category format), control_title, description
   - Include reasoning based on the answer and industry best practices
   - Assign risk levels based on control criticality
   - Always generate at least one gap if any significant "No" answers exist

3. RISK ASSESSMENT
   - Create risk items for high-impact gaps
   - For critical missing controls (e.g., no incident response plan), assign CRITICAL risk
   - For important missing controls (e.g., no training), assign HIGH risk
   - Include likelihood and impact descriptions
   - Connect risks to identified compliance gaps (related_gaps field)

4. RECOMMENDATIONS
   - Create at least one recommendation for each critical/high gap
   - Prioritize by risk level (High priority for Critical gaps, Medium for High gaps)
   - Include specific implementation steps tailored to the organization
   - Add realistic estimated effort estimates based on control complexity
   - Define clear success criteria for verification

5. COMPLIANCE SCORING
   - Calculate compliance percentage based on positive vs total answers
   - Count gaps to determine overall risk score (0-10)
   - CRITICAL gaps: +3 points each, HIGH: +2 points, MEDIUM: +1 point
   - Map risk assessment results to compliance_summary metrics"""

    def _format_organization_info(self, metadata: Dict[str, Any]) -> str:
        """Format organization information for prompt."""
        return f"""
Organization: {metadata.get('organization_name', 'N/A')}
Industry: {metadata.get('industry', 'N/A')}
Size: {metadata.get('size', 'N/A')}
Assessment Scope: {metadata.get('scope', 'N/A')}
Assessment Date: {metadata.get('assessment_date', 'N/A')}
Assessor: {metadata.get('assessor_name', 'N/A')}
Contact: {metadata.get('contact_email', 'N/A')}"""

    def _format_questionnaire_answers(self, answers: List[QuestionAnswer]) -> str:
        """Format questionnaire answers for prompt."""
        if not answers:
            return "No questionnaire responses provided."

        if self.compact_prompt:
            max_answers = 12
            max_answer_chars = 200
            max_evidence_chars = 150
        else:
            max_answers = 50
            max_answer_chars = 500
            max_evidence_chars = 300
        
        # Group answers by function for better analysis
        formatted = []
        answers_by_function = {}
        
        for answer in answers:
            func = answer.nist_function.value
            if func not in answers_by_function:
                answers_by_function[func] = []
            answers_by_function[func].append(answer)
        
        # Track negative responses for easier gap identification
        critical_gaps = []
        
        for function in ['Identify', 'Protect', 'Detect', 'Respond', 'Recover']:
            if function not in answers_by_function:
                continue
            
            formatted.append(f"\n### {function} Function")
            function_answers = answers_by_function[function]
            
            for answer in function_answers:
                answer_lower = answer.answer.lower()
                is_negative = any(word in answer_lower for word in ['no', 'none', 'never', 'lack', 'missing', 'inadequate', 'no plan', 'not implemented', 'not in place'])
                
                # Mark negative answers for easier processing
                marker = "❌ GAP" if is_negative else "✓"
                
                formatted.append(f"\n{marker} **{PromptInjectionDefense.sanitize_user_input(answer.category)} - {PromptInjectionDefense.sanitize_user_input(answer.subcategory)}**")
                formatted.append(f"Q: {PromptInjectionDefense.sanitize_user_input(answer.question_text)}")
                formatted.append(f"A: {PromptInjectionDefense.sanitize_user_input(answer.answer[:max_answer_chars])}{'...[truncated]' if len(answer.answer) > max_answer_chars else ''}")
                
                if is_negative:
                    critical_gaps.append(f"{function} - {answer.category}: {answer.question_text}")
                
                if answer.evidence:
                    formatted.append(f"Evidence: {PromptInjectionDefense.sanitize_user_input(answer.evidence[:max_evidence_chars])}{'...[truncated]' if len(answer.evidence) > max_evidence_chars else ''}")
        
        # Add summary of critical gaps at the top for analysis
        if critical_gaps:
            summary = "\n## POTENTIAL COMPLIANCE GAPS IDENTIFIED FROM QUESTIONNAIRE\n"
            summary += "The following negative responses indicate potential gaps that require detailed analysis:\n"
            for i, gap in enumerate(critical_gaps, 1):
                summary += f"\n{i}. {gap}"
            formatted.insert(0, summary)
        
        if len(answers) > max_answers:
            formatted.append(f"\n...{len(answers) - max_answers} additional answers omitted to reduce prompt size.")
        
        return "\n".join(formatted)
    
    def _format_document_text(self, document_text: str) -> str:
        """Format document text for prompt."""
        if not document_text:
            return "No document text provided."

        # Limit document text to avoid context overflow
        max_chars = 1200 if self.compact_prompt else 4000
        if len(document_text) > max_chars:
            document_text = document_text[:max_chars] + "...[truncated]"
        
        return f"""
### POLICY DOCUMENT ANALYSIS
{document_text}"""

    def _format_nist_context(self, nist_context: Dict[str, Any]) -> str:
        """Format NIST framework context for prompt."""
        if self.compact_prompt:
            functions = ", ".join(nist_context.get("functions", {}).keys())
            return f"### NIST CSF Functions\n{functions}"
        formatted = [f"### {nist_context.get('framework_name', 'NIST CSF')} {nist_context.get('version', '')}"]
        
        if 'functions' in nist_context:
            formatted.append("\n**Core Functions:**")
            for func, desc in nist_context['functions'].items():
                formatted.append(f"- **{func}:** {desc}")
        
        if 'implementation_tiers' in nist_context:
            formatted.append("\n**Implementation Tiers:**")
            for tier, desc in nist_context['implementation_tiers'].items():
                formatted.append(f"- **{tier}:** {desc}")
        
        return "\n".join(formatted)
    
    def _get_output_format_specification(self) -> str:
        """Get the expected output format specification."""
        if self.compact_prompt:
            return """Return JSON with these exact keys: compliance_summary, compliance_gaps, risk_assessment, recommendations.

gaps_by_function MUST be counts like: {"Identify": 2, "Protect": 1} - NOT a list of gap objects.
gaps_by_risk_level MUST be counts like: {"Critical": 1, "High": 2, "Medium": 3, "Low": 0}
total_gaps MUST equal the length of compliance_gaps array.

compliance_gaps[]: {gap_id, control_id, control_title, nist_function, category, subcategory, description, reasoning, risk_level, affected_assets, evidence_sources, related_questions, confidence_score}
risk_assessment[]: {risk_id, title, description, risk_level, likelihood, impact, nist_function, related_gaps, mitigation_status, business_impact}
recommendations[]: {recommendation_id, title, description, priority, nist_function, related_gaps, related_risks, implementation_steps, estimated_effort, dependencies, success_criteria}"""
        return """Return a JSON object with the following EXACT structure and REQUIRED FIELDS populated:

{
  "compliance_summary": {
    "total_gaps": <actual number - MUST match length of compliance_gaps array>,
    "gaps_by_function": {
      "Identify": <number>,
      "Protect": <number>,
      "Detect": <number>,
      "Respond": <number>,
      "Recover": <number>
    },
    "gaps_by_risk_level": {
      "Critical": <number>,
      "High": <number>,
      "Medium": <number>,
      "Low": <number>
    },
    "overall_risk_score": <0-10 based on gap severity and count>,
    "compliance_percentage": <0-100 calculated as (answered_yes / total_questions) * 100>,
    "critical_findings": <count of Critical risk level gaps>,
    "high_priority_recommendations": <count of High priority recommendations>
  },
  "compliance_gaps": [
    {
      "gap_id": "GAP_IDENTIFY_001",
      "control_id": "ID.AM.001",
      "control_title": "Asset Management - Hardware/Software Inventory",
      "nist_function": "Identify",
      "category": "Asset Management",
      "subcategory": "Hardware Assets",
      "description": "No formal asset inventory documented or maintained",
      "reasoning": "Questionnaire response indicates organization does not maintain inventory of physical devices",
      "risk_level": "High",
      "affected_assets": ["All organizational systems"],
      "evidence_sources": ["Question ID_001: 'No' response confirms gap"],
      "related_questions": ["ID_001"],
      "confidence_score": 0.95
    }
  ],
  "risk_assessment": [
    {
      "risk_id": "RISK_001",
      "title": "No Formal Risk Assessment Process",
      "description": "Organization lacks formal risk assessment procedures for security decision-making",
      "risk_level": "Critical",
      "likelihood": "High - Without formal processes, security risks accumulate over time",
      "impact": "Critical - Unmanaged risks lead to security breaches and compliance violations",
      "nist_function": "Identify",
      "related_gaps": ["GAP_IDENTIFY_001", "GAP_IDENTIFY_002"],
      "mitigation_status": "Not Started",
      "business_impact": "Increased vulnerability to cyber threats, regulatory non-compliance, potential financial/reputational loss"
    }
  ],
  "recommendations": [
    {
      "recommendation_id": "REC_001",
      "title": "Establish Formal Asset Inventory Process",
      "description": "Implement comprehensive asset management by creating and maintaining an up-to-date inventory of all physical and software assets",
      "priority": "High",
      "nist_function": "Identify",
      "related_gaps": ["GAP_IDENTIFY_001"],
      "related_risks": ["RISK_001"],
      "implementation_steps": [
        "Step 1: Collect complete list of all hardware and software assets",
        "Step 2: Document asset characteristics (location, owner, criticality)",
        "Step 3: Set up automated tracking system or configuration management database",
        "Step 4: Establish update and maintenance procedures"
      ],
      "estimated_effort": "3-4 weeks for initial implementation",
      "dependencies": ["Staffing resources", "Asset management tools/software"],
      "success_criteria": [
        "Complete inventory covering 100% of organizational assets",
        "Inventory updated within 30 days of any asset change",
        "80%+ accuracy when validated against physical audit"
      ]
    }
  ]
}

CRITICAL REQUIREMENTS:
1. ALWAYS generate at least one gap for EACH significant "No" response in questionnaire
2. total_gaps MUST equal the count of items in compliance_gaps array
3. Sum of gaps_by_function values MUST equal total_gaps
4. Sum of gaps_by_risk_level values MUST equal total_gaps
5. Include specific control_id values referencing NIST controls
6. Include detailed reasoning explaining WHY each gap exists
7. Generate recommendations that directly address identified gaps
8. compliance_percentage = (YES answers / total questions) * 100
9. overall_risk_score = (Critical gaps × 3) + (High gaps × 2) + (Medium gaps × 1), capped at 10
10. Never return empty arrays for compliance_gaps or recommendations"""

    def _get_nist_framework_description(self) -> str:
        """Get NIST framework description."""
        return """The NIST Cybersecurity Framework provides a policy framework of computer security guidance for private sector organizations in the United States. It consists of standards, guidelines, and practices to promote the protection of critical infrastructure."""
    
    def build_context_for_export(
        self,
        report_data: Dict[str, Any],
        organization_info: OrganizationInfo
    ) -> Dict[str, Any]:
        """
        Build context specifically for report export formatting.
        
        Args:
            report_data: Generated report data
            organization_info: Organization information
            
        Returns:
            Export-ready context dictionary
        """
        return {
            "report_metadata": {
                "generated_at": datetime.now().isoformat(),
                "organization": organization_info.organization_name,
                "assessment_date": organization_info.assessment_date.isoformat(),
                "report_version": "1.0"
            },
            "organization_info": organization_info.dict(),
            "report_content": report_data,
            "export_settings": {
                "include_watermark": False,
                "include_attachments": False,
                "format_version": "1.0"
            }
        }
