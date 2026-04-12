# -*- coding: utf-8 -*-
"""
LLM Service for NIST CSF Compliance Report Generation

This module extends the existing RAG system with:
- Compliance report generation using questionnaire answers
- Structured output parsing with Pydantic models
- Integration with CyberLLaMA/Qwen models
- Error handling for malformed LLM responses
"""

import json
import logging
import os
import time
from typing import Dict, Any, Optional, List
import ollama
from pydantic import ValidationError

from models.report_models import (
    FinalReport, ComplianceGap, RiskItem, Recommendation,
    ComplianceSummary, OrganizationInfo, QuestionAnswer,
    AnalysisContext, RiskLevel, NISTFunction
)
from services.context_builder import ContextBuilder
from services.questionnaire_engine import QuestionnaireEngine
from security_utils import PromptInjectionDefense, InputValidation

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class LLMService:
    """Service for LLM-based compliance analysis and report generation."""
    
    def __init__(self, model_name: str = "qwen2.5:3b", timeout_seconds: int = 300):
        """
        Initialize the LLM service.
        
        Args:
            model_name: Name of the Ollama model to use
            timeout_seconds: Max seconds to wait for an LLM response
        """
        self.model_name = model_name
        self.timeout_seconds = timeout_seconds
        self.max_tokens = int(os.getenv("COMPLYAI_MAX_TOKENS", "4096"))
        self.context_builder = ContextBuilder()
        self.questionnaire_engine = QuestionnaireEngine()
        self._ollama_client = None
        if hasattr(ollama, "Client"):
            try:
                self._ollama_client = ollama.Client(timeout=self.timeout_seconds)
            except Exception as e:
                logger.warning(f"Failed to initialize Ollama client with timeout: {str(e)}")
        self._validate_model_connection()
    
    def _validate_model_connection(self) -> None:
        """Validate that the specified model is available in Ollama."""
        self._ollama_available = False
        try:
            models = ollama.list()
            available_models = [model['model'] for model in models.get('models', [])]
            
            if self.model_name not in available_models:
                logger.warning(f"Model {self.model_name} not found. Available models: {available_models}")
                # Try to use a fallback model
                fallback_models = ["qwen2.5:3b", "llama3.2:3b", "mistral:7b"]
                for fallback in fallback_models:
                    if fallback in available_models:
                        self.model_name = fallback
                        logger.info(f"Using fallback model: {self.model_name}")
                        break
                else:
                    logger.warning(f"No suitable model found. Please install one of: {fallback_models}")
                    return
            
            self._ollama_available = True
            logger.info(f"LLM Service initialized with model: {self.model_name}")
            
        except Exception as e:
            logger.warning(f"Ollama not available: {str(e)}. LLM features will be disabled until Ollama is started.")
    
    def _ensure_ollama_available(self) -> None:
        """Check if Ollama is available, attempt reconnection if not."""
        if not self._ollama_available:
            # Try to reconnect
            self._validate_model_connection()
            if not self._ollama_available:
                raise ConnectionError(
                    "Ollama service is not running. Please start Ollama with 'ollama serve' "
                    "or launch the Ollama application."
                )

    def get_embedding(self, text: str, model_name: str = "qwen3-embedding") -> List[float]:
        """Generate an embedding vector for feedback and retrieval workflows."""
        if not text or not str(text).strip():
            raise ValueError("text is required for embedding generation")

        payload = str(text).strip()
        try:
            resp = ollama.embeddings(model=model_name, prompt=payload)
            emb = resp.get("embedding") if isinstance(resp, dict) else None
            if not emb:
                raise RuntimeError("No embedding returned by Ollama")
            return emb
        except Exception as e:
            raise RuntimeError(f"Embedding generation failed: {e}")
    
    def generate_compliance_report(
        self,
        document_text: str,
        questionnaire_answers: List[QuestionAnswer],
        organization_info: OrganizationInfo,
        nist_controls_context: Optional[Dict[str, Any]] = None
    ) -> FinalReport:
        """
        Generate a comprehensive NIST CSF compliance report.
        
        Args:
            document_text: Extracted text from uploaded documents
            questionnaire_answers: List of questionnaire responses
            organization_info: Organization metadata
            nist_controls_context: Optional NIST controls reference data
            
        Returns:
            FinalReport object with complete compliance assessment
        """
        try:
            # Build analysis context
            context = self.context_builder.build_analysis_context(
                document_text=document_text,
                questionnaire_answers=questionnaire_answers,
                organization_info=organization_info,
                nist_controls_context=nist_controls_context
            )
            
            # Generate LLM prompt
            prompt = self.context_builder.build_llm_prompt(context)
            
            # Call LLM
            llm_response = self._call_llm(prompt)
            
            # Parse and validate response
            parsed_response = self._parse_llm_response(llm_response)
            
            # Build final report
            report = self._build_final_report(
                parsed_response=parsed_response,
                context=context,
                organization_info=organization_info
            )
            
            logger.info(f"Successfully generated compliance report with {len(report.compliance_gaps)} gaps")
            return report
            
        except Exception as e:
            logger.error(f"Error generating compliance report: {str(e)}")
            raise
    
    def _call_llm(self, prompt: str, max_retries: int = 3) -> str:
        """
        Call the LLM with retry logic.
        
        Args:
            prompt: The prompt to send to LLM
            max_retries: Maximum number of retry attempts
            
        Returns:
            LLM response string
        """
        for attempt in range(max_retries):
            try:
                logger.info(f"Calling LLM (attempt {attempt + 1}/{max_retries})")

                if self._ollama_client:
                    response = self._ollama_client.chat(
                        model=self.model_name,
                        messages=[
                            {
                                "role": "system",
                                "content": "You are a senior cybersecurity compliance auditor specializing in NIST CSF assessments. Always respond with valid JSON only."
                            },
                            {
                                "role": "user",
                                "content": prompt
                            }
                        ],
                        options={
                            "temperature": 0.3,  # Lower temperature for more consistent output
                            "top_p": 0.9,
                            "max_tokens": self.max_tokens
                        }
                    )
                else:
                    response = ollama.chat(
                    model=self.model_name,
                    messages=[
                        {
                            "role": "system",
                            "content": "You are a senior cybersecurity compliance auditor specializing in NIST CSF assessments. Always respond with valid JSON only."
                        },
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ],
                    options={
                        "temperature": 0.3,  # Lower temperature for more consistent output
                        "top_p": 0.9,
                        "max_tokens": self.max_tokens
                    },
                    timeout=self.timeout_seconds
                )
                
                response_text = response['message']['content'].strip()
                
                # Validate that response contains JSON
                if not self._is_valid_json_response(response_text):
                    raise ValueError("Response does not contain valid JSON")
                
                logger.info("LLM call successful")
                return response_text
                
            except Exception as e:
                logger.warning(f"LLM call attempt {attempt + 1} failed: {str(e)}")
                if attempt == max_retries - 1:
                    raise Exception(f"LLM call failed after {max_retries} attempts: {str(e)}")
                # Wait before retry
                time.sleep(2 ** attempt)  # Exponential backoff
    
    def _is_valid_json_response(self, response: str) -> bool:
        """Check if response contains valid JSON."""
        try:
            # Try to extract JSON from response
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            
            if json_start == -1 or json_end == 0:
                return False
            
            json_content = response[json_start:json_end]
            json.loads(json_content)
            return True
            
        except (json.JSONDecodeError, ValueError):
            return False
    
    def _parse_llm_response(self, response: str) -> Dict[str, Any]:
        """
        Parse and validate LLM response.
        
        Args:
            response: Raw LLM response string
            
        Returns:
            Parsed response dictionary
        """
        try:
            # Extract JSON from response
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            
            if json_start == -1 or json_end == 0:
                raise ValueError("No JSON found in LLM response")
            
            json_content = response[json_start:json_end]
            parsed_data = json.loads(json_content)
            logger.info(f"LLM JSON response (first 500 chars): {json_content[:500]}")
            logger.info(f"compliance_gaps count: {len(parsed_data.get('compliance_gaps', []))}")
            
            # Validate required structure
            required_sections = ['compliance_summary', 'compliance_gaps', 'risk_assessment', 'recommendations']
            for section in required_sections:
                if section not in parsed_data:
                    logger.warning(f"Missing section '{section}' in LLM response, adding empty structure")
                    parsed_data[section] = []
            
            return parsed_data
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON from LLM response: {str(e)}")
            logger.error(f"Response content: {response[:500]}...")
            raise ValueError("Invalid JSON response from LLM")
    
    def _build_final_report(
        self,
        parsed_response: Dict[str, Any],
        context: AnalysisContext,
        organization_info: OrganizationInfo
    ) -> FinalReport:
        """
        Build the final report object from parsed LLM response.
        
        Args:
            parsed_response: Parsed LLM response data
            context: Analysis context used for generation
            organization_info: Organization information
            
        Returns:
            FinalReport object
        """
        try:
            # Generate unique report ID
            import uuid
            report_id = f"report_{uuid.uuid4().hex[:12]}"
            
            # Build compliance summary - handle string keys for gaps_by_function
            summary_data = parsed_response.get('compliance_summary', {})
            
            # Convert string keys to NISTFunction enum
            gaps_by_function = {}
            raw_gaps_by_func = summary_data.get('gaps_by_function', {})

            if isinstance(raw_gaps_by_func, list):
                # LLM returned gap objects instead of counts; count them by function.
                for item in raw_gaps_by_func:
                    if isinstance(item, dict):
                        func_name = item.get('nist_function', '')
                        try:
                            func_enum = NISTFunction(func_name)
                            gaps_by_function[func_enum] = gaps_by_function.get(func_enum, 0) + 1
                        except ValueError:
                            continue
            elif isinstance(raw_gaps_by_func, dict):
                for func_name, count in raw_gaps_by_func.items():
                    try:
                        func_enum = NISTFunction(func_name)
                        gaps_by_function[func_enum] = count
                    except ValueError:
                        # Skip invalid function names
                        continue
            
            # Convert string keys to RiskLevel enum
            gaps_by_risk_level = {}
            if 'gaps_by_risk_level' in summary_data:
                for risk_name, count in summary_data['gaps_by_risk_level'].items():
                    try:
                        risk_enum = RiskLevel(risk_name)
                        gaps_by_risk_level[risk_enum] = count
                    except ValueError:
                        # Skip invalid risk level names
                        continue
            
            compliance_summary_data = {
                'total_gaps': summary_data.get('total_gaps', 0),
                'gaps_by_function': gaps_by_function,
                'gaps_by_risk_level': gaps_by_risk_level,
                'overall_risk_score': summary_data.get('overall_risk_score', 0.0),
                'compliance_percentage': summary_data.get('compliance_percentage', 0.0),
                'critical_findings': summary_data.get('critical_findings', 0),
                'high_priority_recommendations': summary_data.get('high_priority_recommendations', 0)
            }
            
            compliance_summary = ComplianceSummary(**compliance_summary_data)
            
            # Build compliance gaps
            compliance_gaps = []
            for gap_data in parsed_response.get('compliance_gaps', []):
                try:
                    # Convert string enums to proper enum types
                    # Ensure gap_data is a dictionary
                    if isinstance(gap_data, str):
                        logger.warning(f"Gap data is string, skipping: {gap_data}")
                        continue
                    gap_data_copy = gap_data.copy()
                    
                    # Convert nist_function string to enum
                    if 'nist_function' in gap_data_copy:
                        try:
                            gap_data_copy['nist_function'] = NISTFunction(gap_data_copy['nist_function'])
                        except ValueError:
                            gap_data_copy['nist_function'] = NISTFunction.IDENTIFY  # Default
                    
                    # Convert risk_level string to enum
                    if 'risk_level' in gap_data_copy:
                        try:
                            gap_data_copy['risk_level'] = RiskLevel(gap_data_copy['risk_level'])
                        except ValueError:
                            gap_data_copy['risk_level'] = RiskLevel.MEDIUM  # Default
                    
                    gap = ComplianceGap(**gap_data_copy)
                    compliance_gaps.append(gap)
                except ValidationError as e:
                    logger.warning(f"Invalid compliance gap data: {str(e)}")
                    continue
            
            # If no gaps found, create default gaps from negative answers
            if not compliance_gaps:
                logger.info("No compliance gaps from LLM, generating from questionnaire answers")
                compliance_gaps = self._generate_gaps_from_answers(context.questionnaire_answers)
            
            # Build risk assessment
            risk_assessment = []
            for risk_data in parsed_response.get('risk_assessment', []):
                try:
                    # Convert string enums to proper enum types
                    # Ensure risk_data is a dictionary
                    if isinstance(risk_data, str):
                        logger.warning(f"Risk data is string, skipping: {risk_data}")
                        continue
                    risk_data_copy = risk_data.copy()
                    
                    # Convert nist_function string to enum
                    if 'nist_function' in risk_data_copy:
                        try:
                            risk_data_copy['nist_function'] = NISTFunction(risk_data_copy['nist_function'])
                        except ValueError:
                            risk_data_copy['nist_function'] = NISTFunction.IDENTIFY  # Default
                    
                    # Convert risk_level string to enum
                    if 'risk_level' in risk_data_copy:
                        try:
                            risk_data_copy['risk_level'] = RiskLevel(risk_data_copy['risk_level'])
                        except ValueError:
                            risk_data_copy['risk_level'] = RiskLevel.MEDIUM  # Default
                    
                    risk = RiskItem(**risk_data_copy)
                    risk_assessment.append(risk)
                except ValidationError as e:
                    logger.warning(f"Invalid risk item data: {str(e)}")
                    continue
            
            # If no risk assessment, generate from gaps
            if not risk_assessment and compliance_gaps:
                logger.info("No risk assessment from LLM, generating from gaps")
                risk_assessment = self._generate_risk_assessment_from_gaps(compliance_gaps)
            
            # Build recommendations
            recommendations = []
            for rec_data in parsed_response.get('recommendations', []):
                try:
                    # Convert string enums to proper enum types
                    # Ensure rec_data is a dictionary
                    if isinstance(rec_data, str):
                        logger.warning(f"Recommendation data is string, skipping: {rec_data}")
                        continue
                    rec_data_copy = rec_data.copy()
                    
                    # Convert nist_function string to enum
                    if 'nist_function' in rec_data_copy:
                        try:
                            rec_data_copy['nist_function'] = NISTFunction(rec_data_copy['nist_function'])
                        except ValueError:
                            rec_data_copy['nist_function'] = NISTFunction.IDENTIFY  # Default
                    
                    recommendation = Recommendation(**rec_data_copy)
                    recommendations.append(recommendation)
                except ValidationError as e:
                    logger.warning(f"Invalid recommendation data: {str(e)}")
                    continue
            
            # If no recommendations, generate from gaps
            if not recommendations:
                logger.info("No recommendations from LLM, generating from gaps")
                recommendations = self._generate_recommendations_from_gaps(compliance_gaps)
            
            # Recalculate compliance summary based on actual gaps
            # This ensures consistency even if LLM didn't calculate correctly
            compliance_summary = self._recalculate_compliance_summary(
                compliance_gaps=compliance_gaps,
                questionnaire_answers=context.questionnaire_answers,
                recommendations=recommendations
            )
            
            # Create final report
            report = FinalReport(
                report_id=report_id,
                organization_info=organization_info,
                compliance_summary=compliance_summary,
                questionnaire_answers=context.questionnaire_answers,
                compliance_gaps=compliance_gaps,
                risk_assessment=risk_assessment,
                recommendations=recommendations,
                document_analysis={
                    "document_text_length": len(context.document_text),
                    "questionnaire_responses": len(context.questionnaire_answers),
                    "nist_functions_assessed": list(set(q.nist_function for q in context.questionnaire_answers))
                },
                metadata={
                    "llm_model": self.model_name,
                    "analysis_timestamp": context.organization_metadata.get("assessment_date"),
                    "context_size": len(str(context))
                }
            )
            
            return report
            
        except Exception as e:
            logger.error(f"Error building final report: {str(e)}")
            raise
    
    def _generate_gaps_from_answers(self, answers: List[QuestionAnswer]) -> List[ComplianceGap]:
        """
        Generate compliance gaps from questionnaire answers with negative responses.
        
        Args:
            answers: List of questionnaire responses
            
        Returns:
            List of generated ComplianceGap objects
        """
        gaps = []
        gap_id_counter = 1
        
        for answer in answers:
            answer_lower = answer.answer.lower()
            # Check if answer indicates a gap
            is_negative = any(keyword in answer_lower for keyword in 
                            ['no', 'none', 'never', 'lack', 'missing', 'inadequate', 
                             'no plan', 'not implemented', 'not in place', 'not defined'])
            
            if is_negative:
                # Create a gap for this negative answer
                gap = ComplianceGap(
                    gap_id=f"GAP_{answer.nist_function.value.upper()}_{gap_id_counter:03d}",
                    control_id=f"{answer.nist_function.value[0:2].upper()}.{answer.category.replace(' ', '_')}.{gap_id_counter:03d}",
                    control_title=f"{answer.category} - {answer.subcategory}",
                    nist_function=answer.nist_function,
                    category=answer.category,
                    subcategory=answer.subcategory,
                    description=f"Not formally implemented: {answer.question_text}",
                    reasoning=f"Questionnaire response indicates this control is not in place: {answer.answer}",
                    risk_level=self._determine_risk_level_for_gap(answer),
                    affected_assets=[],
                    evidence_sources=[f"Question: {answer.question_id}", f"Answer: {answer.answer}"],
                    related_questions=[answer.question_id],
                    confidence_score=answer.confidence if answer.confidence else 0.85
                )
                gaps.append(gap)
                gap_id_counter += 1
        
        return gaps
    
    def _determine_risk_level_for_gap(self, answer: QuestionAnswer) -> RiskLevel:
        """Determine risk level based on question category."""
        category_lower = answer.category.lower()
        
        # Critical control categories
        critical_keywords = ['risk assessment', 'incident response', 'access control', 
                            'identity management', 'authentication']
        if any(keyword in category_lower for keyword in critical_keywords):
            return RiskLevel.CRITICAL
        
        # High priority categories
        high_keywords = ['asset management', 'awareness', 'training', 'backup', 'recovery',
                        'detection', 'monitoring', 'encryption', 'data protection']
        if any(keyword in category_lower for keyword in high_keywords):
            return RiskLevel.HIGH
        
        # Medium priority by default
        return RiskLevel.MEDIUM
    
    def _recalculate_compliance_summary(
        self,
        compliance_gaps: List[ComplianceGap],
        questionnaire_answers: List[QuestionAnswer],
        recommendations: List[Recommendation]
    ) -> ComplianceSummary:
        """
        Recalculate compliance summary metrics based on actual gaps and answers.
        
        Args:
            compliance_gaps: List of identified gaps
            questionnaire_answers: List of questionnaire responses
            recommendations: List of recommendations
            
        Returns:
            Updated ComplianceSummary object
        """
        # Count gaps by function
        gaps_by_function = {}
        for gap in compliance_gaps:
            func = gap.nist_function
            gaps_by_function[func] = gaps_by_function.get(func, 0) + 1
        
        # Ensure all functions are represented
        for func in NISTFunction:
            if func not in gaps_by_function:
                gaps_by_function[func] = 0
        
        # Count gaps by risk level
        gaps_by_risk_level = {}
        for gap in compliance_gaps:
            level = gap.risk_level
            gaps_by_risk_level[level] = gaps_by_risk_level.get(level, 0) + 1
        
        # Ensure all risk levels are represented
        for level in RiskLevel:
            if level not in gaps_by_risk_level:
                gaps_by_risk_level[level] = 0
        
        # Calculate compliance percentage using questionnaire engine's proper maturity level evaluation
        # This correctly handles maturity scale questions (levels 1-4) instead of simple yes/no matching
        try:
            compliance_by_function = self.questionnaire_engine.compute_compliance_by_function(questionnaire_answers)
            # Get overall compliance percentage
            compliance_percentage = compliance_by_function.get('overall', 0.0)
        except Exception as e:
            logger.warning(f"Failed to compute compliance by function: {e}. Using fallback calculation.")
            # Fallback: simple yes/no detection if questionnaire engine fails
            total_questions = len(questionnaire_answers)
            compliant_answers = sum(1 for a in questionnaire_answers 
                                   if a.answer and any(keyword in str(a.answer).lower() 
                                                      for keyword in ['established', '4 –', '4 -', 'implemented']))
            compliance_percentage = (compliant_answers / total_questions * 100) if total_questions > 0 else 0.0
        
        # Calculate overall risk score (0-10)
        risk_score = min(10, 
            gaps_by_risk_level.get(RiskLevel.CRITICAL, 0) * 3 +
            gaps_by_risk_level.get(RiskLevel.HIGH, 0) * 2 +
            gaps_by_risk_level.get(RiskLevel.MEDIUM, 0) * 1
        )
        
        # Count high priority recommendations
        high_priority_recs = sum(1 for r in recommendations if r.priority == 'High')
        
        return ComplianceSummary(
            total_gaps=len(compliance_gaps),
            gaps_by_function=gaps_by_function,
            gaps_by_risk_level=gaps_by_risk_level,
            overall_risk_score=float(risk_score),
            compliance_percentage=float(compliance_percentage),
            critical_findings=gaps_by_risk_level.get(RiskLevel.CRITICAL, 0),
            high_priority_recommendations=high_priority_recs
        )
    
    def _generate_risk_assessment_from_gaps(self, gaps: List[ComplianceGap]) -> List[RiskItem]:
        """
        Generate risk assessment items from identified compliance gaps.
        
        Args:
            gaps: List of identified compliance gaps
            
        Returns:
            List of generated RiskItem objects
        """
        risk_items = []
        risk_id_counter = 1
        
        # Group gaps by NIST function to create consolidated risk items
        gaps_by_function = {}
        for gap in gaps:
            func = gap.nist_function
            if func not in gaps_by_function:
                gaps_by_function[func] = []
            gaps_by_function[func].append(gap)
        
        # Create risk item for each function with gaps
        for function, function_gaps in gaps_by_function.items():
            # Find the most critical gap in this function
            critical_gaps = [g for g in function_gaps if g.risk_level == RiskLevel.CRITICAL]
            high_gaps = [g for g in function_gaps if g.risk_level == RiskLevel.HIGH]
            
            if critical_gaps or high_gaps:
                most_critical = critical_gaps[0] if critical_gaps else high_gaps[0]
                risk_level = most_critical.risk_level
                
                # Determine likelihood and impact
                if risk_level == RiskLevel.CRITICAL:
                    likelihood = "High - Critical control missing, vulnerability highly probable"
                    impact = "Critical - Business operations or compliance severely impacted"
                elif risk_level == RiskLevel.HIGH:
                    likelihood = "Medium-High - Important control missing, higher probability of incident"
                    impact = "High - Significant operational or compliance impact possible"
                else:
                    likelihood = "Medium - Control gap could be exploited"
                    impact = "Medium - Moderate operational or compliance impact"
                
                # Create risk item
                risk_item = RiskItem(
                    risk_id=f"RISK_{function.value.upper()}_{risk_id_counter:03d}",
                    title=f"{function.value} Function Control Gaps",
                    description=f"{len(function_gaps)} control gaps identified in {function.value} function. " +
                               f"Most critical: {most_critical.control_title}",
                    risk_level=risk_level,
                    likelihood=likelihood,
                    impact=impact,
                    nist_function=function,
                    related_gaps=[g.gap_id for g in function_gaps],
                    mitigation_status="Not Started",
                    business_impact=f"Unaddressed {function.value} controls may lead to security incidents, " +
                                   f"data breaches, or regulatory non-compliance"
                )
                
                risk_items.append(risk_item)
                risk_id_counter += 1
        
        return risk_items
    
    def _generate_recommendations_from_gaps(self, gaps: List[ComplianceGap]) -> List[Recommendation]:
        """
        Generate recommendations from identified compliance gaps.
        
        Args:
            gaps: List of identified compliance gaps
            
        Returns:
            List of generated Recommendation objects
        """
        recommendations = []
        rec_id_counter = 1
        
        for gap in gaps:
            # Determine priority based on risk level
            if gap.risk_level == RiskLevel.CRITICAL:
                priority = "High"
            elif gap.risk_level == RiskLevel.HIGH:
                priority = "High"
            elif gap.risk_level == RiskLevel.MEDIUM:
                priority = "Medium"
            else:
                priority = "Low"
            
            # Generate recommendation title and description
            title = f"Implement {gap.control_title}"
            description = f"Establish and document {gap.category.lower()} controls as specified in NIST CSF. Current state: {gap.description}"
            
            # Generate implementation steps
            steps = [
                f"Step 1: Define requirements and scope for {gap.subcategory}",
                f"Step 2: Select and acquire necessary tools or solutions",
                f"Step 3: Configure and deploy {gap.subcategory} controls",
                f"Step 4: Test and validate implementation",
                f"Step 5: Document procedures and provide user training"
            ]
            
            # Estimate effort based on category
            if "inventory" in gap.subcategory.lower() or "planning" in gap.subcategory.lower():
                effort = "2-3 weeks"
            elif "training" in gap.subcategory.lower() or "awareness" in gap.subcategory.lower():
                effort = "1-2 weeks"
            elif "incident" in gap.category.lower() or "response" in gap.category.lower():
                effort = "3-4 weeks"
            else:
                effort = "2-4 weeks"
            
            recommendation = Recommendation(
                recommendation_id=f"REC_{gap.nist_function.value.upper()}_{rec_id_counter:03d}",
                title=title,
                description=description,
                priority=priority,
                nist_function=gap.nist_function,
                related_gaps=[gap.gap_id],
                related_risks=[],
                implementation_steps=steps,
                estimated_effort=effort,
                dependencies=["Personnel resources", "Budget allocation"],
                success_criteria=[
                    "Control implemented and documented",
                    "Personnel trained and competent",
                    "Compliance verified through testing",
                    "Monitoring and maintenance procedures established"
                ]
            )
            
            recommendations.append(recommendation)
            rec_id_counter += 1
        
        return recommendations
    
    def generate_quick_assessment(
        self,
        questionnaire_answers: List[QuestionAnswer],
        organization_info: OrganizationInfo
    ) -> Dict[str, Any]:
        """
        Generate a quick compliance assessment based only on questionnaire answers.
        
        Args:
            questionnaire_answers: List of questionnaire responses
            organization_info: Organization metadata
            
        Returns:
            Quick assessment dictionary
        """
        # Validate input size
        for answer in questionnaire_answers:
            InputValidation.validate_string(answer.get('answer', ''), max_length=5000)
        
        try:
            # Build simplified context
            context = self.context_builder.build_analysis_context(
                document_text="",
                questionnaire_answers=questionnaire_answers,
                organization_info=organization_info
            )
            
            # Create simplified prompt for quick assessment
            # (user input is sanitized by context_builder._format_questionnaire_answers)
            prompt = f"""Based on the following NIST CSF questionnaire responses (user input is sanitized), provide a quick compliance assessment:

{self.context_builder._format_questionnaire_answers(questionnaire_answers)}

Provide a JSON response with:
{{
  "overall_risk_level": "Low/Medium/High/Critical",
  "compliance_score": <0-100>,
  "key_findings": ["finding1", "finding2"],
  "immediate_actions": ["action1", "action2"],
  "recommended_next_steps": ["step1", "step2"]
}}"""
            
            response = self._call_llm(prompt)
            parsed_response = self._parse_llm_response(response)
            
            return parsed_response
            
        except Exception as e:
            logger.error(f"Error generating quick assessment: {str(e)}")
            raise
    
    def validate_report_quality(self, report: FinalReport) -> Dict[str, Any]:
        """
        Validate the quality and completeness of a generated report.
        
        Args:
            report: FinalReport object to validate
            
        Returns:
            Validation results dictionary
        """
        validation_results = {
            "is_valid": True,
            "warnings": [],
            "errors": [],
            "quality_score": 0.0
        }
        
        try:
            # Check basic structure
            if not report.compliance_gaps:
                validation_results["warnings"].append("No compliance gaps identified")
            
            if not report.recommendations:
                validation_results["errors"].append("No recommendations provided")
                validation_results["is_valid"] = False
            
            # Check data consistency
            total_gaps = len(report.compliance_gaps)
            summary_gaps = report.compliance_summary.total_gaps
            
            if total_gaps != summary_gaps:
                validation_results["warnings"].append(f"Gap count mismatch: {total_gaps} vs {summary_gaps}")
            
            # Calculate quality score
            quality_factors = {
                "has_gaps": 1.0 if report.compliance_gaps else 0.0,
                "has_recommendations": 1.0 if report.recommendations else 0.0,
                "has_risk_assessment": 1.0 if report.risk_assessment else 0.0,
                "consistent_data": 1.0 if total_gaps == summary_gaps else 0.5,
                "detailed_gaps": 1.0 if all(g.confidence_score > 0.5 for g in report.compliance_gaps) else 0.7
            }
            
            validation_results["quality_score"] = sum(quality_factors.values()) / len(quality_factors)
            
            # Determine overall validity
            validation_results["is_valid"] = (
                validation_results["quality_score"] >= 0.6 and 
                len(validation_results["errors"]) == 0
            )
            
        except Exception as e:
            validation_results["errors"].append(f"Validation error: {str(e)}")
            validation_results["is_valid"] = False
        
        return validation_results
