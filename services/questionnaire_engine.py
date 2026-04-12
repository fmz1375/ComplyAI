# -*- coding: utf-8 -*-
"""
NIST CSF Questionnaire Engine

This module handles:
- Parsing NIST CSF questions from HTML template
- Dynamic question generation based on selected functions
- Question categorization and management
- Answer validation and processing
"""

import os
import re
from typing import List, Dict, Any, Optional, Set
from bs4 import BeautifulSoup

from models.report_models import (
    QuestionAnswer, QuestionnaireTemplate, 
    NISTFunction, QuestionType
)

# Standard 4-level maturity scale used for all "Do you..." questions
MATURITY_SCALE = [
    "1 – Not implemented: No process or control exists",
    "2 – Initial: Ad hoc or informal approach, not consistently applied",
    "3 – Developing: Partially implemented or in progress",
    "4 – Established: Fully implemented, documented, and consistently applied"
]


class QuestionnaireEngine:
    """Engine for managing NIST CSF questionnaire generation and processing."""
    
    def __init__(self, html_template_path: str = "NIST CSF Compliance Questionnaire.html"):
        """
        Initialize the questionnaire engine.
        
        Args:
            html_template_path: Path to the HTML template file
        """
        self.html_template_path = html_template_path
        self._questions_cache: Dict[NISTFunction, List[Dict[str, Any]]] = {}
        self._load_questions()
    
    def _load_questions(self) -> None:
        """Load and parse questions from the HTML template."""
        try:
            with open(self.html_template_path, 'r', encoding='utf-8') as file:
                html_content = file.read()
            
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Parse questions for each NIST function
            for function in NISTFunction:
                questions = self._extract_function_questions(soup, function)
                self._questions_cache[function] = questions
                
        except Exception as e:
            print(f"Failed to load questionnaire template: {str(e)}")
            # Create fallback questions if HTML parsing fails
            self._create_fallback_questions()
    
    def _extract_function_questions(self, soup: BeautifulSoup, function: NISTFunction) -> List[Dict[str, Any]]:
        """
        Extract questions for a specific NIST function from HTML.
        
        Args:
            soup: BeautifulSoup object of the HTML template
            function: NIST function to extract questions for
            
        Returns:
            List of question dictionaries
        """
        questions = []
        function_lower = function.value.lower()
        
        # Create sample questions for each function if HTML parsing fails
        sample_questions = self._get_sample_questions(function)
        
        return sample_questions
    
    def _get_sample_questions(self, function: NISTFunction) -> List[Dict[str, Any]]:
        """Get sample questions for each NIST function."""
        questions_map = {
            NISTFunction.GOVERN: [
                # Organizational Context (GV.OC) - 3 questions
                {
                    'question_id': "GV_001",
                    'question_text': "Has your organization documented its mission, objectives, and how cybersecurity supports achieving them?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.GOVERN,
                    'category': "Organizational Context",
                    'subcategory': "GV.OC-01",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 1
                },
                {
                    'question_id': "GV_002",
                    'question_text': "Have you identified all stakeholders (internal and external) who have expectations regarding your cybersecurity?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.GOVERN,
                    'category': "Organizational Context",
                    'subcategory': "GV.OC-02",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 2
                },
                {
                    'question_id': "GV_003",
                    'question_text': "Do you maintain a current register of legal, regulatory, and contractual cybersecurity requirements applicable to your organization?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.GOVERN,
                    'category': "Organizational Context",
                    'subcategory': "GV.OC-03",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 3
                },
                # Risk Management Strategy (GV.RM) - 5 questions
                {
                    'question_id': "GV_004",
                    'question_text': "Has leadership established documented cybersecurity risk management objectives?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.GOVERN,
                    'category': "Risk Management Strategy",
                    'subcategory': "GV.RM-01",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 4
                },
                {
                    'question_id': "GV_005",
                    'question_text': "Does your organization have documented statements of risk appetite and risk tolerance?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.GOVERN,
                    'category': "Risk Management Strategy",
                    'subcategory': "GV.RM-02",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 5
                },
                {
                    'question_id': "GV_006",
                    'question_text': "Is cybersecurity risk management integrated into your enterprise risk management (ERM) program?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.GOVERN,
                    'category': "Risk Management Strategy",
                    'subcategory': "GV.RM-03",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 6
                },
                {
                    'question_id': "GV_007",
                    'question_text': "Do you have a standardized method for calculating, documenting, and prioritizing cybersecurity risks?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.GOVERN,
                    'category': "Risk Management Strategy",
                    'subcategory': "GV.RM-06",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 7
                },
                {
                    'question_id': "GV_008",
                    'question_text': "Are there established communication channels for reporting cybersecurity risks across the organization?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.GOVERN,
                    'category': "Risk Management Strategy",
                    'subcategory': "GV.RM-05",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 8
                },
                # Roles, Responsibilities, and Authorities (GV.RR) - 4 questions
                {
                    'question_id': "GV_009",
                    'question_text': "Are cybersecurity roles, responsibilities, and authorities clearly defined and documented?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.GOVERN,
                    'category': "Roles & Responsibilities",
                    'subcategory': "GV.RR-02",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 9
                },
                {
                    'question_id': "GV_010",
                    'question_text': "Has leadership allocated adequate budget and resources for cybersecurity activities?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.GOVERN,
                    'category': "Roles & Responsibilities",
                    'subcategory': "GV.RR-03",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 10
                },
                {
                    'question_id': "GV_011",
                    'question_text': "Are cybersecurity considerations included in human resources practices (hiring, onboarding, offboarding)?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.GOVERN,
                    'category': "Roles & Responsibilities",
                    'subcategory': "GV.RR-04",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 11
                },
                {
                    'question_id': "GV_012",
                    'question_text': "Does organizational leadership demonstrate accountability for cybersecurity risk management?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.GOVERN,
                    'category': "Roles & Responsibilities",
                    'subcategory': "GV.RR-01",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 12
                },
                # Policy (GV.PO) - 2 questions
                {
                    'question_id': "GV_013",
                    'question_text': "Do you have a formal cybersecurity policy approved by leadership and communicated to all personnel?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.GOVERN,
                    'category': "Policy",
                    'subcategory': "GV.PO-01",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 13
                },
                {
                    'question_id': "GV_014",
                    'question_text': "Is your cybersecurity policy reviewed and updated at least annually?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.GOVERN,
                    'category': "Policy",
                    'subcategory': "GV.PO-02",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 14
                },
                # Cybersecurity Supply Chain Risk Management (GV.SC) - 1 question
                {
                    'question_id': "GV_015",
                    'question_text': "Do you have a program for managing cybersecurity risks from suppliers and third-party service providers?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.GOVERN,
                    'category': "Supply Chain Risk Management",
                    'subcategory': "GV.SC-01",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 15
                }
            ],
            NISTFunction.IDENTIFY: [
                # Asset Management (ID.AM) - 7 questions
                {
                    'question_id': "ID_001",
                    'question_text': "Do you maintain an inventory of hardware assets (servers, workstations, network devices)?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.IDENTIFY,
                    'category': "Asset Management",
                    'subcategory': "ID.AM-01",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 1
                },
                {
                    'question_id': "ID_002",
                    'question_text': "Do you maintain an inventory of software applications and services?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.IDENTIFY,
                    'category': "Asset Management",
                    'subcategory': "ID.AM-02",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 2
                },
                {
                    'question_id': "ID_003",
                    'question_text': "Do you maintain documentation of network architecture and authorized data flows?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.IDENTIFY,
                    'category': "Asset Management",
                    'subcategory': "ID.AM-03",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 3
                },
                {
                    'question_id': "ID_004",
                    'question_text': "Do you maintain an inventory of external services provided by suppliers?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.IDENTIFY,
                    'category': "Asset Management",
                    'subcategory': "ID.AM-04",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 4
                },
                {
                    'question_id': "ID_005",
                    'question_text': "Have you classified and prioritized assets based on their criticality to business operations?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.IDENTIFY,
                    'category': "Asset Management",
                    'subcategory': "ID.AM-05",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 5
                },
                {
                    'question_id': "ID_006",
                    'question_text': "Do you maintain an inventory of organizational data and data types?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.IDENTIFY,
                    'category': "Asset Management",
                    'subcategory': "ID.AM-07",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 6
                },
                {
                    'question_id': "ID_007",
                    'question_text': "Are assets managed throughout their entire lifecycle (acquisition, deployment, maintenance, disposal)?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.IDENTIFY,
                    'category': "Asset Management",
                    'subcategory': "ID.AM-08",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 7
                },
                # Risk Assessment (ID.RA) - 6 questions
                {
                    'question_id': "ID_008",
                    'question_text': "Do you regularly identify and document vulnerabilities in your systems and applications?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.IDENTIFY,
                    'category': "Risk Assessment",
                    'subcategory': "ID.RA-01",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 8
                },
                {
                    'question_id': "ID_009",
                    'question_text': "Do you receive and review cyber threat intelligence?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.IDENTIFY,
                    'category': "Risk Assessment",
                    'subcategory': "ID.RA-02",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 9
                },
                {
                    'question_id': "ID_010",
                    'question_text': "Have you identified and documented threats (internal and external) to your organization?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.IDENTIFY,
                    'category': "Risk Assessment",
                    'subcategory': "ID.RA-03",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 10
                },
                {
                    'question_id': "ID_011",
                    'question_text': "Do you conduct risk assessments that evaluate likelihood and impact of threats?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.IDENTIFY,
                    'category': "Risk Assessment",
                    'subcategory': "ID.RA-04",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 11
                },
                {
                    'question_id': "ID_012",
                    'question_text': "Are risk response decisions (mitigate, transfer, avoid, accept) documented and tracked?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.IDENTIFY,
                    'category': "Risk Assessment",
                    'subcategory': "ID.RA-06",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 12
                },
                {
                    'question_id': "ID_013",
                    'question_text': "Do you have a process for receiving and responding to vulnerability disclosures?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.IDENTIFY,
                    'category': "Risk Assessment",
                    'subcategory': "ID.RA-08",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 13
                },
                # Improvement (ID.IM) - 2 questions
                {
                    'question_id': "ID_014",
                    'question_text': "Do you conduct regular evaluations (audits, assessments) to identify cybersecurity improvements?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.IDENTIFY,
                    'category': "Improvement",
                    'subcategory': "ID.IM-01",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 14
                },
                {
                    'question_id': "ID_015",
                    'question_text': "Do you conduct security testing and exercises to identify areas for improvement?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.IDENTIFY,
                    'category': "Improvement",
                    'subcategory': "ID.IM-02",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 15
                }
            ],
            NISTFunction.PROTECT: [
                # Identity Management, Authentication, and Access Control (PR.AA) - 7 questions
                {
                    'question_id': "PR_001",
                    'question_text': "Do users access systems using unique user identifiers?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.PROTECT,
                    'category': "Identity & Access Control",
                    'subcategory': "PR.AA-01",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 1
                },
                {
                    'question_id': "PR_002",
                    'question_text': "Do you implement multi-factor authentication (MFA) for accessing critical systems?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.PROTECT,
                    'category': "Identity & Access Control",
                    'subcategory': "PR.AA-03",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 2
                },
                {
                    'question_id': "PR_003",
                    'question_text': "Are access permissions based on the principle of least privilege?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.PROTECT,
                    'category': "Identity & Access Control",
                    'subcategory': "PR.AA-05",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 3
                },
                {
                    'question_id': "PR_004",
                    'question_text': "Do you periodically review and recertify user access rights?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.PROTECT,
                    'category': "Identity & Access Control",
                    'subcategory': "PR.AA-05",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 4
                },
                {
                    'question_id': "PR_005",
                    'question_text': "Are access rights promptly removed when users change roles or leave the organization?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.PROTECT,
                    'category': "Identity & Access Control",
                    'subcategory': "PR.AA-01",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 5
                },
                {
                    'question_id': "PR_006",
                    'question_text': "Do you have physical access controls for facilities containing sensitive systems?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.PROTECT,
                    'category': "Identity & Access Control",
                    'subcategory': "PR.AA-06",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 6
                },
                {
                    'question_id': "PR_007",
                    'question_text': "Do you manage and control privileged/administrative accounts separately from regular user accounts?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.PROTECT,
                    'category': "Identity & Access Control",
                    'subcategory': "PR.AA-05",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 7
                },
                # Awareness and Training (PR.AT) - 2 questions
                {
                    'question_id': "PR_008",
                    'question_text': "Do all personnel receive cybersecurity awareness training?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.PROTECT,
                    'category': "Awareness & Training",
                    'subcategory': "PR.AT-01",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 8
                },
                {
                    'question_id': "PR_009",
                    'question_text': "Do personnel in specialized roles receive role-specific cybersecurity training?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.PROTECT,
                    'category': "Awareness & Training",
                    'subcategory': "PR.AT-02",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 9
                },
                # Data Security (PR.DS) - 4 questions
                {
                    'question_id': "PR_010",
                    'question_text': "Do you encrypt sensitive data when stored (data-at-rest)?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.PROTECT,
                    'category': "Data Security",
                    'subcategory': "PR.DS-01",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 10
                },
                {
                    'question_id': "PR_011",
                    'question_text': "Do you encrypt sensitive data when transmitted over networks (data-in-transit)?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.PROTECT,
                    'category': "Data Security",
                    'subcategory': "PR.DS-02",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 11
                },
                {
                    'question_id': "PR_012",
                    'question_text': "Do you maintain regular backups of critical systems and data?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.PROTECT,
                    'category': "Data Security",
                    'subcategory': "PR.DS-11",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 12
                },
                {
                    'question_id': "PR_013",
                    'question_text': "Do you test backup restoration procedures?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.PROTECT,
                    'category': "Data Security",
                    'subcategory': "PR.DS-11",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 13
                },
                # Platform Security (PR.PS) - 5 questions
                {
                    'question_id': "PR_014",
                    'question_text': "Do you have a configuration management process for systems (security baselines, hardening)?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.PROTECT,
                    'category': "Platform Security",
                    'subcategory': "PR.PS-01",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 14
                },
                {
                    'question_id': "PR_015",
                    'question_text': "Do you apply security patches and updates in a timely manner?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.PROTECT,
                    'category': "Platform Security",
                    'subcategory': "PR.PS-02",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 15
                },
                {
                    'question_id': "PR_016",
                    'question_text': "Do you maintain hardware assets according to manufacturer recommendations?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.PROTECT,
                    'category': "Platform Security",
                    'subcategory': "PR.PS-03",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 16
                },
                {
                    'question_id': "PR_017",
                    'question_text': "Do systems generate logs for security-relevant events?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.PROTECT,
                    'category': "Platform Security",
                    'subcategory': "PR.PS-04",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 17
                },
                {
                    'question_id': "PR_018",
                    'question_text': "Do you prevent installation and execution of unauthorized software?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.PROTECT,
                    'category': "Platform Security",
                    'subcategory': "PR.PS-05",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 18
                },
                # Technology Infrastructure Resilience (PR.IR) - 2 questions
                {
                    'question_id': "PR_019",
                    'question_text': "Do you implement network security controls (firewalls, segmentation)?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.PROTECT,
                    'category': "Infrastructure Resilience",
                    'subcategory': "PR.IR-01",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 19
                },
                {
                    'question_id': "PR_020",
                    'question_text': "Do you have redundancy for critical systems to ensure availability?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.PROTECT,
                    'category': "Infrastructure Resilience",
                    'subcategory': "PR.IR-03",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 20
                }
            ],
            NISTFunction.DETECT: [
                # Continuous Monitoring (DE.CM) - 6 questions
                {
                    'question_id': "DE_001",
                    'question_text': "Do you monitor network traffic for anomalies and suspicious activity?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.DETECT,
                    'category': "Continuous Monitoring",
                    'subcategory': "DE.CM-01",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 1
                },
                {
                    'question_id': "DE_002",
                    'question_text': "Do you monitor physical access to facilities?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.DETECT,
                    'category': "Continuous Monitoring",
                    'subcategory': "DE.CM-02",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 2
                },
                {
                    'question_id': "DE_003",
                    'question_text': "Do you monitor user activities for suspicious behavior?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.DETECT,
                    'category': "Continuous Monitoring",
                    'subcategory': "DE.CM-03",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 3
                },
                {
                    'question_id': "DE_004",
                    'question_text': "Do you monitor external service provider activities?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.DETECT,
                    'category': "Continuous Monitoring",
                    'subcategory': "DE.CM-06",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 4
                },
                {
                    'question_id': "DE_005",
                    'question_text': "Do you monitor systems and applications for security events?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.DETECT,
                    'category': "Continuous Monitoring",
                    'subcategory': "DE.CM-09",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 5
                },
                {
                    'question_id': "DE_006",
                    'question_text': "How quickly can you detect unauthorized access attempts?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.DETECT,
                    'category': "Continuous Monitoring",
                    'subcategory': "DE.CM-01",
                    'options': [
                        "1 – Not implemented: No detection capability exists",
                        "2 – Initial: Detection is manual and may take days or longer",
                        "3 – Developing: Detection typically occurs within hours to 24 hours",
                        "4 – Established: Real-time or near real-time automated detection"
                    ],
                    'required': True,
                    'order': 6
                },
                # Adverse Event Analysis (DE.AE) - 4 questions
                {
                    'question_id': "DE_007",
                    'question_text': "Do you analyze detected anomalies and events to determine if they are security incidents?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.DETECT,
                    'category': "Adverse Event Analysis",
                    'subcategory': "DE.AE-02",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 7
                },
                {
                    'question_id': "DE_008",
                    'question_text': "Do you correlate security events from multiple sources?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.DETECT,
                    'category': "Adverse Event Analysis",
                    'subcategory': "DE.AE-03",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 8
                },
                {
                    'question_id': "DE_009",
                    'question_text': "Do you have defined criteria for declaring a security incident?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.DETECT,
                    'category': "Adverse Event Analysis",
                    'subcategory': "DE.AE-08",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 9
                },
                {
                    'question_id': "DE_010",
                    'question_text': "Do you use threat intelligence to analyze detected events?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.DETECT,
                    'category': "Adverse Event Analysis",
                    'subcategory': "DE.AE-07",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 10
                }
            ],
            NISTFunction.RESPOND: [
                # Incident Management (RS.MA) - 3 questions
                {
                    'question_id': "RS_001",
                    'question_text': "Do you have a documented incident response plan?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.RESPOND,
                    'category': "Incident Management",
                    'subcategory': "RS.MA-01",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 1
                },
                {
                    'question_id': "RS_002",
                    'question_text': "Do you categorize and prioritize incidents based on severity?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.RESPOND,
                    'category': "Incident Management",
                    'subcategory': "RS.MA-03",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 2
                },
                {
                    'question_id': "RS_003",
                    'question_text': "Do you have an escalation process for critical incidents?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.RESPOND,
                    'category': "Incident Management",
                    'subcategory': "RS.MA-04",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 3
                },
                # Incident Analysis (RS.AN) - 2 questions
                {
                    'question_id': "RS_004",
                    'question_text': "Do you conduct root cause analysis after incidents?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.RESPOND,
                    'category': "Incident Analysis",
                    'subcategory': "RS.AN-03",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 4
                },
                {
                    'question_id': "RS_005",
                    'question_text': "Do you collect and preserve evidence during incident investigations?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.RESPOND,
                    'category': "Incident Analysis",
                    'subcategory': "RS.AN-07",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 5
                },
                # Incident Response Reporting and Communication (RS.CO) - 2 questions
                {
                    'question_id': "RS_006",
                    'question_text': "Do you notify relevant stakeholders of security incidents?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.RESPOND,
                    'category': "Incident Communication",
                    'subcategory': "RS.CO-02",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 6
                },
                {
                    'question_id': "RS_007",
                    'question_text': "Do you share incident information with appropriate internal and external parties?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.RESPOND,
                    'category': "Incident Communication",
                    'subcategory': "RS.CO-03",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 7
                },
                # Incident Mitigation (RS.MI) - 1 question
                {
                    'question_id': "RS_008",
                    'question_text': "Do you have procedures to contain and eradicate threats when incidents occur?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.RESPOND,
                    'category': "Incident Mitigation",
                    'subcategory': "RS.MI-01",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 8
                }
            ],
            NISTFunction.RECOVER: [
                # Incident Recovery Plan Execution (RC.RP) - 4 questions
                {
                    'question_id': "RC_001",
                    'question_text': "Do you have documented recovery procedures for critical systems?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.RECOVER,
                    'category': "Recovery Planning",
                    'subcategory': "RC.RP-01",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 1
                },
                {
                    'question_id': "RC_002",
                    'question_text': "Do you prioritize recovery activities based on business impact?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.RECOVER,
                    'category': "Recovery Planning",
                    'subcategory': "RC.RP-02",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 2
                },
                {
                    'question_id': "RC_003",
                    'question_text': "Do you verify the integrity of backups and recovery assets before restoration?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.RECOVER,
                    'category': "Recovery Planning",
                    'subcategory': "RC.RP-03",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 3
                },
                {
                    'question_id': "RC_004",
                    'question_text': "Do you test your recovery procedures through exercises or drills?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.RECOVER,
                    'category': "Recovery Planning",
                    'subcategory': "RC.RP-05",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 4
                },
                # Incident Recovery Communication (RC.CO) - 1 question
                {
                    'question_id': "RC_005",
                    'question_text': "Do you communicate recovery status and progress to stakeholders?",
                    'question_type': QuestionType.MULTIPLE_CHOICE,
                    'nist_function': NISTFunction.RECOVER,
                    'category': "Recovery Communication",
                    'subcategory': "RC.CO-03",
                    'options': MATURITY_SCALE,
                    'required': True,
                    'order': 5
                }
            ]
        }
        
        return questions_map.get(function, [])
    
    def _create_fallback_questions(self) -> None:
        """Create fallback questions if HTML parsing fails."""
        for function in NISTFunction:
            self._questions_cache[function] = self._get_sample_questions(function)
    
    def get_questions_for_functions(self, selected_functions: List[NISTFunction]) -> List[Dict[str, Any]]:
        """
        Get questions for the specified NIST functions.
        
        Args:
            selected_functions: List of selected NIST functions
            
        Returns:
            List of question dictionaries
        """
        all_questions = []
        
        for function in selected_functions:
            if function in self._questions_cache:
                questions = self._questions_cache[function]
                all_questions.extend(questions)
        
        # Sort by order
        all_questions.sort(key=lambda x: x.get('order', 0))
        
        return all_questions
    
    def get_questionnaire_template(self, function: NISTFunction) -> QuestionnaireTemplate:
        """
        Get a questionnaire template for a specific NIST function.
        
        Args:
            function: NIST function
            
        Returns:
            QuestionnaireTemplate object
        """
        questions = self._questions_cache.get(function, [])
        
        # Calculate estimated time (2 minutes per question on average)
        estimated_time = len(questions) * 2
        
        return QuestionnaireTemplate(
            template_id=f"{function.value.lower()}_template",
            nist_function=function,
            category=f"{function.value} Function Assessment",
            subcategory="Compliance Assessment",
            questions=questions,
            description=f"Comprehensive questionnaire for {function.value} function compliance assessment",
            estimated_time=estimated_time
        )
    
    def validate_answer(self, question_data: Dict[str, Any], answer: str) -> tuple[bool, str]:
        """
        Validate a question answer.
        
        Args:
            question_data: Question dictionary
            answer: User's answer
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not answer or not answer.strip():
            return False, "Answer cannot be empty"
        
        question_type = question_data.get('question_type')
        
        if question_type == QuestionType.YES_NO:
            normalized = answer.lower().strip()
            if normalized not in ['yes', 'no', 'y', 'n']:
                return False, "Answer must be Yes or No"
        
        elif question_type == QuestionType.MULTIPLE_CHOICE:
            options = question_data.get('options', [])
            if options and answer not in options:
                return False, f"Answer must be one of: {', '.join(options)}"
        
        elif question_type == QuestionType.SCALE:
            try:
                score = int(answer)
                if not 1 <= score <= 5:
                    return False, "Scale must be between 1 and 5"
            except ValueError:
                return False, "Scale must be a number"
        
        return True, ""
    
    def process_answers(self, answers: List[Dict[str, Any]]) -> List[QuestionAnswer]:
        """
        Process and validate questionnaire answers.
        
        Args:
            answers: List of answer dictionaries
            
        Returns:
            List of QuestionAnswer objects
        """
        processed_answers = []
        
        for answer_data in answers:
            question_id = answer_data.get('question_id')
            answer_text = answer_data.get('answer', '')
            evidence = answer_data.get('evidence', '')
            
            # Find the corresponding question
            question_data = None
            for function_questions in self._questions_cache.values():
                for q in function_questions:
                    if q.get('question_id') == question_id:
                        question_data = q
                        break
                if question_data:
                    break
            
            if not question_data:
                continue
            
            # Validate the answer
            is_valid, error_msg = self.validate_answer(question_data, answer_text)
            if not is_valid:
                raise ValueError(f"Invalid answer for {question_id}: {error_msg}")
            
            # Create QuestionAnswer object
            question_answer = QuestionAnswer(
                question_id=question_id,
                question_text=question_data.get('question_text', ''),
                question_type=question_data.get('question_type'),
                nist_function=question_data.get('nist_function'),
                category=question_data.get('category', ''),
                subcategory=question_data.get('subcategory', ''),
                answer=answer_text,
                evidence=evidence if evidence else None,
                confidence=answer_data.get('confidence')
            )
            
            processed_answers.append(question_answer)
        
        return processed_answers
    
    def get_available_functions(self) -> List[NISTFunction]:
        """Get list of available NIST functions with questions."""
        return list(self._questions_cache.keys())
    
    def get_function_summary(self, function: NISTFunction) -> Dict[str, Any]:
        """
        Get summary information for a NIST function.
        
        Args:
            function: NIST function
            
        Returns:
            Dictionary with function summary
        """
        questions = self._questions_cache.get(function, [])
        
        # Count questions by type
        type_counts = {}
        for question in questions:
            q_type = question.get('question_type')
            type_counts[q_type] = type_counts.get(q_type, 0) + 1
        
        return {
            'function': function.value,
            'total_questions': len(questions),
            'question_types': type_counts,
            'estimated_time_minutes': len(questions) * 2,
            'categories': list(set(q.get('category', '') for q in questions))
        }
    
    def get_risk_appetite_questions(self) -> List[Dict[str, Any]]:
        """
        Get risk appetite assessment questions.
        
        Returns:
            List of risk appetite questions
        """
        return [
            {
                'question_id': 'RA_001',
                'question_text': 'How would you describe your organization\'s general approach to cybersecurity/AI risk?',
                'question_type': QuestionType.MULTIPLE_CHOICE,
                'category': 'Risk Appetite',
                'subcategory': 'Overall Risk Posture',
                'options': [
                    'Very conservative – avoid almost all non-essential risk',
                    'Conservative – accept only well-understood, low risks',
                    'Balanced – accept moderate risk for business value',
                    'Aggressive – accept higher risk for innovation/competitive advantage',
                    'Very aggressive – prioritize speed/innovation even with significant risk'
                ],
                'required': True,
                'order': 1
            },
            {
                'question_id': 'RA_002',
                'question_text': 'For this scope (system/policies), what is the highest risk level you are normally willing to accept without immediate mitigation?',
                'question_type': QuestionType.MULTIPLE_CHOICE,
                'category': 'Risk Appetite',
                'subcategory': 'Maximum Acceptable Risk',
                'options': [
                    'Only Low',
                    'Low and some Medium',
                    'Medium is acceptable; High must be mitigated',
                    'High is acceptable with management sign-off'
                ],
                'required': True,
                'order': 2
            },
            {
                'question_id': 'RA_003',
                'question_text': 'Which potential harms are your organization least willing to tolerate? (Select top 2–3.)',
                'question_type': QuestionType.MULTIPLE_CHOICE,
                'category': 'Risk Appetite',
                'subcategory': 'Impact Sensitivity',
                'options': [
                    'Harm to individuals (safety, rights, discrimination)',
                    'Regulatory / legal breaches',
                    'Financial loss',
                    'Service downtime / operational disruption',
                    'Reputational damage',
                    'Environmental / societal harm'
                ],
                'required': True,
                'order': 3
            },
            {
                'question_id': 'RA_004',
                'question_text': 'For risks rated High by the matrix, what is the default expected response?',
                'question_type': QuestionType.MULTIPLE_CHOICE,
                'category': 'Risk Appetite',
                'subcategory': 'Prioritization Rules',
                'options': [
                    'Must be mitigated or reduced within 1 month',
                    'Must be mitigated within 3 months',
                    'Can be accepted with executive approval',
                    'Other (describe in evidence field)'
                ],
                'required': True,
                'order': 4
            },
            {
                'question_id': 'RA_005',
                'question_text': 'When a risk is above appetite, what is your usual preferred treatment?',
                'question_type': QuestionType.MULTIPLE_CHOICE,
                'category': 'Risk Appetite',
                'subcategory': 'Treatment Preference',
                'options': [
                    'Reduce (add controls)',
                    'Transfer (insurance, contracts)',
                    'Avoid (change design, stop activity)',
                    'Accept with justification'
                ],
                'required': True,
                'order': 5
            }
        ]
    
    def get_heatmap_input_template(self) -> List[Dict[str, Any]]:
        """
        Get heat-map input templates for items assessment.
        
        Returns:
            List of heat-map input fields
        """
        return [
            {
                'field_id': 'HM_NAME',
                'field_text': 'Item Name & Description',
                'field_type': 'text',
                'required': True,
                'help_text': 'Name of document/policy/system and what it governs'
            },
            {
                'field_id': 'HM_IMPACT',
                'field_text': 'Impact Score (1–5)',
                'field_type': 'scale',
                'min': 1,
                'max': 5,
                'required': True,
                'help_text': 'If this system fails or is misused, how severe are the consequences?'
            },
            {
                'field_id': 'HM_LIKELIHOOD',
                'field_text': 'Likelihood Score (1–5)',
                'field_type': 'scale',
                'min': 1,
                'max': 5,
                'required': True,
                'help_text': 'How likely is it that a harmful event will occur?'
            },
            {
                'field_id': 'HM_RISK_TYPE',
                'field_text': 'Primary Risk Type',
                'field_type': 'multiple_choice',
                'options': [
                    'Safety / Human harm',
                    'Regulatory / Legal',
                    'Data privacy / Confidentiality',
                    'Financial / Fraud',
                    'Operational / Availability',
                    'Fairness / Bias / Ethics'
                ],
                'required': True,
                'help_text': 'Main nature of the risk'
            },
            {
                'field_id': 'HM_RESIDUAL',
                'field_text': 'Residual Risk Level',
                'field_type': 'multiple_choice',
                'options': ['Low', 'Medium', 'High'],
                'required': True,
                'help_text': 'Expert judgment considering existing controls'
            }
        ]

    def compute_compliance_by_function(self, answers: List[QuestionAnswer], include_functions: Optional[List[NISTFunction]] = None) -> Dict[str, float]:
        """
        Compute compliance percentage per NIST function.

        Compliance rules implemented here:
        - MULTIPLE_CHOICE (maturity scale): options indexed 0..n-1; answers at index >= 2 ("3" or "4") count as compliant
        - SCALE (numeric 1-5): score >= 3 is compliant
        - YES_NO: 'yes' (or 'y') is compliant
        - TEXT: considered compliant if it contains keywords like 'yes', 'compliant', 'implemented', 'established'

        Behavior / edge-cases:
        - Missing answers are treated as non-compliant (included in denominator)
        - Partial answers (low confidence) are counted the same as full answers (do not exclude)
        - Avoid divide-by-zero: if a function has zero questions, percentage = 0.0
        - Rounds percentages to 1 decimal place

        Args:
            answers: list of `QuestionAnswer` objects (or dict-like with same fields)
            include_functions: optional list of NISTFunction to compute (defaults to all 6 NIST functions)

        Returns:
            dict mapping function name (lowercase) to percentage and an 'overall' key
        """
        # Default to ALL six NIST CSF functions
        if include_functions is None:
            include_functions = [
                NISTFunction.GOVERN, 
                NISTFunction.IDENTIFY, 
                NISTFunction.PROTECT,
                NISTFunction.DETECT,
                NISTFunction.RESPOND,
                NISTFunction.RECOVER
            ]

        # Normalize input answers to objects with expected attrs
        normalized_answers = []
        for a in answers or []:
            if isinstance(a, QuestionAnswer):
                normalized_answers.append(a)
            else:
                try:
                    normalized_answers.append(QuestionAnswer(**a))
                except Exception:
                    # Skip malformed answer entries
                    continue

        # Build counts
        compliant_counts = {f: 0 for f in include_functions}
        total_questions = {f: len(self._questions_cache.get(f, [])) for f in include_functions}

        def get_compliance_score(ans: QuestionAnswer) -> float:
            """
            Get compliance score (0-100) for an answer based on maturity level.
            
            Maturity levels are scored as:
            - Level 1 (Not implemented) → 0%
            - Level 2 (Initial) → 33%
            - Level 3 (Developing) → 66%
            - Level 4 (Established) → 100%
            """
            qtype = ans.question_type
            raw = (ans.answer or "").strip()
            if not raw:
                return 0.0

            if qtype == QuestionType.MULTIPLE_CHOICE:
                # Maturity scale scoring
                try:
                    if raw in MATURITY_SCALE:
                        idx = MATURITY_SCALE.index(raw)
                        # Map index to compliance percentage: [0%, 33%, 66%, 100%]
                        maturity_scores = [0.0, 33.0, 66.0, 100.0]
                        return maturity_scores[idx]
                except Exception:
                    pass
                # Fallback keyword match for maturity levels
                low = raw.lower()
                if any(k in low for k in ["4 –", "4 -", "establish", "established"]):
                    return 100.0
                elif any(k in low for k in ["3 –", "3 -", "developing"]):
                    return 66.0
                elif any(k in low for k in ["2 –", "2 -", "initial"]):
                    return 33.0
                elif any(k in low for k in ["1 –", "1 -", "not implemented"]):
                    return 0.0
                else:
                    # Default to implemented keyword check
                    return 100.0 if "implemented" in low else 0.0

            if qtype == QuestionType.SCALE:
                try:
                    score = int(raw)
                    # Map scale 1-5 to maturity levels
                    if score <= 1:
                        return 0.0
                    elif score == 2:
                        return 33.0
                    elif score == 3:
                        return 66.0
                    else:  # 4-5
                        return 100.0
                except Exception:
                    return 0.0

            if qtype == QuestionType.YES_NO:
                return 100.0 if raw.lower() in ["yes", "y"] else 0.0

            # TEXT and others: use heuristic
            low = raw.lower()
            if any(k in low for k in ["established", "fully"]):
                return 100.0
            elif any(k in low for k in ["developing", "partial"]):
                return 66.0
            elif any(k in low for k in ["initial", "informal"]):
                return 33.0
            elif any(k in low for k in ["yes", "compliant", "implemented"]):
                return 100.0
            else:
                return 0.0

        # Count compliance scores per function (sum of all answer scores)
        for ans in normalized_answers:
            func = ans.nist_function
            # ans.nist_function may be enum or string
            try:
                if isinstance(func, str):
                    func_enum = NISTFunction(func)
                else:
                    func_enum = func
            except Exception:
                continue

            if func_enum not in include_functions:
                continue

            try:
                score = get_compliance_score(ans)
                compliant_counts[func_enum] += score
            except Exception:
                # On any per-answer error, treat as 0% compliant and continue
                continue

        # Compute percentages
        results: Dict[str, float] = {}
        total_compliant_score = 0.0
        total_possible_score = 0.0
        for f in include_functions:
            tq = total_questions.get(f, 0) or 0
            score_sum = compliant_counts.get(f, 0.0)
            total_compliant_score += score_sum
            total_possible_score += tq * 100.0  # Each question is max 100 points
            if tq == 0:
                pct = 0.0
            else:
                pct = round(score_sum / tq, 1)
            results[f.value.lower()] = pct

        # Overall across included functions (weighted by question counts)
        if total_possible_score == 0:
            overall = 0.0
        else:
            overall = round(100.0 * total_compliant_score / total_possible_score, 1)

        results["overall"] = overall
        return results
