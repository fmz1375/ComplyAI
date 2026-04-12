# -*- coding: utf-8 -*-
"""
Risk Heat Map Generation Service - Fixed Version
This generates proper heatmaps from compliance gaps
"""

import os
import logging
from typing import List, Dict, Any
from pathlib import Path
from datetime import datetime
import uuid

import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.colors import ListedColormap

from models.report_models import (
    HeatMapItem, HeatMapAnalysis, HeatMapReport, RiskAppetiteProfile,
    MaxAcceptableRisk, ComplianceGap, RiskLevel,
    RiskApproach, ImpactType, MitigationTimeline, RiskTreatment
)

logger = logging.getLogger(__name__)


class RiskHeatMapService:
    """Service for generating risk heat maps from compliance gaps."""

    def __init__(self, output_dir: str = "exports"):
        """
        Initialize the heat-map service.

        Args:
            output_dir: Directory to save generated heat map images
        """
        # Use absolute path for output directory
        self.output_dir = Path(output_dir).resolve()
        self.output_dir.mkdir(exist_ok=True)

        # Define color scheme for risk levels (aligned with NIST script)
        self.risk_colors = {
            "Low": "#2ecc71",
            "Medium": "#f1c40f",
            "High": "#e67e22",
            "Critical": "#e74c3c"
        }

    def generate_heatmap_from_gaps(
        self,
        compliance_gaps: List[ComplianceGap],
        organization_name: str,
        session_id: str
    ) -> HeatMapReport:
        """
        Generate a heatmap report directly from compliance gaps.

        Args:
            compliance_gaps: List of identified compliance gaps
            organization_name: Name of the organization
            session_id: Session ID for reference

        Returns:
            HeatMapReport object with analysis and visualization
        """
        heatmap_items = []

        for i, gap in enumerate(compliance_gaps):
            # Assign likelihood and impact based on risk level
            if gap.risk_level == RiskLevel.CRITICAL:
                likelihood = np.random.randint(4, 6)  # 4-5
                impact = np.random.randint(4, 6)      # 4-5
            elif gap.risk_level == RiskLevel.HIGH:
                likelihood = np.random.randint(3, 5)  # 3-4
                impact = np.random.randint(3, 5)      # 3-4
            elif gap.risk_level == RiskLevel.MEDIUM:
                likelihood = np.random.randint(2, 4)  # 2-3
                impact = np.random.randint(2, 4)      # 2-3
            else:  # LOW
                likelihood = np.random.randint(1, 3)  # 1-2
                impact = np.random.randint(1, 3)      # 1-2

            item = HeatMapItem(
                item_id=f"item_{i:03d}_{uuid.uuid4().hex[:8]}",
                name=f"{gap.control_id}: {gap.control_title}",
                description=gap.description,
                impact_score=impact,
                likelihood_score=likelihood,
                primary_risk_type=gap.category,
                residual_risk_level=gap.risk_level.value
            )
            heatmap_items.append(item)

        appetite_profile = RiskAppetiteProfile(
            profile_id=f"appetite_{uuid.uuid4().hex[:12]}",
            session_id=session_id,
            organization_name=organization_name,
            overall_risk_posture=RiskApproach.BALANCED,
            max_acceptable_risk=MaxAcceptableRisk.MEDIUM_WITH_MITIGATION,
            impact_sensitivities=[
                ImpactType.REGULATORY_LEGAL,
                ImpactType.FINANCIAL_LOSS,
                ImpactType.HARM_TO_INDIVIDUALS
            ],
            high_risk_mitigation_timeline=MitigationTimeline.THREE_MONTHS,
            preferred_risk_treatment=RiskTreatment.REDUCE
        )

        return self.generate_heat_map_report(heatmap_items, appetite_profile, session_id)

    def generate_heat_map_report(
        self,
        items: List[HeatMapItem],
        appetite_profile: RiskAppetiteProfile,
        session_id: str
    ) -> HeatMapReport:
        """Generate a complete heat-map report with analysis and visualization."""
        analyses = self._analyze_items(items, appetite_profile)
        image_path = self._generate_heatmap_visualization(analyses, appetite_profile)
        items_above = sum(1 for a in analyses if a.above_appetite)

        report = HeatMapReport(
            report_id=f"heatmap_{uuid.uuid4().hex[:12]}",
            session_id=session_id,
            organization=appetite_profile.organization_name,
            risk_appetite_profile=appetite_profile,
            heat_map_items=analyses,
            items_above_appetite=items_above,
            visualization_path=image_path if image_path else None,
            generated_at=datetime.now()
        )

        return report

    def _analyze_items(
        self,
        items: List[HeatMapItem],
        appetite_profile: RiskAppetiteProfile
    ) -> List[HeatMapAnalysis]:
        """Analyze heatmap items and classify risks."""
        analyses = []

        for item in items:
            risk_level = self._classify_risk(item.likelihood_score, item.impact_score)
            above_appetite = self._is_above_appetite(risk_level, appetite_profile)
            color_code = self.risk_colors.get(risk_level, "#6b7280")
            reasoning = self._generate_reasoning(item, risk_level, above_appetite, appetite_profile)

            analysis = HeatMapAnalysis(
                item_id=item.item_id,
                name=item.name,
                impact=item.impact_score,
                likelihood=item.likelihood_score,
                risk_level=risk_level,
                color_code=color_code,
                above_appetite=above_appetite,
                reasoning=reasoning
            )

            analyses.append(analysis)

        return analyses

    def _classify_risk(self, likelihood: int, impact: int) -> str:
        """Classify risk based on likelihood and impact."""
        likelihood = max(1, min(5, likelihood))
        impact = max(1, min(5, impact))
        score = likelihood * impact
        if score <= 5:
            return "Low"
        if score <= 12:
            return "Medium"
        if score <= 20:
            return "High"
        return "Critical"

    def _is_above_appetite(self, risk_level: str, appetite_profile: RiskAppetiteProfile) -> bool:
        """Check if risk exceeds organizational appetite."""
        risk_ranking = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
        risk_score = risk_ranking.get(risk_level, 2)

        max_acceptable = appetite_profile.max_acceptable_risk.value

        if "Only Low" in max_acceptable:
            return risk_score > 1
        if "Low and some Medium" in max_acceptable:
            return risk_score > 2
        if "Medium acceptable" in max_acceptable:
            return risk_score > 3
        if "High acceptable" in max_acceptable:
            return False

        return False

    def _generate_reasoning(self, item, risk_level, above_appetite, appetite_profile) -> str:
        """Generate reasoning for risk classification."""
        reasoning = f"Item: {item.name}\n"
        reasoning += f"Likelihood: {item.likelihood_score}/5 | Impact: {item.impact_score}/5\n"
        reasoning += f"Risk Classification: {risk_level}\n"

        if above_appetite:
            reasoning += "⚠️ ABOVE organizational appetite\n"
            reasoning += f"Appetite: {appetite_profile.max_acceptable_risk.value}"
        else:
            reasoning += "✓ Within organizational appetite"

        return reasoning

    def _generate_heatmap_visualization(
        self,
        analyses: List[HeatMapAnalysis],
        appetite_profile: RiskAppetiteProfile
    ) -> str:
        """Generate a 5x5 risk matrix visualization aligned with NIST logic."""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"risk_heatmap_{timestamp}.png"
            filepath = self.output_dir / filename

            size = 5
            category_matrix = np.zeros((size, size))

            for analysis in analyses:
                i = analysis.impact - 1
                j = analysis.likelihood - 1
                score = analysis.impact * analysis.likelihood

                if score <= 5:
                    category_matrix[i][j] = 0
                elif score <= 12:
                    category_matrix[i][j] = 1
                elif score <= 20:
                    category_matrix[i][j] = 2
                else:
                    category_matrix[i][j] = 3

            cmap = ListedColormap([
                self.risk_colors["Low"],
                self.risk_colors["Medium"],
                self.risk_colors["High"],
                self.risk_colors["Critical"]
            ])

            # Create figure with extra space for legend
            fig, ax = plt.subplots(figsize=(12, 8))
            im = ax.imshow(category_matrix, cmap=cmap, origin="lower")

            ax.set_xticks(range(size))
            ax.set_xticklabels(range(1, size + 1))
            ax.set_yticks(range(size))
            ax.set_yticklabels(range(1, size + 1))

            ax.set_xlabel("Likelihood", fontsize=12)
            ax.set_ylabel("Impact", fontsize=12)
            ax.set_title("AI Risk Matrix (NIST CSF Aligned)", fontsize=14, fontweight='bold')

            # Track positions to handle overlapping items
            position_counts = {}
            for idx, analysis in enumerate(analyses):
                x = analysis.likelihood - 1
                y = analysis.impact - 1
                pos_key = (x, y)
                if pos_key not in position_counts:
                    position_counts[pos_key] = []
                position_counts[pos_key].append(idx + 1)

            # Place numbered markers on heatmap (combined for same position)
            for (x, y), indices in position_counts.items():
                label = ",".join(map(str, indices))
                ax.text(
                    x, y, label,
                    ha="center", va="center",
                    fontsize=10, fontweight='bold',
                    color="white",
                    bbox=dict(boxstyle='circle,pad=0.3', facecolor='black', alpha=0.7)
                )

            # Add colorbar
            cbar = plt.colorbar(im, ax=ax, ticks=[0.375, 1.125, 1.875, 2.625])
            cbar.ax.set_yticklabels(['Low', 'Medium', 'High', 'Critical'])
            cbar.set_label('Risk Level', fontsize=10)

            # Build legend text
            legend_text = "RISK ITEMS:\n" + "-" * 40 + "\n"
            for idx, analysis in enumerate(analyses):
                risk_label = "[H]" if analysis.risk_level in ["High", "Critical"] else "[M]" if analysis.risk_level == "Medium" else "[L]"
                legend_text += f"{idx + 1}. {risk_label} {analysis.name}\n"

            # Add legend as text box outside the plot
            fig.text(0.02, 0.02, legend_text, fontsize=8, family='monospace',
                     verticalalignment='bottom', horizontalalignment='left',
                     bbox=dict(boxstyle='round,pad=0.5', facecolor='#f0f0f0', alpha=0.9))

            plt.tight_layout(rect=[0, 0.15 + len(analyses) * 0.02, 1, 1])  # Adjust for legend
            plt.savefig(filepath, dpi=150, bbox_inches='tight', facecolor='white')
            plt.close()

            logger.info(f"Generated heatmap: {filepath}")
            return str(filepath)

        except Exception as e:
            logger.error(f"Failed to generate heatmap: {str(e)}")
            return ""

    def _draw_risk_matrix_background(self, ax):
        """Draw the risk matrix background with colored zones."""
        colors = ['#22c55e', '#fbbf24', '#f97316', '#dc2626']
        cmap = LinearSegmentedColormap.from_list('risk_cmap', colors, N=100)

        x = np.linspace(0.5, 5.5, 100)
        y = np.linspace(0.5, 5.5, 100)
        grid_x, grid_y = np.meshgrid(x, y)

        risk_scores = (grid_x - 0.5) * (grid_y - 0.5) / 25 * 100

        ax.imshow(risk_scores, extent=[0.5, 5.5, 0.5, 5.5], origin='lower',
                  cmap=cmap, alpha=0.2, aspect='auto')

        ax.axhline(y=2.5, xmin=0, xmax=1, color='gray', linestyle='--', alpha=0.5)
        ax.axhline(y=3.5, xmin=0, xmax=1, color='gray', linestyle='--', alpha=0.5)
        ax.axvline(x=2.5, ymin=0, ymax=1, color='gray', linestyle='--', alpha=0.5)
        ax.axvline(x=3.5, ymin=0, ymax=1, color='gray', linestyle='--', alpha=0.5)

    def get_heatmap_summary(self, report: HeatMapReport) -> Dict[str, Any]:
        """Generate summary of heatmap report."""
        analyses = report.heat_map_items
        risk_counts = {}
        for analysis in analyses:
            risk_counts[analysis.risk_level] = risk_counts.get(analysis.risk_level, 0) + 1

        return {
            "total_items": len(analyses),
            "items_above_appetite": report.items_above_appetite,
            "items_within_appetite": len(analyses) - report.items_above_appetite,
            "risk_distribution": risk_counts,
            "organization_appetite": report.risk_appetite_profile.max_acceptable_risk.value,
            "generated_at": report.generated_at.isoformat() if report.generated_at else None
        }
