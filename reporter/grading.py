"""
Grading and Reporting System for InfraScan.

Provides extensible scoring for Cost Optimization, IaC Security, and Container Security,
with easy configuration for adding new metrics and scores.

GRADING FORMULAS:

Cost Grade:
  - Weighted Score = Σ(severity_weight × count) for all cost findings
  - Max Score = (resource_count + unique_rules) × max_severity_weight
  - Percentage = 100 - (Weighted Score / Max Score × 100)
  - Letter Grade = Based on percentage thresholds (A: 95+, B: 85+, C: 70+, D: 55+, F: <55)

IaC Security Grade:
  - Only most severe finding per resource is scored (avoids overweighting multiple checks per resource)
  - Max Score = resource_count × max_severity_weight
  - Percentage calculation same as cost
  - Letter Grade = Based on percentage thresholds

Container Security Grade:
  - Aggregated by container image - only worst severity per image is scored
  - Groups by 'image' field rather than 'file' for accurate per-container assessment
  - Severity breakdown shows count of images at each severity level (not total vulnerabilities)
  - Max Score = image_count × max_severity_weight
  - Example: 3 images with 2 Critical and 1 Medium = 2×4 + 1×2 = 10 score, max = 3×4 = 12
  - Percentage calculation same as IaC security
  - Letter Grade = Based on percentage thresholds

Severity Weights:
  - Critical: 4, High: 3, Medium: 2, Low: 1, Info: 0.5

Severity Caps:
  - Critical findings cap grade at C
  - High findings cap grade at B
  - Ensures realistic grades even with high violation counts

Overall Grade:
  - Weighted average: ~33% Cost + ~33% IaC Security + ~33% Container Security (when all scanners used)
  - Falls back to present scanners when not all are used
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict

SEVERITY_WEIGHTS = {
    'critical': 4,
    'high': 3,
    'medium': 2,
    'low': 1,
    'info': 0.5,
}

def normalize_severity(severity: str) -> str:
    """Normalize severity to lowercase."""
    return str(severity).lower() if severity else 'medium'

GRADE_THRESHOLDS = {
    'A': 95,
    'B': 85,
    'C': 70,
    'D': 55,
    'F': 0
}

RISK_LEVELS = {
    'A': 'Low',
    'B': 'Medium',
    'C': 'Medium-High',
    'D': 'High',
    'F': 'Critical'
}

# Weights for overall score calculation
SCORE_WEIGHTS = {
    'cost': 0.34,
    'security': 0.33,
    'container': 0.33
}


@dataclass
class GradeInfo:
    """Grade information for a specific category."""
    letter: str
    percentage: float
    score: int
    max_score: int
    risk_level: str
    violations: int
    severity_breakdown: Dict[str, int]
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)
    
    @staticmethod
    def empty() -> 'GradeInfo':
        """Create empty perfect grade."""
        return GradeInfo(
            letter='A', percentage=100.0, score=0, max_score=0,
            risk_level='Low', violations=0,
            severity_breakdown={'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        )


@dataclass
class ScanReport:
    """Complete scan report with grades and findings."""
    # Overall metrics
    overall_grade: GradeInfo
    cost_grade: 'GradeInfo | None'
    security_grade: 'GradeInfo | None'
    container_grade: 'GradeInfo | None'
    
    # Findings
    cost_findings: List[Dict[str, Any]]
    security_findings: List[Dict[str, Any]]
    container_findings: List[Dict[str, Any]]
    all_findings: List[Dict[str, Any]]
    
    # Metadata
    resource_count: int
    scanner_type: str
    total_violations: int
    
    # Analysis
    recommendations: List[str]
    top_issues: List[Dict[str, Any]]
    
    # Extensible: easy to add more fields
    metrics: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return {
            'overall': self.overall_grade.to_dict(),
            'cost': self.cost_grade.to_dict() if self.cost_grade else None,
            'security': self.security_grade.to_dict() if self.security_grade else None,
            'container': self.container_grade.to_dict() if self.container_grade else None,
            'findings': {
                'cost': self.cost_findings,
                'security': self.security_findings,
                'container': self.container_findings,
                'all': self.all_findings
            },
            'metadata': {
                'resource_count': self.resource_count,
                'scanner_type': self.scanner_type,
                'total_violations': self.total_violations
            },
            'analysis': {
                'recommendations': self.recommendations,
                'top_issues': self.top_issues
            },
            'metrics': self.metrics or {}
        }


class GradeCalculator:
    """Calculates grades with configurable weights and thresholds."""
    
    def __init__(self, severity_weights: Dict[str, float] = None,
                 grade_thresholds: Dict[str, int] = None):
        """
        Initialize calculator with custom weights/thresholds.
        
        Args:
            severity_weights: Custom severity weights (optional)
            grade_thresholds: Custom grade thresholds (optional)
        """
        self.severity_weights = severity_weights or SEVERITY_WEIGHTS
        self.grade_thresholds = grade_thresholds or GRADE_THRESHOLDS
    
    def calculate_weighted_score(self, findings: List[Dict[str, Any]]) -> tuple:
        """
        Calculate weighted score based on severity.
        
        Returns:
            Tuple of (total_score, severity_breakdown_dict)
        """
        total_score = 0
        severity_breakdown = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        for finding in findings:
            sev = normalize_severity(finding.get('severity', 'medium'))
            total_score += self.severity_weights.get(sev, 2)
            if sev in severity_breakdown:
                severity_breakdown[sev] += 1
        
        return total_score, severity_breakdown
    
    def calculate_severity_breakdown(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Calculate severity breakdown from findings.
        
        Returns:
            Dict with counts per severity level
        """
        severity_breakdown = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        for finding in findings:
            sev = normalize_severity(finding.get('severity', 'medium'))
            if sev in severity_breakdown:
                severity_breakdown[sev] += 1
        
        return severity_breakdown
    
    def get_letter_grade(self, percentage: float) -> str:
        """Convert percentage to letter grade."""
        for letter in ['A', 'B', 'C', 'D', 'F']:
            if percentage >= self.grade_thresholds[letter]:
                return letter
        return 'F'

    def apply_severity_caps(self, findings: List[Dict[str, Any]],
                            percentage: float, letter_grade: str) -> tuple:
        """Cap grades based on critical/high severity findings."""
        if not findings:
            return percentage, letter_grade

        severities = {normalize_severity(f.get('severity', '')) for f in findings}
        cap_letter = 'C' if 'critical' in severities else 'B' if 'high' in severities else None
        
        if not cap_letter:
            return percentage, letter_grade

        order = ['A', 'B', 'C', 'D', 'F']
        if order.index(letter_grade) > order.index(cap_letter):
            return percentage, letter_grade

        # Clamp percentage to cap grade's upper bound
        cap_idx = order.index(cap_letter)
        max_pct = 100.0 if cap_idx == 0 else self.grade_thresholds[order[cap_idx - 1]] - 0.1
        return min(percentage, max_pct), cap_letter
    
    def _build_grade_info(self, findings: List[Dict[str, Any]], 
                         weighted_score: int, max_score: int,
                         severity_breakdown: Dict,
                         violations: int = None,
                         all_findings: List[Dict[str, Any]] = None) -> GradeInfo:
        """Build GradeInfo from calculated scores."""
        percentage = max(0, 100 - ((weighted_score / max_score) * 100))
        letter_grade = self.get_letter_grade(percentage)
        percentage, letter_grade = self.apply_severity_caps(findings, percentage, letter_grade)
        
        # If all_findings provided, use it for severity breakdown (for security/container grades)
        if all_findings is not None:
            severity_breakdown = self.calculate_severity_breakdown(all_findings)
        
        return GradeInfo(
            letter=letter_grade,
            percentage=round(percentage, 1),
            score=weighted_score,
            max_score=int(max_score),
            risk_level=RISK_LEVELS.get(letter_grade, 'Unknown'),
            violations=violations if violations is not None else len(findings),
            severity_breakdown=severity_breakdown
        )
    
    def calculate_grade(self, findings: List[Dict[str, Any]], 
                       resource_count: int = None) -> GradeInfo:
        """Calculate grade based on findings and resource count."""
        if not findings:
            return GradeInfo.empty()
        
        weighted_score, severity_breakdown = self.calculate_weighted_score(findings)
        
        # Auto-calculate resource count if not provided
        if not resource_count:
            resource_count = len(set(f.get('file', f.get('resource', '')) for f in findings))
        
        # Scale max score by scope (resources + rule diversity)
        unique_rules = len(set(f.get('rule_id', 'unknown') for f in findings))
        scope_size = max(resource_count, 1) + max(unique_rules, 1)
        max_score = scope_size * max(self.severity_weights.values())
        
        return self._build_grade_info(findings, weighted_score, max_score, severity_breakdown)

    def calculate_grade_with_max(self, findings: List[Dict[str, Any]], max_score: int, 
                                violations: int = None, all_findings: List[Dict[str, Any]] = None) -> GradeInfo:
        """Calculate grade with explicit max score."""
        if not findings:
            return GradeInfo.empty()

        weighted_score, severity_breakdown = self.calculate_weighted_score(findings)
        return self._build_grade_info(findings, weighted_score, max(max_score, 1), 
                                     severity_breakdown, violations, all_findings)


class ReportGenerator:
    """Generates comprehensive scan reports with grades and findings."""
    
    def __init__(self, calculator: GradeCalculator = None):
        """
        Initialize report generator.
        
        Args:
            calculator: Custom grade calculator (optional)
        """
        self.calculator = calculator or GradeCalculator()
    
    def generate_report(self,
                       findings: List[Dict[str, Any]],
                       resource_count: int = 0,
                       scanner_type: str = 'comprehensive',
                       extra_recommendations: List[str] = None) -> ScanReport:
        """
        Generate complete scan report.
        
        Args:
            findings: All scan findings
            resource_count: Number of resources scanned
            scanner_type: Type of scanner used
            extra_recommendations: Additional recommendations to include
            
        Returns:
            Complete ScanReport object
        """
        # Separate findings by scanner type
        cost_findings = [f for f in findings if f.get('scanner') == 'regex']
        security_findings = [f for f in findings if f.get('scanner') == 'checkov']
        container_findings = [f for f in findings if f.get('scanner') in ['docker-scout', 'grype']]

        # For security and container, score only the most severe finding per resource
        security_scoring_findings = self._most_severe_per_resource(security_findings)
        
        # For containers, group by image (not by file) for better aggregation
        container_scoring_findings = self._most_severe_per_container_image(container_findings)

        # Determine which scanners actually ran based on scanner_type
        # 'regex' = cost only, 'checkov' = security only, 'containers' = container only,
        # 'comprehensive' = all, 'fast' = regex only
        scanner_types = [s.strip() for s in scanner_type.split(',')]

        # Calculate individual grades - only for scanners that actually ran
        cost_grade: 'GradeInfo | None'
        security_grade: 'GradeInfo | None'
        container_grade: 'GradeInfo | None'

        # Cost grade (regex scanner)
        if any(s in ['regex', 'fast', 'comprehensive'] for s in scanner_types):
            cost_grade = self.calculator.calculate_grade(cost_findings, resource_count)
        else:
            cost_grade = None

        # Security uses resource-based max score to avoid overweighting many checks per resource
        max_severity_weight = max(self.calculator.severity_weights.values())
        base_resource_count = resource_count if resource_count and resource_count > 0 else 0
        
        # Security grade (checkov scanner)
        if any(s in ['checkov', 'comprehensive'] for s in scanner_types):
            security_resource_count = max(base_resource_count, len(security_scoring_findings), 1)
            security_max_score = security_resource_count * max_severity_weight
            security_grade = self.calculator.calculate_grade_with_max(
                security_scoring_findings, security_max_score, 
                violations=len(security_findings), all_findings=security_findings
            )
        else:
            security_grade = None
        
        # Container security grading (aggregated by image)
        # Use scoring_findings for severity breakdown to show container counts, not total vulnerabilities
        if any(s in ['containers', 'comprehensive'] for s in scanner_types):
            container_resource_count = max(base_resource_count, len(container_scoring_findings), 1)
            container_max_score = container_resource_count * max_severity_weight
            container_grade = self.calculator.calculate_grade_with_max(
                container_scoring_findings, container_max_score, 
                violations=len(container_scoring_findings), all_findings=container_scoring_findings
            )
        else:
            container_grade = None
        
        # Calculate overall grade
        overall_grade = self._calculate_overall_grade(
            cost_grade, security_grade, container_grade, cost_findings, security_findings, container_findings
        )
        
        # Generate analysis
        recommendations = self._generate_recommendations(
            cost_grade, security_grade, container_grade, cost_findings, security_findings, container_findings
        )
        
        # Add extra recommendations if provided
        if extra_recommendations:
            recommendations.extend(extra_recommendations)
        
        top_issues = self._identify_top_issues(findings)
        
        # Additional metrics (extensible)
        metrics = self._calculate_additional_metrics(findings, resource_count)
        
        return ScanReport(
            overall_grade=overall_grade,
            cost_grade=cost_grade,
            security_grade=security_grade,
            container_grade=container_grade,
            cost_findings=cost_findings,
            security_findings=security_findings,
            container_findings=container_findings,
            all_findings=findings,
            resource_count=resource_count,
            scanner_type=scanner_type,
            total_violations=len(findings),
            recommendations=recommendations,
            top_issues=top_issues,
            metrics=metrics
        )

    def _most_severe_per_resource(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Return only the most severe finding per resource."""
        by_resource: Dict[str, Dict[str, Any]] = {}
        for f in findings:
            resource = f.get('resource') or f.get('file') or 'unknown'
            sev_weight = self.calculator.severity_weights.get(normalize_severity(f.get('severity')), 2)
            
            if resource not in by_resource or sev_weight > self.calculator.severity_weights.get(
                normalize_severity(by_resource[resource].get('severity')), 2):
                by_resource[resource] = f
        
        return list(by_resource.values())
    
    def _most_severe_per_container_image(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Return only the most severe finding per container image.
        For container findings, group by 'image' field instead of 'file'.
        """
        by_image: Dict[str, Dict[str, Any]] = {}
        for f in findings:
            image = f.get('image') or f.get('file') or 'unknown'
            sev_weight = self.calculator.severity_weights.get(normalize_severity(f.get('severity')), 2)
            
            if image not in by_image or sev_weight > self.calculator.severity_weights.get(
                normalize_severity(by_image[image].get('severity')), 2):
                by_image[image] = f
        
        return list(by_image.values())

    
    def _calculate_overall_grade(self, cost_grade: 'GradeInfo | None',
                                security_grade: 'GradeInfo | None',
                                container_grade: 'GradeInfo | None',
                                cost_findings: List, 
                                security_findings: List,
                                container_findings: List) -> GradeInfo:
        """Calculate overall grade from cost, security, and container grades.
        Only grades for scanners that actually ran are included."""
        # Determine which scanners ran (based on non-None grades)
        scanners_used = []
        grade_map = {}
        if cost_grade is not None:
            scanners_used.append('cost')
            grade_map['cost'] = cost_grade
        if security_grade is not None:
            scanners_used.append('security')
            grade_map['security'] = security_grade
        if container_grade is not None:
            scanners_used.append('container')
            grade_map['container'] = container_grade
        
        if not scanners_used:
            overall_percentage = 100.0
            combined_score = 0
            max_combined = 0
        elif len(scanners_used) == 1:
            # Single scanner - use its grade directly
            g = grade_map[scanners_used[0]]
            overall_percentage = g.percentage
            combined_score = g.score
            max_combined = g.max_score
        else:
            # Multiple scanners - weighted average
            total_weight = sum(SCORE_WEIGHTS[s] for s in scanners_used)
            overall_percentage = sum(
                grade_map[s].percentage * SCORE_WEIGHTS[s]
                for s in scanners_used
            ) / total_weight
            combined_score = sum(grade_map[s].score for s in scanners_used)
            max_combined = sum(grade_map[s].max_score for s in scanners_used)
        
        letter = self.calculator.get_letter_grade(overall_percentage)
        
        # Merge severity breakdowns (only from scanners that actually ran)
        combined_breakdown = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        for g in grade_map.values():
            for sev in combined_breakdown:
                combined_breakdown[sev] += g.severity_breakdown.get(sev, 0)
        
        total_violations = sum(g.violations for g in grade_map.values())
        
        return GradeInfo(
            letter=letter,
            percentage=round(overall_percentage, 1),
            score=combined_score,
            max_score=max_combined,
            risk_level=RISK_LEVELS.get(letter, 'Unknown'),
            violations=total_violations,
            severity_breakdown=combined_breakdown
        )
    
    def _generate_recommendations(self, cost_grade: 'GradeInfo | None',
                                 security_grade: 'GradeInfo | None',
                                 container_grade: 'GradeInfo | None',
                                 cost_findings: List, 
                                 security_findings: List,
                                 container_findings: List) -> List[str]:
        """Generate actionable recommendations - max 1 per category."""
        recommendations = []
        
        # IaC Security - show most critical issue only (if scanner ran)
        if security_grade is not None:
            iac_critical = security_grade.severity_breakdown.get('critical', 0)
            iac_high = security_grade.severity_breakdown['high']
            if iac_critical > 0:
                recommendations.append(
                    f"🔥 URGENT: Fix {iac_critical} critical-severity "
                    f"IaC security {'issue' if iac_critical == 1 else 'issues'} immediately"
                )
            elif iac_high > 0:
                recommendations.append(
                f"🔒 Priority: Fix {iac_high} high-severity "
                f"IaC security {'issue' if iac_high == 1 else 'issues'} before deployment"
            )
        
        # Container Security - show most critical issue only (if scanner ran)
        if container_grade is not None:
            container_critical = container_grade.severity_breakdown.get('critical', 0)
            container_high = container_grade.severity_breakdown['high']
            if container_critical > 0:
                recommendations.append(
                    f"🔥 URGENT: Address {container_critical} {'image with' if container_critical == 1 else 'images with'} critical "
                    f"vulnerabilities - update base images or rebuild containers with patched packages"
                )
            elif container_high > 0:
                recommendations.append(
                f"🐳 Priority: Address {container_high} {'image with' if container_high == 1 else 'images with'} high-severity "
                f"vulnerabilities - update container images or patch affected packages"
            )
        
        # Cost - show only if high priority (if scanner ran)
        if cost_grade is not None and cost_grade.severity_breakdown['high'] > 0:
            recommendations.append(
                f"💰 Optimize {cost_grade.severity_breakdown['high']} high-cost "
                f"{'issue' if cost_grade.severity_breakdown['high'] == 1 else 'issues'} for significant savings"
            )
        
        # Overall assessment - max 1
        active_grades = [g.letter for g in [cost_grade, security_grade, container_grade] if g is not None]
        worst_grade = min(active_grades) if active_grades else 'A'
        total_findings = len(cost_findings) + len(security_findings) + len(container_findings)
        
        if worst_grade in ['D', 'F']:
            recommendations.append(
                "⚠️ Infrastructure needs improvement - consider professional review"
            )
        elif all(g.letter == 'A' for g in [cost_grade, security_grade, container_grade] if g is not None) and total_findings > 0:
            recommendations.append("✅ Excellent infrastructure health - maintain current practices")
        elif worst_grade in ['B', 'C']:
            recommendations.append("👍 Good foundation - address remaining issues for optimal results")
        
        return recommendations or ["✅ No significant issues found"]
    
    def _identify_top_issues(self, findings: List[Dict[str, Any]], 
                           top_n: int = 5) -> List[Dict[str, Any]]:
        """Identify most common/severe issues."""
        rule_counts = {}
        for f in findings:
            rule_id = f.get('rule_id', 'unknown')
            if rule_id not in rule_counts:
                rule_counts[rule_id] = {
                    'rule_id': rule_id,
                    'rule_name': f.get('rule_name', 'Unknown'),
                    'severity': f.get('severity', 'Medium'),
                    'count': 0,
                    'estimated_savings': f.get('estimated_savings', 'N/A')
                }
            rule_counts[rule_id]['count'] += 1
        
        return sorted(
            rule_counts.values(),
            key=lambda x: SEVERITY_WEIGHTS.get(normalize_severity(x['severity']), 2) * x['count'],
            reverse=True
        )[:top_n]
    
    def _calculate_additional_metrics(self, findings: List[Dict[str, Any]], 
                                     resource_count: int) -> Dict[str, Any]:
        """Calculate additional metrics for dashboard (extensible)."""
        metrics = {
            'findings_per_resource': round(len(findings) / max(resource_count, 1), 2),
            'unique_rules_triggered': len(set(f.get('rule_id') for f in findings)),
            'files_affected': len(set(f.get('file') for f in findings if f.get('file'))),
        }
        
        # Calculate estimated potential savings (for cost findings)
        # This is extensible - add more calculations as needed
        
        return metrics
