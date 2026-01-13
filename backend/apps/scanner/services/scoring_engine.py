"""
Security Scoring Engine.
Aggregates findings from all analyzers and calculates overall security score.
"""
from typing import List, Dict, Any
from dataclasses import dataclass


# Severity weights for score calculation
SEVERITY_WEIGHTS = {
    'CRITICAL': 15,
    'HIGH': 10,
    'MEDIUM': 5,
    'LOW': 2,
    'INFO': 0,
}

# Grade thresholds
GRADE_THRESHOLDS = [
    ('A+', 90, 100),
    ('A', 80, 89),
    ('B', 70, 79),
    ('C', 60, 69),
    ('D', 50, 59),
    ('F', 0, 49),
]

# Category weights for overall score
CATEGORY_WEIGHTS = {
    'headers': 0.30,      # 30% - HTTP security headers
    'cookies': 0.20,      # 20% - Cookie security
    'tls': 0.30,          # 30% - TLS/SSL configuration
    'https': 0.15,        # 15% - HTTPS enforcement
    'info_disclosure': 0.05,  # 5% - Information disclosure
}


@dataclass
class ScoreResult:
    """Result of security score calculation."""
    overall_score: int
    grade: str
    headers_score: int
    cookies_score: int
    tls_score: int
    https_score: int
    findings_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int


def calculate_category_score(findings: List[Dict[str, Any]], category: str) -> int:
    """
    Calculate score for a specific category based on findings.
    
    Args:
        findings: List of finding dictionaries
        category: Category to calculate score for
    
    Returns:
        Score from 0-100
    """
    max_score = 100
    
    category_findings = [
        f for f in findings 
        if f.get('category') == category
    ]
    
    total_impact = sum(f.get('score_impact', 0) for f in category_findings)
    
    # Cap at 100 points of deductions
    score = max(0, max_score - min(total_impact, 100))
    
    return score


def calculate_overall_score(
    headers_score: int,
    cookies_score: int,
    tls_score: int,
    https_score: int
) -> int:
    """
    Calculate weighted overall security score.
    
    Args:
        headers_score: HTTP headers score (0-100)
        cookies_score: Cookie security score (0-100)
        tls_score: TLS/SSL score (0-100)
        https_score: HTTPS enforcement score (0-100)
    
    Returns:
        Overall score from 0-100
    """
    # Weighted average
    overall = (
        headers_score * (CATEGORY_WEIGHTS['headers'] + CATEGORY_WEIGHTS['info_disclosure']) +
        cookies_score * CATEGORY_WEIGHTS['cookies'] +
        tls_score * CATEGORY_WEIGHTS['tls'] +
        https_score * CATEGORY_WEIGHTS['https']
    )
    
    return round(overall)


def get_grade(score: int) -> str:
    """
    Convert numeric score to letter grade.
    
    Args:
        score: Score from 0-100
    
    Returns:
        Letter grade (A+, A, B, C, D, F)
    """
    for grade, min_score, max_score in GRADE_THRESHOLDS:
        if min_score <= score <= max_score:
            return grade
    return 'F'


def calculate_scores(findings: List[Dict[str, Any]]) -> ScoreResult:
    """
    Calculate all security scores from a list of findings.
    
    Args:
        findings: List of finding dictionaries with keys:
            - category: 'headers', 'cookies', 'tls', 'https', 'info_disclosure'
            - severity: 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'
            - score_impact: int
    
    Returns:
        ScoreResult with all scores and counts
    """
    # Calculate category scores
    headers_findings = [f for f in findings if f.get('category') in ('headers', 'info_disclosure')]
    cookies_findings = [f for f in findings if f.get('category') == 'cookies']
    tls_findings = [f for f in findings if f.get('category') == 'tls']
    https_findings = [f for f in findings if f.get('category') == 'https']
    
    headers_score = max(0, 100 - sum(f.get('score_impact', 0) for f in headers_findings))
    cookies_score = max(0, 100 - sum(f.get('score_impact', 0) for f in cookies_findings))
    tls_score = max(0, 100 - sum(f.get('score_impact', 0) for f in tls_findings))
    https_score = max(0, 100 - sum(f.get('score_impact', 0) for f in https_findings))
    
    # If no cookies were found, assume perfect score
    if not cookies_findings and not any(f.get('category') == 'cookies' for f in findings):
        cookies_score = 100
    
    # Calculate overall score
    overall_score = calculate_overall_score(
        headers_score,
        cookies_score,
        tls_score,
        https_score
    )
    
    # Get grade
    grade = get_grade(overall_score)
    
    # Count findings by severity
    severity_counts = {
        'critical': len([f for f in findings if f.get('severity') == 'CRITICAL']),
        'high': len([f for f in findings if f.get('severity') == 'HIGH']),
        'medium': len([f for f in findings if f.get('severity') == 'MEDIUM']),
        'low': len([f for f in findings if f.get('severity') == 'LOW']),
    }
    
    return ScoreResult(
        overall_score=overall_score,
        grade=grade,
        headers_score=headers_score,
        cookies_score=cookies_score,
        tls_score=tls_score,
        https_score=https_score,
        findings_count=len(findings),
        critical_count=severity_counts['critical'],
        high_count=severity_counts['high'],
        medium_count=severity_counts['medium'],
        low_count=severity_counts['low'],
    )


def get_score_breakdown(score_result: ScoreResult) -> Dict[str, Any]:
    """
    Generate score breakdown for API response.
    
    Args:
        score_result: ScoreResult object
    
    Returns:
        Dictionary with score breakdown for frontend display
    """
    return {
        'overall': {
            'score': score_result.overall_score,
            'grade': score_result.grade,
            'max_score': 100,
        },
        'categories': {
            'headers': {
                'score': score_result.headers_score,
                'max_score': 100,
                'label': 'HTTP Headers',
                'weight': f"{int((CATEGORY_WEIGHTS['headers'] + CATEGORY_WEIGHTS['info_disclosure']) * 100)}%",
            },
            'cookies': {
                'score': score_result.cookies_score,
                'max_score': 100,
                'label': 'Cookie Security',
                'weight': f"{int(CATEGORY_WEIGHTS['cookies'] * 100)}%",
            },
            'tls': {
                'score': score_result.tls_score,
                'max_score': 100,
                'label': 'TLS/SSL',
                'weight': f"{int(CATEGORY_WEIGHTS['tls'] * 100)}%",
            },
            'https': {
                'score': score_result.https_score,
                'max_score': 100,
                'label': 'HTTPS Enforcement',
                'weight': f"{int(CATEGORY_WEIGHTS['https'] * 100)}%",
            },
        },
        'severity_distribution': {
            'critical': score_result.critical_count,
            'high': score_result.high_count,
            'medium': score_result.medium_count,
            'low': score_result.low_count,
            'total': score_result.findings_count,
        },
    }
