"""
DRF serializers for scanner app.
"""
from rest_framework import serializers
from .models import Scan, Finding


class FindingSerializer(serializers.ModelSerializer):
    """Serializer for Finding model."""
    
    class Meta:
        model = Finding
        fields = [
            'id', 'issue', 'description', 'severity', 'category',
            'impact', 'recommendation', 'fix_examples', 'affected_element',
            'score_impact', 'created_at', 'poc', 'evidence', 'confidence'
        ]
        read_only_fields = ['id', 'created_at']


class ScanListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for scan listing."""
    findings_count = serializers.SerializerMethodField()
    critical_count = serializers.SerializerMethodField()
    high_count = serializers.SerializerMethodField()
    
    class Meta:
        model = Scan
        fields = [
            'id', 'url', 'domain', 'status', 'overall_score', 'grade',
            'headers_score', 'cookies_score', 'tls_score', 'https_score',
            'created_at', 'completed_at', 'findings_count',
            'critical_count', 'high_count', 'exploitation_enabled'
        ]
        read_only_fields = ['id', 'domain', 'status', 'overall_score', 'grade',
                          'headers_score', 'cookies_score', 'tls_score', 'https_score',
                          'created_at', 'completed_at']
    
    def get_findings_count(self, obj):
        return obj.findings.count()
    
    def get_critical_count(self, obj):
        return obj.findings.filter(severity='CRITICAL').count()
    
    def get_high_count(self, obj):
        return obj.findings.filter(severity='HIGH').count()


class ScanDetailSerializer(serializers.ModelSerializer):
    """Full serializer for scan details with findings."""
    findings = FindingSerializer(many=True, read_only=True)
    findings_by_category = serializers.SerializerMethodField()
    severity_distribution = serializers.SerializerMethodField()
    
    class Meta:
        model = Scan
        fields = [
            'id', 'url', 'domain', 'status', 'overall_score', 'grade',
            'headers_score', 'cookies_score', 'tls_score', 'https_score',
            'created_at', 'completed_at', 'error_message',
            'findings', 'findings_by_category', 'severity_distribution',
            'exploitation_enabled'
        ]
        read_only_fields = fields
    
    def get_findings_by_category(self, obj):
        """Group findings by category for frontend display."""
        categories = {}
        for finding in obj.findings.all():
            if finding.category not in categories:
                categories[finding.category] = []
            categories[finding.category].append(FindingSerializer(finding).data)
        return categories
    
    def get_severity_distribution(self, obj):
        """Count findings by severity level."""
        return {
            'critical': obj.findings.filter(severity='CRITICAL').count(),
            'high': obj.findings.filter(severity='HIGH').count(),
            'medium': obj.findings.filter(severity='MEDIUM').count(),
            'low': obj.findings.filter(severity='LOW').count(),
            'info': obj.findings.filter(severity='INFO').count(),
        }


class ScanCreateSerializer(serializers.Serializer):
    """Serializer for creating a new scan."""
    url = serializers.URLField(max_length=2048)
    exploitation_enabled = serializers.BooleanField(default=False, required=False)
    
    def validate_url(self, value):
        """Validate and normalize URL."""
        from urllib.parse import urlparse
        
        parsed = urlparse(value)
        if parsed.scheme not in ('http', 'https'):
            raise serializers.ValidationError("URL must use http or https protocol")
        if not parsed.netloc:
            raise serializers.ValidationError("Invalid URL: missing domain")
        
        return value


class ScanStatusSerializer(serializers.ModelSerializer):
    """Lightweight serializer for polling scan status."""
    
    class Meta:
        model = Scan
        fields = ['id', 'status', 'overall_score', 'grade', 'error_message']
        read_only_fields = fields
