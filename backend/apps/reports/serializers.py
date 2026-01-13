"""
DRF serializers for reports app.
"""
from rest_framework import serializers
from .models import Report
from apps.scanner.serializers import ScanDetailSerializer


class ReportSerializer(serializers.ModelSerializer):
    """Full report serializer with scan details."""
    scan = ScanDetailSerializer(read_only=True)
    
    class Meta:
        model = Report
        fields = ['id', 'scan', 'generated_at', 'executive_summary']
        read_only_fields = fields
