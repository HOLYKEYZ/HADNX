"""
Scanner models for Hadnx security platform.
"""
import uuid
from django.db import models


class Scan(models.Model):
    """Represents a security scan of a URL."""
    
    class Status(models.TextChoices):
        PENDING = 'pending', 'Pending'
        RUNNING = 'running', 'Running'
        COMPLETED = 'completed', 'Completed'
        FAILED = 'failed', 'Failed'
    
    class Grade(models.TextChoices):
        A_PLUS = 'A+', 'A+'
        A = 'A', 'A'
        B = 'B', 'B'
        C = 'C', 'C'
        D = 'D', 'D'
        F = 'F', 'F'
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    url = models.URLField(max_length=2048)
    domain = models.CharField(max_length=255, blank=True)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING)
    
    # Scoring
    overall_score = models.IntegerField(null=True, blank=True)
    grade = models.CharField(max_length=2, choices=Grade.choices, blank=True)
    
    # Category scores (0-100)
    headers_score = models.IntegerField(null=True, blank=True)
    cookies_score = models.IntegerField(null=True, blank=True)
    tls_score = models.IntegerField(null=True, blank=True)
    https_score = models.IntegerField(null=True, blank=True)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    error_message = models.TextField(blank=True)
    
    # Raw response data (for debugging)
    response_headers = models.JSONField(default=dict, blank=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['status']),
            models.Index(fields=['created_at']),
            models.Index(fields=['domain']),
        ]
    
    def __str__(self):
        return f"Scan {self.id} - {self.domain} ({self.status})"


class Finding(models.Model):
    """Individual security finding from a scan."""
    
    class Severity(models.TextChoices):
        CRITICAL = 'CRITICAL', 'Critical'
        HIGH = 'HIGH', 'High'
        MEDIUM = 'MEDIUM', 'Medium'
        LOW = 'LOW', 'Low'
        INFO = 'INFO', 'Info'
    
    class Category(models.TextChoices):
        HEADERS = 'headers', 'HTTP Headers'
        COOKIES = 'cookies', 'Cookies'
        TLS = 'tls', 'TLS/SSL'
        HTTPS = 'https', 'HTTPS Enforcement'
        INFO_DISCLOSURE = 'info_disclosure', 'Information Disclosure'
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='findings')
    
    # Finding details
    issue = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    severity = models.CharField(max_length=10, choices=Severity.choices)
    category = models.CharField(max_length=20, choices=Category.choices)
    
    # Impact and recommendations
    impact = models.TextField()
    recommendation = models.TextField()
    
    # Framework-specific fix examples (JSON: {"nginx": "...", "apache": "...", etc})
    fix_examples = models.JSONField(default=dict)
    
    # Optional: affected element (e.g., cookie name, header name)
    affected_element = models.CharField(max_length=255, blank=True)
    
    # Scoring weight for this finding
    score_impact = models.IntegerField(default=0)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-severity', 'category']
        indexes = [
            models.Index(fields=['scan', 'category']),
            models.Index(fields=['severity']),
        ]
    
    def __str__(self):
        return f"{self.severity}: {self.issue}"
