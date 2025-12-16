"""
Reports models for Hadnx.
"""
import uuid
from django.db import models


class Report(models.Model):
    """Exportable security report."""
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.OneToOneField(
        'scanner.Scan',
        on_delete=models.CASCADE,
        related_name='report'
    )
    
    # Report metadata
    generated_at = models.DateTimeField(auto_now_add=True)
    
    # Cached summary data for quick access
    executive_summary = models.TextField(blank=True)
    
    class Meta:
        ordering = ['-generated_at']
    
    def __str__(self):
        return f"Report for {self.scan.domain}"
