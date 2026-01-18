import io
import logging
from django.template.loader import render_to_string
from django.utils import timezone
from xhtml2pdf import pisa
import markdown

from apps.scanner.models import Scan, Finding

logger = logging.getLogger(__name__)

class PDFGenerator:
    """Generates PDF reports for security scans."""
    
    @staticmethod
    def generate_report(scan: Scan) -> bytes:
        """
        Generates a PDF report for the given scan.
        Returns bytes content of the PDF.
        """
        try:
            # Gather Data
            findings = scan.findings.all().order_by('score_impact', 'severity')
            
            # Severity counts
            severity_counts = {
                'CRITICAL': findings.filter(severity='CRITICAL').count(),
                'HIGH': findings.filter(severity='HIGH').count(),
                'MEDIUM': findings.filter(severity='MEDIUM').count(),
                'LOW': findings.filter(severity='LOW').count(),
                'INFO': findings.filter(severity='INFO').count(),
            }
            
            # Extract AI Narrative (if any)
            # We look for a finding of category 'ai_analysis' which usually holds the narrative in description
            ai_finding = findings.filter(category='ai_analysis').first()
            ai_narrative_html = ""
            if ai_finding and ai_finding.description:
                # Convert Markdown to safe HTML
                ai_narrative_html = markdown.markdown(
                    ai_finding.description,
                    extensions=['extra', 'codehilite']
                )

            context = {
                'scan': scan,
                'findings': findings,
                'severity_counts': severity_counts,
                'generated_at': timezone.now(),
                'ai_narrative': ai_narrative_html,
            }
            
            # Render HTML
            html_string = render_to_string('reports/scan_report.html', context)
            
            # Convert to PDF
            pdf_file = io.BytesIO()
            pisa_status = pisa.CreatePDF(
                io.BytesIO(html_string.encode("UTF-8")),
                dest=pdf_file,
                encoding='UTF-8'
            )
            
            if pisa_status.err:
                logger.error(f"PDF generation error: {pisa_status.err}")
                return b""
                
            return pdf_file.getvalue()
            
        except Exception as e:
            logger.error(f"Failed to generate PDF for scan {scan.id}: {str(e)}")
            raise e
