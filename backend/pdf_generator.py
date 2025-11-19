from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from datetime import datetime
import os

def generate_pdf_report(scan_results: dict, output_dir: str = "reports") -> str:
    """
    Generate PDF report from scan results
    Returns path to generated PDF file
    """
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pdf_path = os.path.join(output_dir, f"scan_report_{timestamp}.pdf")
    
    doc = SimpleDocTemplate(pdf_path, pagesize=A4)
    story = []
    styles = getSampleStyleSheet()
    
    # Title
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#1a1a1a'),
        spaceAfter=30,
        alignment=TA_CENTER
    )
    story.append(Paragraph("SOCinator Security Scan Report", title_style))
    story.append(Spacer(1, 0.2*inch))
    
    # Report metadata
    meta_style = ParagraphStyle(
        'Meta',
        parent=styles['Normal'],
        fontSize=10,
        textColor=colors.HexColor('#666666')
    )
    story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", meta_style))
    story.append(Spacer(1, 0.3*inch))
    
    # Summary statistics
    summary_data = [
        ['Total Detections', str(scan_results.get('total_detections', 0))],
        ['High Severity', str(scan_results.get('high_severity', 0))],
        ['Medium Severity', str(scan_results.get('medium_severity', 0))],
        ['Low Severity', str(scan_results.get('low_severity', 0))]
    ]
    
    summary_table = Table(summary_data, colWidths=[3*inch, 2*inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#ecf0f1')),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#bdc3c7')),
        ('FONTSIZE', (0, 1), (-1, -1), 11),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 0.4*inch))
    
    # Detailed results
    heading_style = ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading2'],
        fontSize=16,
        textColor=colors.HexColor('#1a1a1a'),
        spaceAfter=12
    )
    story.append(Paragraph("Detection Details", heading_style))
    story.append(Spacer(1, 0.2*inch))
    
    # Results table
    results = scan_results.get('results', [])
    if results:
        table_data = [['Rule Name', 'Severity', 'MITRE ID', 'Pattern']]
        
        for result in results:
            severity = result.get('severity', 'Unknown')
            severity_color = {
                'High': colors.HexColor('#e74c3c'),
                'Medium': colors.HexColor('#f39c12'),
                'Low': colors.HexColor('#3498db')
            }.get(severity, colors.black)
            
            rule_name = result.get('rule_name', 'Unknown')[:40]
            mitre_id = result.get('mitre_attack_id', 'N/A')
            pattern = result.get('detected_pattern', '')[:60]
            
            table_data.append([
                rule_name,
                severity,
                mitre_id,
                pattern
            ])
        
        results_table = Table(table_data, colWidths=[2*inch, 1*inch, 1*inch, 2.5*inch])
        results_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#ecf0f1')),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#bdc3c7')),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')]),
        ]))
        story.append(results_table)
    else:
        story.append(Paragraph("No detections found.", styles['Normal']))
    
    # Build PDF
    doc.build(story)
    return pdf_path

