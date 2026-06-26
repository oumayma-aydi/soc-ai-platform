import os
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

def generate_detailed_incident_pdf(result_data: dict, output_path: str):
    # Configuration du document (marges de 2cm)
    doc = SimpleDocTemplate(
        output_path, 
        pagesize=letter,
        rightMargin=54, leftMargin=54, topMargin=54, bottomMargin=54
    )
    
    styles = getSampleStyleSheet()
    
    # Palette de couleurs "SOC / Cyber"
    NAVY = colors.HexColor("#0A2540")
    RED_CRIT = colors.HexColor("#D32F2F")
    GREY_BG = colors.HexColor("#F8F9FA")
    BORDER_GREY = colors.HexColor("#E0E0E0")
    TEXT_DARK = colors.HexColor("#2C3E50")
    
    # Styles personnalisés
    title_style = ParagraphStyle('DocTitle', parent=styles['Heading1'], fontName='Helvetica-Bold', fontSize=22, textColor=NAVY, spaceAfter=6)
    subtitle_style = ParagraphStyle('DocSub', parent=styles['Normal'], fontName='Helvetica-Oblique', fontSize=10, textColor=colors.gray, spaceAfter=20)
    h1_style = ParagraphStyle('SectionH1', parent=styles['Heading2'], fontName='Helvetica-Bold', fontSize=14, textColor=NAVY, spaceBefore=18, spaceAfter=10)
    h2_style = ParagraphStyle('SectionH2', parent=styles['Heading3'], fontName='Helvetica-Bold', fontSize=11, textColor=TEXT_DARK, spaceBefore=10, spaceAfter=6)
    body_style = ParagraphStyle('Body', parent=styles['BodyText'], fontName='Helvetica', fontSize=10, textColor=TEXT_DARK, leading=14)
    code_style = ParagraphStyle('Code', parent=styles['Code'], fontName='Courier', fontSize=9, leading=12)
    
    story = []
    
    # -------------------------------------------------------------------------
    # EN-TÊTE DU RAPPORT
    # -------------------------------------------------------------------------
    story.append(Paragraph("🚨 RAPPORT D'ANALYSE D'INCIDENT SOC AI", title_style))
    story.append(Paragraph(f"Généré automatiquement par la plateforme SOC — ID Dossier : {result_data.get('incident_id', 'INC-2026-001')}", subtitle_style))
    story.append(Spacer(1, 10))
    
    # -------------------------------------------------------------------------
    # METRICS & SYNTHÈSE (Tableau horizontal)
    # -------------------------------------------------------------------------
    summary_data = [
        [Paragraph("<b>Type d'incident :</b>", body_style), Paragraph(result_data.get('incident_type', 'N/A'), body_style)],
        [Paragraph("<b>Sévérité globale :</b>", body_style), Paragraph(f"<font color='red'><b>{result_data.get('severity', '0')}/10 ({result_data.get('urgency', 'N/A')})</b></font>", body_style)],
        [Paragraph("<b>Score de confiance IA :</b>", body_style), Paragraph(f"<b>{result_data.get('confidence_score', 0.0)}/1.0</b> 🎯", body_style)]
    ]
    summary_table = Table(summary_data, colWidths=[130, 374])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), GREY_BG),
        ('GRID', (0,0), (-1,-1), 0.5, BORDER_GREY),
        ('PADDING', (0,0), (-1,-1), 8),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 15))
    
    # Synthèse Exécutive
    story.append(Paragraph("Résumé Exécutif", h2_style))
    story.append(Paragraph(result_data.get('remediation', {}).get('summary', 'Aucun résumé généré.'), body_style))
    story.append(Spacer(1, 15))
    
    # -------------------------------------------------------------------------
    # CARTOGRAPHIE MITRE ATT&CK
    # -------------------------------------------------------------------------
    story.append(Paragraph("1. Cartographie des Techniques MITRE ATT&CK", h1_style))
    mitre_data = [[Paragraph("<b>Identifiant</b>", body_style), Paragraph("<b>Nom de la Technique</b>", body_style), Paragraph("<b>Confiance</b>", body_style)]]
    
    for tech in result_data.get('mitre_techniques', []):
        mitre_data.append([
            Paragraph(tech.get('id', 'N/A'), code_style),
            Paragraph(tech.get('name', 'N/A'), body_style),
            Paragraph(f"{int(tech.get('confidence', 0)*100)}%", body_style)
        ])
        
    mitre_table = Table(mitre_data, colWidths=[94, 320, 90])
    mitre_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), NAVY),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('GRID', (0,0), (-1,-1), 0.5, BORDER_GREY),
        ('PADDING', (0,0), (-1,-1), 6),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    # Forcer l'en-tête en blanc pour le tableau MITRE
    for i in range(3):
        mitre_table.setStyle(TableStyle([('TEXTCOLOR', (i,0), (i,0), colors.white)]))
    story.append(mitre_table)
    story.append(Spacer(1, 15))
    
    # -------------------------------------------------------------------------
    # CHRONOLOGIE DE LA CYBER KILL CHAIN
    # -------------------------------------------------------------------------
    story.append(Paragraph("2. Reconstitution de la Cyber Kill Chain", h1_style))
    kc_elements = []
    for step in result_data.get('kill_chain', []):
        p_text = f"<b>Étape {step.get('step', '?')} [{step.get('phase', 'N/A')}] :</b> {step.get('description', '')}"
        kc_elements.append([Paragraph(p_text, body_style)])
    
    kc_table = Table(kc_elements, colWidths=[504])
    kc_table.setStyle(TableStyle([
        ('GRID', (0,0), (-1,-1), 0.5, BORDER_GREY),
        ('BACKGROUND', (0,0), (-1,-1), GREY_BG),
        ('PADDING', (0,0), (-1,-1), 8),
        ('LINEBEFORE', (0,0), (0,-1), 3, NAVY), # Barre bleue à gauche pour faire un effet de timeline
    ]))
    story.append(kc_table)
    story.append(Spacer(1, 15))
    
    # -------------------------------------------------------------------------
    # PLAN DE REMÉDIATION SUR MESURE
    # -------------------------------------------------------------------------
    story.append(Paragraph("3. Plan d'Action & Mesures de Remédiation", h1_style))
    
    for action in result_data.get('remediation', {}).get('actions', []):
        priority = f"P{action.get('priority', '3')}"
        timeframe = action.get('timeframe', 'N/A')
        act_title = action.get('action', 'N/A')
        how_text = action.get('how', 'N/A')
        source = action.get('source', 'N/A')
        
        action_content = [
            [Paragraph(f"<b>{priority} — [{timeframe}] : {act_title}</b>", body_style)],
            [Paragraph(f"<b>Procédure d'application :</b> {how_text}", body_style)],
            [Paragraph(f"<font color='gray'><b>Source de conformité :</b> {source}</font>", body_style)]
        ]
        
        action_table = Table(action_content, colWidths=[504])
        # Alerte visuelle : Bordure rouge si P1, sinon grise
        border_color = RED_CRIT if priority == "P1" else NAVY
        
        action_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), GREY_BG),
            ('PADDING', (0,0), (-1,-1), 6),
            ('LINEBEFORE', (0,0), (0,-1), 4, border_color),
            ('LINEBELOW', (0,0), (-1,-1), 0.5, BORDER_GREY),
        ]))
        story.append(KeepTogether([action_table, Spacer(1, 10)]))
        
    story.append(Spacer(1, 10))
    
    # -------------------------------------------------------------------------
    # RÈGLES DE DÉTECTION À DÉPLOYER (SIEM / WAZEH)
    # -------------------------------------------------------------------------
    story.append(Paragraph("4. Règles de Détection Recommandées (SIEM/Wazuh)", h1_style))
    det_elements = []
    for det in result_data.get('remediation', {}).get('detections_to_deploy', []):
        det_elements.append([Paragraph(f"• {det}", body_style)])
        
    det_table = Table(det_elements, colWidths=[504])
    det_table.setStyle(TableStyle([
        ('PADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(det_table)
    
    # Build du document complet
    doc.build(story)