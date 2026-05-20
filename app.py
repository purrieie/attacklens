"""
ATT&CKLens — AI Incident Analysis & MITRE ATT&CK Mapper
Flask backend with Groq LLM inference and PDF report generation
"""

import os
import json
import re
import io
from datetime import datetime
from flask import Flask, request, jsonify, render_template, send_file
from dotenv import load_dotenv
from groq import Groq

# ── PDF generation ──────────────────────────────────────────────────────────
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus.flowables import Flowable

# ── App setup ────────────────────────────────────────────────────────────────
load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY")

if not GROQ_API_KEY:
    raise ValueError("Missing GROQ_API_KEY environment variable")

groq_client = Groq(api_key=GROQ_API_KEY)

# ── System prompt for the SOC analyst LLM ───────────────────────────────────
SYSTEM_PROMPT = """You are an elite SOC Tier-3 analyst and MITRE ATT&CK expert.
Analyze the provided cybersecurity incident scenario and return ONLY a valid JSON object — no markdown, no code blocks, no prose outside the JSON.

Return exactly this JSON structure:

{
  "executive_summary": "string — 2-3 paragraph executive summary",
  "threat_classification": "string — e.g. APT / Ransomware / Insider Threat / Phishing Campaign",
  "severity": "Critical|High|Medium|Low",
  "severity_score": integer between 1 and 10,
  "attack_flow_timeline": [
    {"phase": "string", "description": "string", "timestamp_label": "string"}
  ],
  "mitre_mapping": [
    {
      "type": "Tactic|Technique|Sub-technique",
      "id": "TA#### or T#### or T####.###",
      "name": "string",
      "description": "string — how it applies to THIS incident",
      "url": "https://attack.mitre.org/tactics/TA####/ or https://attack.mitre.org/techniques/T####/"
    }
  ],
  "iocs": {
    "ip_addresses": ["string"],
    "domains": ["string"],
    "urls": ["string"],
    "emails": ["string"],
    "file_hashes": ["string"],
    "filenames": ["string"]
  },
  "potential_impact": ["string"],
  "persistence_mechanisms": ["string"],
  "lateral_movement_indicators": ["string"],
  "detection_opportunities": ["string"],
  "mitigation_recommendations": ["string"],
  "threat_hunting_suggestions": ["string"],
  "recommended_log_sources": ["string"],
  "security_control_failures": ["string"]
}

Rules:
- MITRE IDs must be real and accurate (e.g. TA0001, T1566, T1566.001).
- URLs: tactics use /tactics/TA####/, techniques use /techniques/T####/.
- If no real IOCs appear in the scenario, return empty arrays for IOC fields.
- severity_score: 1-3=Low, 4-5=Medium, 6-7=High, 8-10=Critical.
- Be specific to the scenario — do not give generic answers.
- Output ONLY the JSON object. No text before or after it."""


# ── Helper: call Groq ────────────────────────────────────────────────────────
def analyze_with_groq(scenario: str) -> dict:
    """Send scenario to Groq, parse and return structured JSON."""
    response = groq_client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Analyze this incident scenario:\n\n{scenario}"}
        ],
        temperature=0.2,
        max_tokens=4096,
    )

    raw = response.choices[0].message.content.strip()

    # Strip accidental markdown fences
    raw = re.sub(r"^```[a-zA-Z]*\s*", "", raw)
    raw = re.sub(r"\s*```$", "", raw)

    return json.loads(raw)


# ── Routes ───────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    """Receive scenario, call Groq, return structured JSON."""
    try:
        body = request.get_json(force=True)
        scenario = (body.get("scenario") or "").strip()

        if not scenario:
            return jsonify({"error": "No scenario provided."}), 400
        if len(scenario) < 20:
            return jsonify({"error": "Scenario too short. Provide more detail."}), 400

        result = analyze_with_groq(scenario)
        result["scenario"] = scenario
        result["generated_at"] = datetime.utcnow().isoformat() + "Z"
        return jsonify(result)

    except json.JSONDecodeError as e:
        return jsonify({"error": f"LLM returned invalid JSON: {str(e)}"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── PDF Report Generator ──────────────────────────────────────────────────────
@app.route("/export-pdf", methods=["POST"])
def export_pdf():
    """Generate a professional PDF report from analysis data."""
    try:
        data = request.get_json(force=True)
        pdf_bytes = generate_pdf_report(data)
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        return send_file(
            io.BytesIO(pdf_bytes),
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"ATTACKLens_Report_{timestamp}.pdf"
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── PDF internals ─────────────────────────────────────────────────────────────

# Clean professional color palette
C_WHITE      = colors.white
C_OFF_WHITE  = colors.HexColor("#F8F9FA")
C_LIGHT_GREY = colors.HexColor("#F1F3F5")
C_BORDER     = colors.HexColor("#DEE2E6")
C_BORDER_MED = colors.HexColor("#CED4DA")

C_INK        = colors.HexColor("#0F172A")   # near-black for body text
C_INK2       = colors.HexColor("#1E293B")   # headings
C_SLATE      = colors.HexColor("#475569")   # secondary text
C_MUTED      = colors.HexColor("#94A3B8")   # labels / captions

C_BLUE_DARK  = colors.HexColor("#1E3A5F")   # header bar, section titles
C_BLUE_MID   = colors.HexColor("#1D4ED8")   # accent, links
C_BLUE_LIGHT = colors.HexColor("#DBEAFE")   # table header bg
C_BLUE_PALE  = colors.HexColor("#EFF6FF")   # alternating row bg

C_SEV_CRIT_BG  = colors.HexColor("#FEE2E2"); C_SEV_CRIT_FG = colors.HexColor("#991B1B")
C_SEV_HIGH_BG  = colors.HexColor("#FFEDD5"); C_SEV_HIGH_FG = colors.HexColor("#9A3412")
C_SEV_MED_BG   = colors.HexColor("#FEF9C3"); C_SEV_MED_FG  = colors.HexColor("#854D0E")
C_SEV_LOW_BG   = colors.HexColor("#DCFCE7"); C_SEV_LOW_FG  = colors.HexColor("#166534")

SEVERITY_COLORS = {
    "Critical": (C_SEV_CRIT_BG, C_SEV_CRIT_FG),
    "High":     (C_SEV_HIGH_BG, C_SEV_HIGH_FG),
    "Medium":   (C_SEV_MED_BG,  C_SEV_MED_FG),
    "Low":      (C_SEV_LOW_BG,  C_SEV_LOW_FG),
}


class ColoredLine(Flowable):
    """A simple horizontal rule."""
    def __init__(self, width, color=C_BORDER, thickness=0.75):
        super().__init__()
        self.width = width
        self.color = color
        self.thickness = thickness

    def draw(self):
        self.canv.setStrokeColor(self.color)
        self.canv.setLineWidth(self.thickness)
        self.canv.line(0, 0, self.width, 0)


def _styles():
    """Return a dict of clean, readable paragraph styles."""
    def ps(name, **kw):
        return ParagraphStyle(name, **kw)

    return {
        "cover_title": ps("cover_title",
            fontName="Helvetica-Bold", fontSize=26,
            textColor=C_WHITE, alignment=TA_LEFT, spaceAfter=6),
        "cover_sub": ps("cover_sub",
            fontName="Helvetica", fontSize=12,
            textColor=colors.HexColor("#93C5FD"), alignment=TA_LEFT, spaceAfter=4),
        "section_title": ps("section_title",
            fontName="Helvetica-Bold", fontSize=12,
            textColor=C_BLUE_DARK, spaceBefore=16, spaceAfter=6),
        "subsection": ps("subsection",
            fontName="Helvetica-Bold", fontSize=10,
            textColor=C_INK2, spaceBefore=10, spaceAfter=4),
        "body": ps("body",
            fontName="Helvetica", fontSize=9.5,
            textColor=C_INK, leading=15, spaceAfter=4,
            alignment=TA_JUSTIFY),
        "bullet": ps("bullet",
            fontName="Helvetica", fontSize=9.5,
            textColor=C_INK, leading=14,
            leftIndent=14, spaceAfter=4),
        "mono": ps("mono",
            fontName="Courier", fontSize=8.5,
            textColor=C_INK2, leading=13),
        "table_header": ps("table_header",
            fontName="Helvetica-Bold", fontSize=8.5,
            textColor=C_INK2),
        "table_cell": ps("table_cell",
            fontName="Helvetica", fontSize=8.5,
            textColor=C_INK, leading=13),
        "table_mono": ps("table_mono",
            fontName="Courier", fontSize=8,
            textColor=C_BLUE_MID, leading=13),
        "label": ps("label",
            fontName="Helvetica-Bold", fontSize=8,
            textColor=C_MUTED, spaceBefore=2),
        "disclaimer": ps("disclaimer",
            fontName="Helvetica", fontSize=8,
            textColor=C_SLATE, alignment=TA_CENTER, leading=12),
    }


def _header_footer(canvas, doc):
    """Draw a clean header/footer on every page."""
    canvas.saveState()
    w, h = A4
    margin = 0.75 * inch

    # ── Header bar (dark navy) ─────────────────────────────────────
    canvas.setFillColor(C_BLUE_DARK)
    canvas.rect(0, h - 38, w, 38, fill=1, stroke=0)

    canvas.setFillColor(C_WHITE)
    canvas.setFont("Helvetica-Bold", 10)
    canvas.drawString(margin, h - 24, "ATT&CKLens — Incident Analysis Report")

    canvas.setFillColor(colors.HexColor("#93C5FD"))
    canvas.setFont("Helvetica", 8)
    canvas.drawRightString(w - margin, h - 24,
        f"CONFIDENTIAL  ·  {datetime.utcnow().strftime('%d %b %Y, %H:%M UTC')}")

    # ── Footer ─────────────────────────────────────────────────────
    canvas.setFillColor(C_LIGHT_GREY)
    canvas.rect(0, 0, w, 26, fill=1, stroke=0)
    canvas.setStrokeColor(C_BORDER)
    canvas.setLineWidth(0.5)
    canvas.line(0, 26, w, 26)

    canvas.setFillColor(C_MUTED)
    canvas.setFont("Helvetica", 7.5)
    canvas.drawString(margin, 9, "Generated by ATT&CKLens  ·  Powered by Groq  ·  MITRE ATT&CK® Enterprise")
    canvas.drawRightString(w - margin, 9, f"Page {doc.page}")

    canvas.restoreState()


def generate_pdf_report(data: dict) -> bytes:
    """Build the full PDF report and return it as bytes."""
    buf = io.BytesIO()
    S = _styles()

    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=0.75 * inch, rightMargin=0.75 * inch,
        topMargin=0.9 * inch, bottomMargin=0.55 * inch,
    )

    page_w = A4[0] - 1.5 * inch
    story  = []

    sev = data.get("severity", "Unknown")
    sev_bg, sev_fg = SEVERITY_COLORS.get(sev, (C_LIGHT_GREY, C_SLATE))
    sev_score    = data.get("severity_score", "—")
    threat_class = data.get("threat_classification", "Unknown")
    gen_at = data.get("generated_at", datetime.utcnow().isoformat())[:19].replace("T", " ")

    # ── COVER PAGE ────────────────────────────────────────────────────────────
    # Full-width dark banner
    class CoverBanner(Flowable):
        def __init__(self, w):
            super().__init__()
            self.width = w
            self.height = 1.6 * inch
        def draw(self):
            c = self.canv
            c.setFillColor(C_BLUE_DARK)
            c.rect(0, 0, self.width, self.height, fill=1, stroke=0)
            # Subtle bottom accent line
            c.setFillColor(C_BLUE_MID)
            c.rect(0, 0, self.width, 3, fill=1, stroke=0)
            c.setFillColor(C_WHITE)
            c.setFont("Helvetica-Bold", 24)
            c.drawString(0.25 * inch, self.height - 0.55 * inch, "ATT&CKLens")
            c.setFillColor(colors.HexColor("#93C5FD"))
            c.setFont("Helvetica", 11)
            c.drawString(0.25 * inch, self.height - 0.85 * inch,
                         "AI-Powered Incident Analysis & MITRE ATT&CK Report")

    story.append(CoverBanner(page_w))
    story.append(Spacer(1, 0.3 * inch))

    # Cover metadata table — clean white with light borders
    cover_rows = [
        ["Threat Classification", threat_class],
        ["Severity Level",        sev],
        ["Risk Score",            f"{sev_score} / 10"],
        ["Report Generated",      gen_at + " UTC"],
        ["Framework",             "MITRE ATT&CK Enterprise"],
    ]

    def _cover_cell(text, bold=False):
        return Paragraph(text, ParagraphStyle("cc",
            fontName="Helvetica-Bold" if bold else "Helvetica",
            fontSize=10, textColor=C_INK, leading=14))

    cover_table_data = [
        [_cover_cell(r[0], bold=True), _cover_cell(r[1])]
        for r in cover_rows
    ]

    ct = Table(cover_table_data, colWidths=[2.2 * inch, page_w - 2.2 * inch])
    ct.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (0, -1), C_LIGHT_GREY),
        ("BACKGROUND",    (1, 0), (1, -1), C_WHITE),
        ("ROWBACKGROUNDS",(0, 0), (-1, -1), [C_LIGHT_GREY, C_OFF_WHITE] * 5),
        ("GRID",          (0, 0), (-1, -1), 0.5, C_BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
        ("LEFTPADDING",   (0, 0), (-1, -1), 12),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 12),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        # Severity cell gets colour treatment
        ("BACKGROUND",    (1, 1), (1, 1), sev_bg),
        ("TEXTCOLOR",     (1, 1), (1, 1), sev_fg),
    ]))
    story.append(ct)
    story.append(Spacer(1, 0.35 * inch))

    # Scenario snippet box
    scenario = data.get("scenario", "")
    if scenario:
        story.append(Paragraph("Incident Scenario", S["subsection"]))
        story.append(ColoredLine(page_w, C_BORDER_MED))
        story.append(Spacer(1, 5))
        snippet = scenario[:600] + ("…" if len(scenario) > 600 else "")
        snip_style = ParagraphStyle("snip",
            fontName="Helvetica", fontSize=9, textColor=C_SLATE,
            leading=14, leftIndent=10, borderPadding=(8, 10, 8, 10),
            backColor=C_OFF_WHITE, borderColor=C_BORDER,
            borderWidth=0.5, borderRadius=4)
        story.append(Paragraph(snippet, snip_style))

    story.append(PageBreak())

    # ── SECTION / BULLET HELPERS ──────────────────────────────────────────────
    def section(title):
        story.append(Spacer(1, 6))
        story.append(Paragraph(title, S["section_title"]))
        story.append(ColoredLine(page_w, C_BLUE_MID, 1.5))
        story.append(Spacer(1, 6))

    def bullets(items):
        for item in (items or []):
            story.append(Paragraph(f"• &nbsp;{item}", S["bullet"]))

    def table_style_clean(header_cols=None):
        """Return a standard clean TableStyle."""
        base = [
            ("BACKGROUND",    (0, 0), (-1, 0), C_BLUE_LIGHT),
            ("TEXTCOLOR",     (0, 0), (-1, 0), C_BLUE_DARK),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 8.5),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_WHITE, C_OFF_WHITE]),
            ("TEXTCOLOR",     (0, 1), (-1, -1), C_INK),
            ("GRID",          (0, 0), (-1, -1), 0.4, C_BORDER),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING",   (0, 0), (-1, -1), 7),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 7),
        ]
        return TableStyle(base)

    # ── 1. EXECUTIVE SUMMARY ──────────────────────────────────────────────────
    section("1.  Executive Summary")
    story.append(Paragraph(data.get("executive_summary", "N/A"), S["body"]))

    # ── 2. SEVERITY & RISK ────────────────────────────────────────────────────
    section("2.  Severity &amp; Risk Assessment")
    risk_rows = [
        ["Severity", "Risk Score", "Threat Classification"],
        [sev,        f"{sev_score} / 10", threat_class],
    ]
    rt = Table(risk_rows, colWidths=[page_w / 3] * 3)
    rt_style = table_style_clean()
    rt_style.add("ALIGN",       (0, 0), (-1, -1), "CENTER")
    rt_style.add("FONTNAME",    (0, 1), (-1, 1),  "Helvetica-Bold")
    rt_style.add("FONTSIZE",    (0, 1), (-1, 1),  10)
    rt_style.add("BACKGROUND",  (0, 1), (0, 1),   sev_bg)
    rt_style.add("TEXTCOLOR",   (0, 1), (0, 1),   sev_fg)
    rt.setStyle(rt_style)
    story.append(rt)

    # ── 3. ATTACK TIMELINE ────────────────────────────────────────────────────
    section("3.  Attack Flow Timeline")
    timeline = data.get("attack_flow_timeline", [])
    if timeline:
        tl_data = [["#", "Phase", "Time", "Description"]]
        for i, step in enumerate(timeline, 1):
            tl_data.append([
                str(i),
                step.get("phase", ""),
                step.get("timestamp_label", ""),
                step.get("description", ""),
            ])
        col_w = [0.3 * inch, 1.3 * inch, 1.1 * inch, page_w - 2.7 * inch]
        tlt = Table(tl_data, colWidths=col_w, repeatRows=1)
        tlt_style = table_style_clean()
        tlt_style.add("FONTNAME", (1, 1), (1, -1), "Helvetica-Bold")
        tlt_style.add("TEXTCOLOR", (1, 1), (1, -1), C_BLUE_DARK)
        tlt_style.add("ALIGN", (0, 0), (0, -1), "CENTER")
        tlt.setStyle(tlt_style)
        story.append(tlt)
    else:
        story.append(Paragraph("No timeline data available.", S["body"]))

    story.append(PageBreak())

    # ── 4. MITRE ATT&CK MAPPING ───────────────────────────────────────────────
    section("4.  MITRE ATT&amp;CK Mapping")
    mitre = data.get("mitre_mapping", [])
    if mitre:
        mt_data = [["Type", "ID", "Name", "Description", "URL"]]
        for m in mitre:
            desc = m.get("description", "")
            mt_data.append([
                m.get("type", ""),
                m.get("id", ""),
                m.get("name", ""),
                desc[:110] + ("…" if len(desc) > 110 else ""),
                m.get("url", ""),
            ])
        col_w = [0.75*inch, 0.75*inch, 1.3*inch, page_w - 3.55*inch, 1.75*inch]
        mtt = Table(mt_data, colWidths=col_w, repeatRows=1)
        mtt_style = table_style_clean()
        mtt_style.add("FONTNAME",  (1, 1), (1, -1), "Courier-Bold")
        mtt_style.add("TEXTCOLOR", (1, 1), (1, -1), C_BLUE_MID)
        mtt_style.add("FONTNAME",  (4, 1), (4, -1), "Courier")
        mtt_style.add("TEXTCOLOR", (4, 1), (4, -1), C_SLATE)
        mtt_style.add("FONTSIZE",  (4, 1), (4, -1), 7)
        mtt.setStyle(mtt_style)
        story.append(mtt)
    else:
        story.append(Paragraph("No MITRE mapping available.", S["body"]))

    story.append(PageBreak())

    # ── 5. INDICATORS OF COMPROMISE ──────────────────────────────────────────
    section("5.  Indicators of Compromise (IOCs)")
    iocs = data.get("iocs", {})
    ioc_map = {
        "IP Addresses":         iocs.get("ip_addresses", []),
        "Domains":              iocs.get("domains", []),
        "URLs":                 iocs.get("urls", []),
        "Email Addresses":      iocs.get("emails", []),
        "File Hashes":          iocs.get("file_hashes", []),
        "Suspicious Filenames": iocs.get("filenames", []),
    }
    has_ioc = any(ioc_map.values())
    if has_ioc:
        for category, items in ioc_map.items():
            if not items:
                continue
            story.append(Paragraph(category, S["subsection"]))
            ioc_rows = [[Paragraph(item, S["mono"])] for item in items]
            it = Table(ioc_rows, colWidths=[page_w])
            it.setStyle(TableStyle([
                ("ROWBACKGROUNDS", (0, 0), (-1, -1), [C_WHITE, C_OFF_WHITE]),
                ("GRID",           (0, 0), (-1, -1), 0.3, C_BORDER),
                ("TOPPADDING",     (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING",  (0, 0), (-1, -1), 5),
                ("LEFTPADDING",    (0, 0), (-1, -1), 10),
            ]))
            story.append(it)
            story.append(Spacer(1, 6))
    else:
        story.append(Paragraph(
            "No specific IOCs were identified in the provided scenario. "
            "Extract IOCs from live log sources and SIEM alerts for a real investigation.",
            S["body"]
        ))

    # ── 6–8. IMPACT, PERSISTENCE, LATERAL MOVEMENT ───────────────────────────
    section("6.  Potential Impact")
    bullets(data.get("potential_impact", []))

    section("7.  Persistence Mechanisms")
    bullets(data.get("persistence_mechanisms", []))

    section("8.  Lateral Movement Indicators")
    bullets(data.get("lateral_movement_indicators", []))

    story.append(PageBreak())

    # ── 9–13. DETECTION, MITIGATION, HUNTING, LOGS, FAILURES ─────────────────
    section("9.  Detection Opportunities")
    bullets(data.get("detection_opportunities", []))

    section("10. Mitigation Recommendations")
    bullets(data.get("mitigation_recommendations", []))

    section("11. Threat Hunting Suggestions")
    bullets(data.get("threat_hunting_suggestions", []))

    section("12. Recommended Log Sources")
    bullets(data.get("recommended_log_sources", []))

    section("13. Security Control Failures")
    bullets(data.get("security_control_failures", []))

    # ── DISCLAIMER ────────────────────────────────────────────────────────────
    story.append(PageBreak())
    story.append(Spacer(1, 0.6 * inch))
    story.append(ColoredLine(page_w, C_BORDER_MED, 1))
    story.append(Spacer(1, 12))
    story.append(Paragraph("CONFIDENTIAL — FOR AUTHORIZED USE ONLY", S["disclaimer"]))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "This report was generated automatically by ATT&amp;CKLens using AI inference. "
        "All findings should be validated by a qualified security professional before taking action. "
        "MITRE ATT&amp;CK® is a registered trademark of The MITRE Corporation.",
        S["disclaimer"]
    ))

    # ── BUILD ─────────────────────────────────────────────────────────────────
    doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)
    return buf.getvalue()


if __name__ == "__main__":
    app.run(debug=True, port=5000)
