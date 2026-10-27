import os
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List

# Indian Standard Time (IST = UTC+5:30)
IST = timezone(timedelta(hours=5, minutes=30))


class CorruptionReportService:
    """
    Standardized Forensic Corruption Audit Report Generator.
    Produces interactive standalone HTML reports and structured JSON representations.
    """

    @classmethod
    def generate_html_report(cls, record: Dict[str, Any]) -> str:
        """Renders a self-contained, beautifully styled HTML corruption report."""
        timestamp = record.get("timestamp", datetime.now(IST).strftime("%Y-%m-%d %I:%M:%S %p IST"))
        orig_filename = record.get("original_filename", "document")
        corr_filename = record.get("corrupted_filename", "corrupted_document")
        file_type = (record.get("file_type") or "PDF").upper()
        orig_size = record.get("original_size_human", "0 B")
        corr_size = record.get("corrupted_size_human", "0 B")
        is_all = record.get("is_all", False)
        summary = record.get("summary", "Document surgically corrupted.")
        regions = record.get("corrupted_regions", [])
        matrix = record.get("structure_matrix", {})
        diffs = record.get("hex_diffs", [])
        corr_id = record.get("id", "")

        # Format matrix items
        sections = [
            ("HEADER", "header", "Magic bytes & container header"),
            ("BODY", "body", "Content streams & object syntax"),
            ("REFERENCE", "reference", "Cross-reference (XREF) & pointers"),
            ("END OF FILE", "end_of_file", "Trailer dictionary & %%EOF"),
            ("IMAGES", "images", "Embedded visual streams & raster"),
        ]

        matrix_cards_html = ""
        for display_name, key, desc in sections:
            status = matrix.get(key, "INTACT")
            is_corrupt = status == "CORRUPTED"
            badge_class = "badge-corrupted" if is_corrupt else "badge-intact"
            status_text = "⚡ CORRUPTED" if is_corrupt else "✓ INTACT"
            icon = "⚡" if is_corrupt else "✓"
            
            matrix_cards_html += f"""
            <div class="matrix-card {'matrix-card-corrupted' if is_corrupt else 'matrix-card-intact'}">
                <div class="matrix-header">
                    <span class="matrix-title">{display_name}</span>
                    <span class="matrix-badge {badge_class}">{status_text}</span>
                </div>
                <p class="matrix-desc">{desc}</p>
            </div>
            """

        # Regions table
        regions_rows_html = ""
        for r in regions:
            regions_rows_html += f"""
            <tr>
                <td><strong>{r.get('name', 'Region')}</strong></td>
                <td><span class="badge-corrupted" style="padding:2px 8px; border-radius:4px; font-weight:700; font-size:11px;">CORRUPTED</span></td>
                <td class="mono-cell">Offset {r.get('offset', 0)}</td>
                <td>{r.get('description', '')}</td>
            </tr>
            """

        # Hex diffs
        diffs_html = ""
        for d in diffs:
            diffs_html += f"""
            <div class="diff-block">
                <div class="diff-title">
                    <span>⚡ {d.get('name', 'Region')} (Offset: {d.get('offset', 0)})</span>
                    <small>{d.get('description', '')}</small>
                </div>
                <div class="diff-grid">
                    <div class="diff-side diff-original">
                        <div class="diff-side-title">ORIGINAL BYTES (Offset {d.get('offset', 0)})</div>
                        <pre class="diff-hex">{d.get('original_hex', '')}</pre>
                        <pre class="diff-ascii">{d.get('original_ascii', '')}</pre>
                    </div>
                    <div class="diff-side diff-corrupted">
                        <div class="diff-side-title">CORRUPTED BYTES (Altered)</div>
                        <pre class="diff-hex hex-corrupt">{d.get('corrupted_hex', '')}</pre>
                        <pre class="diff-ascii ascii-corrupt">{d.get('corrupted_ascii', '')}</pre>
                    </div>
                </div>
            </div>
            """

        download_url = f"/api/corrupt/download/{corr_id}" if corr_id else "#"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FileGuard AI - Forensic Corruption Audit Report: {orig_filename}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-main: #0a0e17;
            --bg-surface: #111827;
            --bg-card: rgba(17, 24, 39, 0.95);
            --border-color: rgba(255, 255, 255, 0.1);
            --primary: #38bdf8;
            --danger: #ef4444;
            --danger-bg: rgba(239, 68, 68, 0.15);
            --success: #10b981;
            --success-bg: rgba(16, 185, 129, 0.15);
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --text-muted: #64748b;
            --font-sans: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            --font-mono: 'JetBrains Mono', monospace;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background: var(--bg-main);
            color: var(--text-primary);
            font-family: var(--font-sans);
            padding: 30px 20px;
            line-height: 1.5;
        }}
        .report-container {{
            max-width: 980px;
            margin: 0 auto;
            background: var(--bg-surface);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            overflow: hidden;
            box-shadow: 0 10px 40px rgba(0,0,0,0.5);
        }}
        .report-header {{
            background: linear-gradient(135deg, rgba(239, 68, 68, 0.2) 0%, rgba(17, 24, 39, 0.9) 100%);
            border-bottom: 1px solid var(--border-color);
            padding: 28px 32px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 16px;
        }}
        .brand-title {{
            font-size: 1.4rem;
            font-weight: 800;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .report-tag {{
            background: var(--danger-bg);
            color: var(--danger);
            border: 1px solid rgba(239, 68, 68, 0.3);
            padding: 4px 12px;
            border-radius: 9999px;
            font-size: 12px;
            font-weight: 700;
            letter-spacing: 0.5px;
        }}
        .report-body {{
            padding: 32px;
            display: flex;
            flex-direction: column;
            gap: 28px;
        }}
        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 20px;
        }}
        .info-item {{
            display: flex;
            flex-direction: column;
            gap: 4px;
        }}
        .info-label {{
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-muted);
            font-weight: 600;
        }}
        .info-val {{
            font-size: 14px;
            font-weight: 700;
            color: #fff;
            word-break: break-all;
        }}
        .summary-banner {{
            background: rgba(239, 68, 68, 0.1);
            border-left: 4px solid var(--danger);
            border-radius: 8px;
            padding: 16px 20px;
            font-size: 14px;
            line-height: 1.6;
        }}
        .section-heading {{
            font-size: 1.15rem;
            font-weight: 700;
            margin-bottom: 14px;
            display: flex;
            align-items: center;
            gap: 8px;
            color: #fff;
            border-bottom: 1px solid rgba(255,255,255,0.06);
            padding-bottom: 8px;
        }}
        .matrix-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
            gap: 12px;
        }}
        .matrix-card {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 14px;
            display: flex;
            flex-direction: column;
            gap: 8px;
        }}
        .matrix-card-corrupted {{
            border-color: rgba(239, 68, 68, 0.4);
            background: rgba(239, 68, 68, 0.05);
        }}
        .matrix-card-intact {{
            border-color: rgba(16, 185, 129, 0.25);
            background: rgba(16, 185, 129, 0.03);
        }}
        .matrix-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .matrix-title {{
            font-weight: 700;
            font-size: 13px;
        }}
        .matrix-badge {{
            font-size: 10px;
            font-weight: 800;
            padding: 2px 6px;
            border-radius: 4px;
        }}
        .badge-corrupted {{
            background: var(--danger-bg);
            color: var(--danger);
            border: 1px solid rgba(239, 68, 68, 0.3);
        }}
        .badge-intact {{
            background: var(--success-bg);
            color: var(--success);
            border: 1px solid rgba(16, 185, 129, 0.3);
        }}
        .matrix-desc {{
            font-size: 11px;
            color: var(--text-muted);
        }}
        .table-wrap {{
            overflow-x: auto;
            border: 1px solid var(--border-color);
            border-radius: 10px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
            text-align: left;
        }}
        th {{
            background: rgba(255,255,255,0.03);
            padding: 12px 16px;
            color: var(--text-secondary);
            font-weight: 600;
            border-bottom: 1px solid var(--border-color);
        }}
        td {{
            padding: 12px 16px;
            border-bottom: 1px solid rgba(255,255,255,0.04);
            vertical-align: middle;
        }}
        .mono-cell {{
            font-family: var(--font-mono);
            font-size: 12px;
            color: var(--primary);
        }}
        .diff-block {{
            background: #090d16;
            border: 1px solid var(--border-color);
            border-radius: 10px;
            overflow: hidden;
            margin-bottom: 16px;
        }}
        .diff-title {{
            background: rgba(255,255,255,0.03);
            padding: 10px 16px;
            font-size: 13px;
            font-weight: 700;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-color);
        }}
        .diff-title small {{
            color: var(--text-muted);
            font-weight: 400;
        }}
        .diff-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1px;
            background: var(--border-color);
        }}
        @media (max-width: 768px) {{
            .diff-grid {{ grid-template-columns: 1fr; }}
        }}
        .diff-side {{
            background: #0d1322;
            padding: 14px 16px;
        }}
        .diff-side-title {{
            font-size: 11px;
            font-weight: 700;
            color: var(--text-muted);
            margin-bottom: 8px;
            letter-spacing: 0.5px;
        }}
        pre.diff-hex {{
            font-family: var(--font-mono);
            font-size: 11px;
            color: #94a3b8;
            margin-bottom: 6px;
            word-break: break-all;
            white-space: pre-wrap;
        }}
        pre.diff-ascii {{
            font-family: var(--font-mono);
            font-size: 11px;
            color: #38bdf8;
            word-break: break-all;
            white-space: pre-wrap;
        }}
        .hex-corrupt {{ color: #f87171 !important; }}
        .ascii-corrupt {{ color: #ef4444 !important; font-weight: 700; }}
        .actions-bar {{
            display: flex;
            justify-content: flex-end;
            gap: 12px;
            margin-top: 10px;
        }}
        .btn {{
            padding: 10px 20px;
            border-radius: 8px;
            font-weight: 700;
            font-size: 13px;
            cursor: pointer;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            transition: 0.15s ease;
        }}
        .btn-download {{
            background: var(--danger);
            color: #fff;
            border: none;
        }}
        .btn-download:hover {{
            background: #dc2626;
        }}
        .btn-outline {{
            background: transparent;
            color: var(--text-primary);
            border: 1px solid var(--border-color);
        }}
        .btn-outline:hover {{
            background: rgba(255,255,255,0.05);
        }}
        @media print {{
            body {{ background: #fff; color: #000; padding: 0; }}
            .report-container {{ border: none; box-shadow: none; }}
            .actions-bar {{ display: none; }}
        }}
    </style>
</head>
<body>
    <div class="report-container">
        <div class="report-header">
            <div>
                <div class="brand-title">🛡️ FileGuard AI <span>• Forensic Studio</span></div>
                <div style="font-size:12px; color:var(--text-muted); margin-top:4px;">Controlled Document Corruption Audit Report</div>
            </div>
            <div style="display:flex; gap:8px; align-items:center;">
                <span class="report-tag">SURGICAL CORRUPTION AUDIT</span>
            </div>
        </div>

        <div class="report-body">
            <!-- Metadata Cards -->
            <div class="info-grid">
                <div class="info-item">
                    <span class="info-label">Original File</span>
                    <span class="info-val">{orig_filename}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Corrupted Output</span>
                    <span class="info-val">{corr_filename}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Detected Type</span>
                    <span class="info-val">{file_type}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Size Comparison</span>
                    <span class="info-val">{orig_size} &rarr; {corr_size}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Audit Timestamp</span>
                    <span class="info-val">{timestamp}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Mode</span>
                    <span class="info-val">{'ALL 5 SECTIONS' if is_all else 'SURGICAL TARGETS'}</span>
                </div>
            </div>

            <!-- Summary Banner -->
            <div class="summary-banner">
                <strong>Forensic Audit Summary:</strong> {summary}
            </div>

            <!-- Structural Matrix -->
            <div>
                <div class="section-heading">Structural Component Status Matrix</div>
                <div class="matrix-grid">
                    {matrix_cards_html}
                </div>
            </div>

            <!-- Altered Regions Table -->
            <div>
                <div class="section-heading">Corrupted Regions & Defect Breakdown</div>
                <div class="table-wrap">
                    <table>
                        <thead>
                            <tr>
                                <th>Section Name</th>
                                <th>Status</th>
                                <th>Byte Offset</th>
                                <th>Defect Description</th>
                            </tr>
                        </thead>
                        <tbody>
                            {regions_rows_html}
                        </tbody>
                    </table>
                </div>
            </div>

            </div>
        </div>
    </div>
</body>
</html>
"""
        return html
