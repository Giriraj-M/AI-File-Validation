# FileGuard AI — Intelligent File Validation, Document Corruption & Multi-Strategy Recovery 🛡️

## Project Overview

**FileGuard AI V3** is an enterprise-grade document intelligence, forensic inspection, surgical corruption simulation, and multi-strategy recovery platform. It replaces rigid, complicated upload wizards and unreliable file repair tools with a clean, conversational interface, a dedicated **Surgical Corruption Studio**, and an autonomous **Forensic Recovery Workbench**.

Instead of configuring dozens of checkboxes or guessing why a document failed, you simply attach a file and type what you need in plain English — for example:  
> *"Validate this PDF and make sure it is under 5 MB."*  
> *"Inspect this damaged Excel spreadsheet and recover all readable data."*  
> *"Surgically corrupt the XREF table and header to benchmark our parser's fault tolerance."*  
> *"Check for hidden malware, prompt injections, or corrupted binary streams."*

FileGuard AI V3 understands your requirements using artificial intelligence (**Google Gemini 3.5 Flash** with an offline deterministic NLP fallback), executes strict multi-layer backend checks, benchmarks document resilience via a **controlled surgical corruption engine**, and features a **deterministic 7-tier recovery engine** that repairs corrupted documents (**PDF, Word, Excel, PowerPoint, Images, CSV, JSON, and Text**) without ever generating fake or blank documents. It is fully serverless-ready with automated `/tmp` ephemeral storage adaptation for Vercel and AWS Lambda deployments.

---

## How It Works in 4 Simple Steps

1. **Attach & Prompt (or Drop Corrupted Files)**: Upload any document and type your validation rules in plain English, benchmark parser resilience in the Corruption Studio, or upload single/batch corrupted documents directly into the Recovery Workbench.
2. **Surgical Defect Simulation (Optional Benchmarking)**: Intentionally inject controlled structural damage across Header, Body, XREF, Trailer/EOF, or ZIP container structures to benchmark error-handling and recovery capabilities.
3. **Forensic Inspection & Multi-Strategy Repair**: The system parses your requirements, verifies raw binary magic bytes, isolates regional corruption, and automatically executes the best repair strategy with progressive fallbacks.
4. **Instant Results, Restored Files & Audit Reports**: Receive a clear 0–100% validation score, download the fully restored files (or a bundled ZIP for batch jobs), and inspect granular HTML/JSON forensic audit reports.

---

## Why FileGuard AI V3?

Traditional file upload forms only check the file extension (like `.pdf` or `.docx`). This creates serious security and reliability risks: malicious executables can easily be renamed, and damaged files cause silent system crashes.

| What Traditional Forms Do | What FileGuard AI V3 Does |
|:---|:---|
| **Trust file extensions**: Relies on `.pdf` or `.xlsx` in the file name, easily fooled by renamed files. | **Inspects true binary bytes**: Scans raw header signatures to detect the authentic format regardless of extension. |
| **Rigid configuration**: Requires complex dropdowns, multi-step wizards, and fixed form rules. | **Natural language prompts**: Understands flexible instructions in plain English using Gemini AI or offline NLP. |
| **No resilience benchmarking**: Cannot systematically test parser error handling or resilience. | **Dedicated Corruption Studio (`/corrupt`)**: Surgically injects localized defects across Header, Body, XREF, Trailer, EOF, and Media. |
| **Misses corruption & rejects broken files**: Fails silently or rejects corrupted documents with no repair option. | **Forensic diagnosis & multi-strategy repair**: Pinpoints corruption regions and automatically recovers damaged files. |
| **Emits fake blank files**: Primitive repair scripts create empty or unreadable dummy documents. | **Authentic content salvage**: Strict anti-blank gates guarantee genuine data recovery or accurate `UNRECOVERABLE` warnings. |
| **Ignores security threats**: Does not scan document text for hidden malicious directives or data leaks. | **Content security checks**: Scans for disguised PE/ELF executables, prompt injections, and leaked PII/credentials. |
| **Vague error messages**: Shows generic "Upload failed" notices without explaining why. | **Comprehensive audit reports**: Provides interactive HTML reports, 1:1 ground-truth metrics, and structured JSON logs. |

---

## Tools & Frameworks

FileGuard AI V3 is built on a battle-tested stack of forensic document inspection libraries, artificial intelligence models, secure web frameworks, and automated testing tools:

### 1. Backend & Web Architecture
- **Python (3.10+)**: Primary runtime language powering the pipeline and forensic algorithms.
- **Flask (3.0+)**: Core web framework managing REST API endpoints, routing, and Jinja2 server-rendered views.
- **Werkzeug (3.0+)**: WSGI utility layer enforcing file upload boundaries, `secure_filename()` sanitization, and hardened security headers.
- **FastAPI & Uvicorn**: High-concurrency microservice routing and asynchronous event utilities.
- **Python-Dotenv**: Multi-environment secrets and runtime configuration management.
- **Requests & HTTPX**: Synchronous and asynchronous HTTP client engines for external API communication.
- **Serverless / Vercel Adapter**: Dynamic path resolver redirecting persistent writes to `/tmp/ai-file-validation` in read-only serverless cloud runtimes.

### 2. Artificial Intelligence & NLP
- **Google Gemini API (`google-generativeai`)**: Powered by `gemini-3.5-flash` for conversational requirement parsing, contextual explanations, and document categorization.
- **Deterministic Lexical NLP**: Zero-dependency offline NLP fallback engine utilizing compiled regular expressions and grammatical keyword extraction.
- **Heuristic Content Scanner**: Pattern matching engine detecting adversarial prompt injections, jailbreak tokens, and sensitive PII/secrets.

### 3. PDF Forensics & Multi-Tier Recovery
- **QPDF (CLI & Engine)**: Industry-standard structural linearization, object stream decanting, and cross-reference normalization.
- **pikepdf (libqpdf)**: Low-level C++ object manipulation and cross-reference table repair.
- **PyMuPDF (fitz)**: High-speed C-based engine for pixmap page rendering verification, heuristic stream normalization, and text extraction.
- **pypdf (4.0+)**: Permissive object tree traversal, xref rebuilding, and page dictionary reassembly.
- **pdfplumber**: Layout-aware visual text and tabular bounding box extraction for 1:1 ground-truth fidelity analysis.
- **ReportLab (4.0+)**: High-fidelity PDF generation engine for synthesizing clean, renderable documents from salvaged stream tokens.

### 4. Office & Media Forensic Engines
- **python-docx (1.1+)**: OpenXML package inspector, XML paragraph/table tree rebuilder, and Word document reconstructor.
- **openpyxl (3.1+)**: Spreadsheet XML parser, worksheet recovery, shared string repair, and workbook assembler.
- **python-pptx (1.0+)**: Presentation package inspector and drawing ML shape text salvager.
- **Pillow (PIL 10.0+)**: Dual-pass image integrity analyzer (`verify()` + `load()`), raw pixel stream decoder, and JPEG/PNG header reconstruction.
- **filetype (1.2+)**: Binary magic byte and MIME signature identification engine.
- **zlib & zipfile**: Low-level raw deflate decompression (`-zlib.MAX_WBITS`), chunked streaming decompression, and ZIP container repair.

### 5. Frontend & User Interface
- **HTML5 & Vanilla CSS**: Modern dark-themed design system featuring glassmorphic elevation cards, glowing accents, and responsive CSS Grid/Flexbox layouts.
- **Vanilla JavaScript (ES6+)**: Pure client-side controller handling drag-and-drop file inputs, asynchronous multi-part uploads, live progress bars, modal previews, and ZIP streaming.

### 6. Testing & Quality Assurance
- **pytest (8.0+)**: Automated testing framework powering the 101-test suite covering corruption, recovery, security, and validation pipelines.

---

## The 4-Stage Validation, Corruption & Recovery Pipeline

Every document passes through an automated, hardened pipeline:

```
+-------------------------------------------------------------+
|                USER PROMPT + FILE ATTACHMENT                |
|           (Validation, Corruption, or Batch Recovery)       |
+-------------------------------------------------------------+
                               |
                               v
+-------------------------------------------------------------+
|            STAGE 1: NATURAL LANGUAGE PARSER                 |
|  - Google Gemini 3.5 Flash / Offline NLP Rule Extraction    |
|  - Extracts: Allowed Formats, Size Limits, Security Rules   |
+-------------------------------------------------------------+
                               |
                               v
+-------------------------------------------------------------+
|        STAGE 2: FORENSIC BINARY & CORRUPTION ANALYSIS       |
|  - Magic byte header inspection (first 4,096 bytes)         |
|  - Disguised malware/executable defense (PE, ELF, Mach-O)   |
|  - Regional localization: Header, Body, XREF, Trailer, EOF  |
|  - Size boundary validation & entropy scoring               |
+-------------------------------------------------------------+
                               |
                               v
+-------------------------------------------------------------+
|      STAGE 3: CONTROLLED CORRUPTION OR ADAPTIVE RECOVERY     |
|  • CORRUPTION STUDIO: Surgical section defect injection     |
|    (Header displacement, stream cuts, broken xref, nulls)   |
|  • RECOVERY ENGINE: Multi-strategy progressive pipeline:    |
|    - PDF: 7 tiers (QPDF -> PyMuPDF -> pypdf -> Binary       |
|      Carver -> zlib Salvage -> Isolated Pages -> Synth)     |
|    - Office (DOCX, XLSX, PPTX): ZIP repair & XML element fix|
|    - Images: Dual-pass permissive PIL header & stream repair|
|    - Text/CSV: Binary noise demuxing & encoding detection   |
+-------------------------------------------------------------+
                               |
                               v
+-------------------------------------------------------------+
|        STAGE 4: VERIFICATION, AUDIT REPORT & EXPORT         |
|  - Post-recovery rendering checks & page count validation   |
|  - 1:1 Ground-truth fidelity comparison (text % & images)   |
|  - Downloadable repaired file, corrupted file, or batch ZIP |
|  - Standalone HTML audit report & structured JSON metrics   |
|  - Real-time logging to Security & Validation Dashboards    |
+-------------------------------------------------------------+
```

---

## Controlled Document Corruption Studio

The **Corruption Studio** (`/corrupt`) enables controlled, scientific benchmarking of file parsers and recovery workflows.

### Targeted Regional Defect Simulation:
1. **Header Structure**: Magic byte zeroing, displaced headers (leading network garbage), invalid version tags.
2. **Body & Content Streams**: Stream truncation, bit flipping, stream terminator deletion, null-byte injection.
3. **References & XREF Tables**: Broken xref tables, shifted byte offsets, corrupted object numbering.
4. **Trailer & Metadata Dictionaries**: Stripped `/Root` catalog references, corrupted `/Size` keys, broken metadata trees.
5. **EOF & Terminator**: Truncated `%%EOF` markers, missing `startxref` byte offsets.
6. **ZIP Containers (Office OpenXML)**: Corrupted central directory headers, broken CRC32 checksums, damaged `[Content_Types].xml`.

Every corruption job generates an immediate downloadable corrupted payload, a diagnostic JSON payload, and a visual HTML corruption report detailing exact byte offsets modified.

---

## Multi-Strategy Recovery Engines

### 1. 7-Tier Progressive PDF Recovery Engine
FileGuard AI V3 does not fake recovery. It runs a progressive 7-tier fallback pipeline:
- **Strategy 0 (QPDF / pikepdf)**: Structural linearization and cross-reference normalization.
- **Strategy 1 (Header Realignment & PyMuPDF)**: Strips leading HTTP/network garbage, realigns `%PDF-` magic bytes, and repairs broken stream pointers.
- **Strategy 2 (Permissive pypdf Reassembler)**: Non-strict object stream reassembly and catalog reconstruction.
- **Strategy 3 (Deep Binary Object Scanner)**: Direct regex parser that indexes surviving `obj`/`endobj` pairs, calculates byte offsets, and synthesizes a fresh ASCII `xref` table and trailer.
- **Strategy 4 (Multi-Window zlib Stream Salvage)**: Decompresses damaged flate streams using raw deflate, multi-window buffers, and chunked streaming decompression.
- **Strategy 5 (Isolated Page Object Carver)**: Locates surviving `/Type /Page` dictionaries and reassembles intact pages when intermediate tree nodes are lost.
- **Strategy 6 (Deep Content Token Synthesis)**: Last-resort text extraction from stream literals (`Tj`, `TJ`), tagged elements, and metadata, synthesized cleanly with ReportLab.
- **Terminal Gate (`UNRECOVERABLE`)**: 0-byte files or pure high-entropy random noise are accurately rejected with clear explanations.

### 2. DOCX Forensic Recovery
- Repairs corrupted ZIP central directory headers and local file headers.
- Reconstructs malformed `word/document.xml`, balances open XML tags, and preserves paragraph/table hierarchies.
- Salvages embedded media from `word/media/`.

### 3. XLSX Forensic Recovery
- Traverses `xl/worksheets/sheet*.xml` to restore broken rows, columns, and cell references.
- Reconstructs damaged `xl/sharedStrings.xml` to prevent empty sheets upon opening.
- Rebuilds clean `.xlsx` workbooks via openpyxl.

### 4. PPTX Forensic Recovery
- Reconstructs presentation slide trees (`ppt/slides/slide*.xml`) and relationship mappings.
- Extracts slide text runs from drawing ML elements (`a:t`, `a:p`).

### 5. Image & Media Salvage
- **JPEG**: Reconstructs missing Start-of-Image (SOI `\xFF\xD8`) and scan markers; renders truncated scan lines.
- **PNG**: Validates 8-byte magic header, recalculates CRC32 checksums, and handles truncated `IDAT` chunks.
- Uses permissive decoding via Pillow to save partial renderable graphics.

### 6. Plain Text & CSV Reconstruction
- Auto-detects text encodings (UTF-8, Latin-1, CP1252).
- Filters out null control bytes (`\x00`) and terminal escape noise.
- Normalizes uneven CSV delimiter columns using automated dialect sniffing.

---

## Supported File Formats

FileGuard AI recognizes, validates, corrupts, and recovers the following file formats:

| Format Category | Supported Types | Allowed Extensions | How It Is Verified, Corrupted & Repaired |
|:---|:---|:---|:---|
| **PDF** | Portable Document Format | `.pdf` | Binary `%PDF-` verification, 7-tier progressive repair engine, page rendering tests. |
| **Word** | Microsoft Word Documents | `.docx`, `.doc` | PK ZIP container check, OpenXML XML tree repair, paragraph/table salvage; legacy OLE2 support. |
| **Excel** | Microsoft Excel Spreadsheets | `.xlsx`, `.xls` | PK ZIP container check, sheet/cell XML reconstruction, shared string recovery; legacy OLE2 support. |
| **PowerPoint** | Microsoft PowerPoint | `.pptx`, `.ppt` | PK ZIP container check, slide XML reassembly, drawing text extraction; legacy OLE2 support. |
| **Images** | JPEG, PNG, GIF, WebP | `.jpg`, `.jpeg`, `.png`, `.gif`, `.webp` | Header signature checks, CRC repair, truncated pixel stream rendering via Pillow. |
| **Text Documents**| Plain Text Files | `.txt` | Character encoding verification (UTF-8/Latin-1) and binary null-byte demuxing. |
| **Spreadsheets** | Comma-Separated Values | `.csv` | UTF-8 validation, delimiter alignment, and broken row structure normalization. |
| **Data Formats** | JavaScript Object Notation | `.json` | UTF-8 parsing, syntax balancing, structural key validation. |
| **Archives** | ZIP Compressed Folders | `.zip` | Standard PK archive header and central directory CRC checksum repair. |

---

## Project Structure

```
AI File Validation V3/
│
├── config.py                     # Central configuration (file types, signatures, serverless/Vercel paths)
├── app.py                        # Flask application entry point, routing, error handlers, REST APIs
├── requirements.txt              # Python runtime dependencies
├── .env                          # Local environment configuration (API keys, secrets, thresholds)
├── README.md                     # Comprehensive project documentation
│
├── services/                     # Core business logic, forensic analyzers, and recovery engines
│   ├── __init__.py               # Services package exporter
│   ├── ai_service.py             # Google Gemini integration, NLP prompt parsing, document classification
│   ├── corruption_classifier.py  # Regional localization (Header, Body, XREF, EOF, Media)
│   ├── corruption_history_service.py # Corruption audit log and metrics persistence
│   ├── corruption_report_service.py # Diagnostic JSON and HTML corruption reports
│   ├── corruption_service.py     # Controlled surgical document corruption engine
│   ├── detector.py               # Magic byte and dangerous binary signature scanner
│   ├── document_service.py       # Multi-format document text extraction
│   ├── docx_analyzer.py          # DOCX XML and package inspector
│   ├── docx_recovery.py          # DOCX ZIP and XML element reconstruction
│   ├── file_analysis_service.py  # Deep byte-level binary diagnostics
│   ├── file_detection_service.py # Binary signature matching and format verification
│   ├── history_service.py        # Validation audit history persistence
│   ├── image_analyzer.py         # JPEG/PNG header and chunk analyzer
│   ├── image_recovery.py         # Permissive raster graphic recovery
│   ├── integrity_service.py      # Pre- and post-recovery file health inspection
│   ├── pdf_analyzer.py           # PDF structural parser and diagnostics
│   ├── pdf_body_recovery.py      # PDF object stream and deflate salvager
│   ├── pdf_eof_recovery.py       # PDF trailer injection and EOF stabilizer
│   ├── pdf_header_recovery.py    # PDF header realignment and magic byte repair
│   ├── pdf_image_recovery.py     # Embedded raster stream carver (JPEG/PNG)
│   ├── pdf_recovery.py           # 7-tier progressive PDF recovery engine
│   ├── pdf_xref_recovery.py      # PDF cross-reference table synthesizer
│   ├── pptx_analyzer.py          # PPTX presentation slide analyzer
│   ├── pptx_recovery.py          # PPTX slide text and shape carver
│   ├── recovery_decision_service.py # Adaptive tool selection and fallback planning
│   ├── recovery_engine.py        # Unified recovery orchestrator
│   ├── recovery_history_service.py # Recovery audit log persistence
│   ├── recovery_report.py        # Interactive HTML and JSON audit report generator
│   ├── recovery_service.py       # High-level recovery workflow coordinator
│   ├── recovery_tool_registry.py # Tool registration and dynamic discovery
│   ├── recovery_validator.py     # Content salvage validation gates (anti-blank enforcement)
│   ├── security_service.py       # Path traversal, prompt injection, and PII scanning
│   ├── text_recovery.py          # Plain text and CSV encoding/noise demuxer
│   ├── tool_manager.py           # External binary inspection (QPDF, PyMuPDF, etc.)
│   ├── tool_recommender.py       # Contextual tool recommendation engine
│   ├── tool_registry.py          # Registered recovery tools catalog
│   ├── validation_service.py     # Master orchestrator coordinating all validation layers
│   ├── validator.py              # Ground-truth post-recovery fidelity validator
│   ├── xlsx_analyzer.py          # XLSX sheet and shared strings inspector
│   └── xlsx_recovery.py          # XLSX spreadsheet reconstructor
│
├── utils/                        # Shared helper utilities
│   ├── __init__.py
│   ├── archive_utils.py          # Multi-file ZIP archive creation and extraction utilities
│   ├── file_utils.py             # Safe filename generation (UUID), size formatting, cleanup
│   └── process_utils.py          # Subprocess runner and execution timeout management
│
├── templates/                    # Jinja2 HTML templates
│   ├── base.html                 # Common layout, navigation bar, footer, and styling links
│   ├── index.html                # Main AI Assistant interface with drag-and-drop & preset prompts
│   ├── dashboard.html            # Security & audit log dashboard with metrics and type charts
│   ├── corrupt.html              # Controlled Document Corruption Studio
│   └── recover.html              # Multi-file Document Recovery Workbench
│
├── static/                       # Static frontend assets (CSS, JS, icons)
│   ├── css/
│   │   └── style.css             # Dark-theme stylesheet with glassmorphic cards and responsive layouts
│   └── js/
│       └── app.js                # Asynchronous file upload, live progress steps, dynamic rendering
│
├── tests/                        # Automated pytest test suite (101 passing tests)
│   ├── __init__.py
│   ├── conftest.py               # Pytest fixtures and test environment setup
│   ├── test_ai_service.py        # AI recommendation and injection tests
│   ├── test_batch_recovery.py    # Multi-file batch recovery and ZIP export tests
│   ├── test_file_corruption_studio.py # Corruption studio endpoints and section tests
│   ├── test_file_detection.py    # File detection and disguised executable tests
│   ├── test_fileguard_corruption_recovery.py # End-to-end recovery pipeline tests
│   ├── test_image_recovery.py    # JPEG and PNG image salvage tests
│   ├── test_integrity.py         # Document integrity and health tests
│   ├── test_intelligent_pdf_pipeline.py # PDF classification and confidence tests
│   ├── test_modular_corruption_recovery.py # Regional corruption recovery tests
│   ├── test_pdf_comprehensive_recovery.py # 11 controlled PDF structural damage tests
│   ├── test_pptx_recovery.py     # PowerPoint slide recovery tests
│   ├── test_recovery.py          # Non-blank recovery verification tests
│   ├── test_security.py          # Path traversal, PII, and injection tests
│   ├── test_tool_selection.py    # Dynamic tool manager and fallback tests
│   ├── test_validation.py        # Deterministic validation test cases
│   ├── test_vercel_storage.py    # Vercel/serverless ephemeral path and storage tests
│   └── test_xlsx_recovery.py     # Excel spreadsheet recovery tests
│
└── instance/                     # Runtime application data (ignored in version control)
    ├── uploads/                  # Isolated temporary upload folder (files auto-cleaned)
    ├── corrupted_files/          # Generated corrupted document artifacts
    ├── corruption_reports/       # Diagnostic JSON and HTML corruption reports
    ├── recovered_files/          # Restored files and generated batch ZIP archives
    ├── reports/                  # HTML and JSON recovery audit reports
    ├── temp_corrupted/           # Diagnostic cache for recovery workbench
    ├── validation_history.json   # Local validation audit log storage
    ├── recovery_history.json     # Local recovery audit log storage
    ├── corruption_history.json   # Local corruption audit log storage
    └── batch_history.json        # Local batch recovery audit log storage
```

---

## Quickstart Guide

### 1. Requirements
- Python 3.10, 3.11, or 3.12 installed on your computer.
- Optional: `qpdf` installed on your system for enhanced PDF linearization (automatic Python fallback if not installed).

### 2. Setup
1. Open a terminal in the project folder.
2. Create and activate a Python virtual environment:
   - **On Windows**:  
     ```powershell
     python -m venv venv
     .\venv\Scripts\activate
     ```
   - **On Mac/Linux**:  
     ```bash
     python3 -m venv venv
     source venv/bin/activate
     ```
3. Install the dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Configure `.env` with your settings (add your Gemini API key if you want conversational AI explanations).

### 3. Optional: Install QPDF
FileGuard AI automatically detects QPDF if available, or falls back to internal engines:
- **Windows**: `winget install qpdf.qpdf` or `choco install qpdf`
- **Linux**: `sudo apt install -y qpdf`
- **macOS**: `brew install qpdf`

### 4. Run the App
Start the application by running:
```bash
python app.py
```

### 5. Open in Browser
- **Validation Assistant**: Open `http://127.0.0.1:5000` in your web browser.
- **Corruption Studio**: Open `http://127.0.0.1:5000/corrupt` to simulate surgical file defects.
- **Recovery Workbench**: Open `http://127.0.0.1:5000/recover` to repair damaged files.
- **Security Dashboard**: Open `http://127.0.0.1:5000/dashboard` to view statistics and audit logs.

---

## Configuration Options

All settings are controlled through the `.env` file and central `config.py`:

| Setting | Default Value | What It Does |
|:---|:---|:---|
| **FLASK_ENV** | `development` | Runs the app in development or production mode. |
| **FLASK_SECRET_KEY** | Internal default | Key used to encrypt session data and cookies. |
| **UPLOAD_FOLDER** | `instance/uploads` | Private server folder where files are placed during processing. Auto-routes to `/tmp/ai-file-validation/uploads` in serverless runtimes. |
| **CORRUPTED_FOLDER** | `instance/corrupted_files` | Storage directory for generated corrupted document artifacts. |
| **CORRUPTION_REPORTS_FOLDER**| `instance/corruption_reports`| Storage directory for corruption diagnostic reports. |
| **RECOVERED_FOLDER** | `instance/recovered_files` | Storage directory for repaired files and batch ZIP archives. |
| **REPORTS_FOLDER** | `instance/reports` | Storage folder for generated HTML and JSON recovery reports. |
| **MAX_CONTENT_LENGTH_MB** | `64` | Global maximum file upload size (in MB). |
| **AI_PROVIDER** | `gemini` | Uses Google Gemini for prompt parsing. Falls back to offline NLP if no key is set. |
| **GEMINI_API_KEY** | (Optional) | Your Google Gemini API key. If left blank, the built-in offline NLP engine works automatically. |
| **GEMINI_MODEL** | `gemini-3.5-flash` | Gemini model used for natural language processing and explanations. |
| **MAX_RECOVERY_ATTEMPTS**| `7` | Maximum number of progressive recovery strategies attempted per file. |
| **RECOVERY_TIMEOUT_SECONDS** | `120` | Maximum time allowed per recovery job before timing out. |
| **QPDF_PATH** | (Auto-detected) | Optional explicit path to the `qpdf` executable. |

---

## Prompting Guide & Examples

You can speak naturally to FileGuard AI. Here are common examples:

### Validating Document Types & Size
- *"Validate whether this is a valid PDF document and make sure it is below 5 MB."*
- *"Ensure this file is an Excel spreadsheet and does not exceed 2 MB."*
- *"Check that this Word document is under 10 megabytes."*
- *"This upload must be a PNG or JPEG image and smaller than 1 MB."*
- *"Verify this file is a CSV spreadsheet under 500 KB."*

### Checking for Corruption & Damage
- *"Check if this PDF is damaged, broken, or corrupted."*
- *"Validate that this Excel sheet can be opened and has intact sheets."*
- *"Verify that this image is not truncated or broken."*

### Security & Privacy Audits
- *"Scan this document for prompt injections, suspicious instructions, or leaked credentials."*
- *"Make sure this file is safe and does not contain private keys or sensitive personal data."*

---

## REST API Reference

For developers integrating FileGuard AI V3 into external workflows:

### 1. Validate File
- **URL**: `POST /api/validate`
- **Format**: `multipart/form-data`
- **Inputs**:
  - `prompt` (text): Validation instructions in plain English.
  - `file` (binary): The file to inspect.
- **What it returns**:
  - `validation_status`: `"passed"` or `"failed"`
  - `score`: Validation score (0 to 100)
  - `file`: Details on detected type, authentic signature, size, and corruption status
  - `checks`: Step-by-step breakdown of file type, file size, integrity, and security checks
  - `violations`: Any issues that caused the file to fail
  - `ai_analysis`: A clear summary explanation of the outcome
  - `cache_id`: Cache ID to forward files to other workflows

### 2. Document Corruption Studio
- **URL**: `POST /api/corrupt/upload` (or `POST /api/corrupt`)
- **Format**: `multipart/form-data`
- **Inputs**:
  - `file` (binary): The document to corrupt.
  - `section` (text): Target region (`header`, `body`, `xref`, `trailer`, `eof`, `random_noise`).
  - `defect_type` (text): Defect mechanism (`strip_header`, `truncate_stream`, `corrupt_xref`, `delete_eof`, etc.).
  - `severity` (text): Defect severity level (`low`, `medium`, `high`).
- **What it returns**:
  - `corruption_id`: Unique identifier for the corruption event
  - `corrupted_filename`: Generated corrupted file name
  - `download_url`: Direct download link for the corrupted file
  - `report_url`: Link to visual HTML diagnostic report
  - `summary`: Human-readable summary of applied surgical defects

### 3. Multi-File Batch Recovery
- **URL**: `POST /api/recover/batch`
- **Format**: `multipart/form-data`
- **Inputs**:
  - `files[]` (binary): Multiple corrupted files.
  - `selected_tools` (JSON text, optional): Per-file tool selection map.
  - `selected_tool` (text, optional): Global override tool (`auto`, `qpdf_engine`, `pymupdf_stream_engine`, etc.).
- **What it returns**:
  - `success`: `true`
  - `batch_id`: Unique batch identifier
  - `results`: Detailed repair outcome per file (score, method, preview snippet, download URLs)
  - `report_urls`: Links to batch HTML report, JSON summary, and bundled ZIP download

### 4. Single File Recovery & 1:1 Ground-Truth Comparison
- **URL**: `POST /api/recover`
- **Format**: `multipart/form-data`
- **Inputs**:
  - `file` (binary): The corrupted file.
  - `file_type` (text, optional): Target format (`auto`, `pdf`, `word`, `excel`, etc.).
  - `original_file` (binary, optional): Intact reference original to compute exact 1:1 recovery metrics.
- **What it returns**:
  - `status`: `"SUCCESS"`, `"PARTIAL"`, or `"UNRECOVERABLE"`
  - `confidence_score`: 0 to 100%
  - `recovery_method`: Exact technical tool/strategy applied
  - `pages_recovered` & `text_recovery`: 1:1 fidelity metrics
  - `download_url`: Direct download link for the restored document
  - `report_html_url`: Direct link to standalone forensic audit report

### 5. Forensic Batch Pre-Analysis
- **URL**: `POST /api/analyze/batch`
- **Format**: `multipart/form-data`
- **What it returns**: Corruption scores, detected corruption regions, and recommended tools for each file before executing recovery.

### 6. View History & Statistics
- **URL**: `GET /api/history` — Returns recent validation records.
- **URL**: `GET /api/stats` — Returns validation counts, pass/fail ratios, and type distribution.
- **URL**: `GET /api/corrupt/stats` — Returns corruption studio operations and breakdown.
- **URL**: `GET /api/corrupt/history` — Returns corruption studio audit logs.
- **URL**: `GET /api/tools` & `GET /api/tools/status` — Returns status of registered tools and external dependencies.
- **URL**: `POST /api/clear-history` — Clears validation audit logs.
- **URL**: `POST /api/corrupt/clear-all` — Clears generated corrupted files.
- **URL**: `POST /api/recover/clear-all` — Clears generated recovered files.
- **URL**: `POST /api/clean-temp` — Cleans up temporary diagnostic files.

---

## Automated Test Suite (101 Passing Tests)

FileGuard AI V3 includes an extensive automated test suite using **pytest** with **101 unit and integration tests** passing with 100% success across 18 test modules:

To run the full suite:
```bash
python -m pytest -v
```

### What the tests cover:
- **Controlled Corruption Studio Tests (`test_file_corruption_studio.py`)**:
  - Surgical corruption by section (Header, Body, XREF, Trailer, EOF)
  - Defect intensity and multi-defect application
  - Diagnostic corruption report generation and download endpoints
- **11 Controlled PDF Structural Damage Tests (`test_pdf_comprehensive_recovery.py`)**:
  - Missing EOF injection (`%%EOF`)
  - Damaged `startxref` offset recalculation
  - Damaged cross-reference table (`xref`) reconstruction
  - Corrupted trailer dictionary repair
  - Displaced headers and shifted object offsets
  - Metadata sanitization
  - Truncated stream recovery
  - Random byte corruption recovery
  - Multiple simultaneous structural corruptions
  - Accurate rejection of 0-byte files (`UNRECOVERABLE`)
  - Accurate rejection of pure random noise (`UNRECOVERABLE`)
- **End-to-End Recovery & Ground Truth (`test_fileguard_corruption_recovery.py`, `test_recovery.py`)**:
  - Full workflow execution and non-blank recovery verification
  - Regional corruption analysis and recommended tools
  - History lifecycle and reporting
- **Intelligent PDF Pipeline (`test_intelligent_pdf_pipeline.py`)**:
  - Regional classification confidence scoring
  - Automated strategy progression and report asset serving
- **Modular Corruption Recovery (`test_modular_corruption_recovery.py`)**:
  - Individual header, body, xref, and eof recovery validation
  - Embedded raster image corruption recovery
  - Tool manager status and unified system interfaces
- **DOCX, XLSX & PPTX Forensics (`test_xlsx_recovery.py`, `test_pptx_recovery.py`)**:
  - ZIP central directory repair
  - Broken `document.xml` parsing
  - Shifted spreadsheet header recovery and empty sheet protection
  - PowerPoint slide shape text salvage
- **Image Salvage (`test_image_recovery.py`)**:
  - Truncated JPEG rendering
  - Embedded raster image extraction from corrupted PDFs
  - Random noise image rejection
- **Security Scans (`test_security.py`, `test_file_detection.py`)**:
  - Disguised executables (`.exe`, ELF, Mach-O disguised as `.pdf` or `.docx`)
  - Path traversal attacks (`../`)
  - Prompt injection attack defense
  - Sensitive PII and credential leak detection
- **Serverless & Environment Tests (`test_vercel_storage.py`)**:
  - Dynamic path resolution for `/tmp` storage in read-only environments
  - Graceful handling of OS write permissions and directory creation
- **Batch Processing & System Interfaces (`test_batch_recovery.py`, `test_tool_selection.py`)**:
  - Multi-file batch recovery and ZIP export
  - Pre-analysis tool recommendations
  - Dynamic tool inspection and cache cleanup

---

## Security & Privacy Guarantee

- **Never Publicly Accessible**: Uploaded, corrupted, and recovered files are stored in private directories outside public static routes.
- **Automatic File Cleanup**: Temporary inspection files are deleted automatically or can be flushed with one click.
- **Safe Filenames**: All uploads are sanitized and assigned unique random UUIDs to prevent path traversal and file collisions.
- **Browser Protection**: All responses enforce strict HTTP security headers (`nosniff`, `SAMEORIGIN`, `X-XSS-Protection`).
