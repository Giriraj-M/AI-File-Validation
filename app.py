import os
import json
import logging
from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    redirect,
    url_for,
    flash,
    send_file,
    Response
)
from werkzeug.exceptions import RequestEntityTooLarge
from config import Config
from services.validation_service import ValidationService
from services.history_service import HistoryService
from services.recovery_service import RecoveryService
from services.recovery_history_service import RecoveryHistoryService
from services.file_analysis_service import FileAnalysisService
from services.recovery_decision_service import RecoveryDecisionService
from services.tool_manager import ToolManager
from services.corruption_service import FileCorruptor
from services.corruption_history_service import CorruptionHistoryService
from services.corruption_report_service import CorruptionReportService
from utils.file_utils import (
    ensure_upload_directory,
    generate_safe_filename,
    cleanup_file,
    format_size
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("FileGuard")

# =========================================================
# APPLICATION SETUP
# =========================================================

app = Flask(__name__)
app.config.from_object(Config)

# Ensure private upload, recovery, reports, corrupted, and temporary storage folders exist
for folder_key in [
    "UPLOAD_FOLDER",
    "RECOVERED_FOLDER",
    "REPORTS_FOLDER",
    "TEMP_CORRUPTED_FOLDER",
    "CORRUPTED_FOLDER",
    "CORRUPTION_REPORTS_FOLDER"
]:
    folder_path = app.config.get(folder_key)
    if folder_path:
        ensure_upload_directory(folder_path)


# =========================================================
# SECURITY HEADERS
# =========================================================

@app.after_request
def apply_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


# =========================================================
# ERROR HANDLERS
# =========================================================

@app.errorhandler(413)
@app.errorhandler(RequestEntityTooLarge)
def handle_payload_too_large(e):
    logger.warning("Upload rejected: File size exceeds MAX_CONTENT_LENGTH.")
    msg = f"File is too large. Server maximum upload limit is {Config.MAX_CONTENT_LENGTH_MB} MB."
    if request.is_json or request.path.startswith("/api/"):
        return jsonify({
            "success": False,
            "validation_status": "failed",
            "score": 0,
            "violations": [msg],
            "ai_analysis": msg
        }), 413
    flash(msg, "error")
    return redirect(url_for("index"))

@app.errorhandler(400)
def handle_bad_request(e):
    if request.is_json or request.path.startswith("/api/"):
        return jsonify({"success": False, "error": "Bad request format."}), 400
    flash("Invalid request parameters.", "error")
    return redirect(url_for("index"))

@app.errorhandler(500)
def handle_server_error(e):
    logger.error(f"Internal server error occurred: {str(e)}", exc_info=True)
    if request.is_json or request.path.startswith("/api/"):
        return jsonify({
            "success": False,
            "error": "A server processing error occurred. Details have been logged safely."
        }), 500
    flash("An unexpected error occurred. Please try again.", "error")
    return redirect(url_for("index"))


# =========================================================
# MAIN PAGES
# =========================================================

@app.route("/")
def index():
    """Main AI Assistant Interface."""
    return render_template("index.html")

@app.route("/dashboard")
def dashboard():
    """Validation Analytics & History Dashboard."""
    stats = HistoryService.get_stats()
    recent_records = HistoryService.get_recent_validations(limit=25)
    return render_template("dashboard.html", stats=stats, records=recent_records)

@app.route("/recover")
def recover_page():
    """AI Multi-File Document Recovery Workbench with Security-Dashboard style audit history."""
    stats = RecoveryHistoryService.get_stats()
    recent_records = RecoveryHistoryService.get_recent_recoveries(limit=50)
    system_tools = ToolManager.get_system_tools()
    return render_template("recover.html", stats=stats, records=recent_records, tools=system_tools)

@app.route("/corrupt")
def corrupt_page():
    """Controlled Document Corruption Studio with Forensic Target Selection and Audit Log."""
    stats = CorruptionHistoryService.get_stats()
    recent_records = CorruptionHistoryService.get_recent_corruptions(limit=50)
    return render_template("corrupt.html", stats=stats, records=recent_records)


# =========================================================
# MULTI-FILE RECOVERY ENDPOINTS
# =========================================================

@app.route("/api/recover/batch", methods=["POST"])
def api_recover_batch():
    """
    Recovers multiple uploaded corrupted files simultaneously.
    Accepts multipart form-data:
      - 'files[]' or 'files' or 'file': list of uploaded files
      - 'prompt': optional instructions
    """
    uploaded_files = request.files.getlist("files[]") or request.files.getlist("files") or request.files.getlist("file")
    
    if not uploaded_files or len(uploaded_files) == 0 or (len(uploaded_files) == 1 and uploaded_files[0].filename == ""):
        return jsonify({
            "success": False,
            "error": "No files were selected for recovery."
        }), 400

    import uuid
    import zipfile
    from services.recovery_engine import RecoveryEngine
    from services.recovery_report import RecoveryReportGenerator

    batch_id = f"batch_{uuid.uuid4().hex[:10]}"
    temp_work_dir = os.path.join(app.config["UPLOAD_FOLDER"], "temp_multi_recovery", batch_id)
    ensure_upload_directory(temp_work_dir)

    selected_tools_raw = request.form.get("selected_tools") or "{}"
    try:
        selected_tools_map = json.loads(selected_tools_raw) if selected_tools_raw else {}
    except Exception:
        selected_tools_map = {}
    global_selected_tool = request.form.get("selected_tool") or "auto"

    results = []
    recovered_files_for_zip = []
    total_files = 0
    successful_count = 0
    partial_count = 0
    failed_count = 0
    format_counts = {}
    tool_counts = {}

    for idx, f in enumerate(uploaded_files, start=1):
        if not f.filename:
            continue

        total_files += 1
        file_id = f"file_{idx:03d}"
        clean_name, storage_name = generate_safe_filename(f.filename)
        local_save_path = os.path.join(temp_work_dir, f"{file_id}_{storage_name}")
        f.save(local_save_path)

        # 1. Forensic Binary Analysis
        try:
            analysis = FileAnalysisService.analyze_file(local_save_path, clean_name, file_id)
        except Exception as e:
            logger.error(f"Analysis failed on {clean_name}: {e}")
            analysis = {
                "file_id": file_id,
                "filename": clean_name,
                "detected_type": "UNKNOWN",
                "corruption": {"score": 100},
                "integrity": {"status": "CORRUPTED"},
                "recoverability": "LOW",
                "classification": "CRITICAL"
            }

        detected_fmt = analysis.get("detected_type", "UNKNOWN")
        format_counts[detected_fmt] = format_counts.get(detected_fmt, 0) + 1

        # 2. Recovery Decision Planning
        plan = RecoveryDecisionService.plan_recovery(analysis)
        recommended_tool = plan.get("recommended_tool", "auto")
        fallback_sequence = plan.get("fallback_sequence", [])

        # Determine tool for this file: per-file selection or global or auto
        chosen_tool = (
            selected_tools_map.get(file_id) or
            selected_tools_map.get(clean_name) or
            request.form.get(f"tool_{file_id}") or
            request.form.get(f"tool_{clean_name}") or
            global_selected_tool
        )

        # 3. Execute Recovery
        rec_result = None
        if analysis.get("recoverability") == "UNRECOVERABLE":
            rec_result = {
                "success": False,
                "status": "UNRECOVERABLE",
                "recovery_score": 0,
                "confidence": "HIGH",
                "method": "Rejection (Unrecoverable payload)",
                "summary": "File is empty or contains zero recoverable document structures."
            }
            failed_count += 1
        else:
            try:
                rec_result = RecoveryEngine.recover_file(
                    file_path=local_save_path,
                    original_filename=clean_name,
                    requested_type="auto",
                    selected_tool=chosen_tool
                )
            except Exception as e:
                logger.error(f"Recovery error on {clean_name}: {e}", exc_info=True)
                rec_result = {
                    "success": False,
                    "status": "FAILED",
                    "recovery_score": 0,
                    "confidence": "LOW",
                    "method": "Recovery Execution Error",
                    "summary": str(e)
                }

        # 4. Process Outcome
        status = rec_result.get("status", "FAILED")
        rec_score = rec_result.get("recovery_score", 0)
        rec_method = rec_result.get("recovery_method") or rec_result.get("method") or "Deterministic Engine"
        tool_counts[rec_method] = tool_counts.get(rec_method, 0) + 1

        if status in ["FULLY_RECOVERED", "SUCCESS"]:
            successful_count += 1
        elif status in ["PARTIALLY_RECOVERED", "PARTIAL"]:
            partial_count += 1
        else:
            failed_count += 1

        from services.corruption_classifier import CorruptionClassifier
        is_corrupt = analysis.get("integrity", {}).get("status") == "CORRUPTED" or analysis.get("is_corrupted", False)
        corrupt_area = CorruptionClassifier.get_corruption_area(
            file_path=local_save_path,
            detected_type=detected_fmt,
            analysis=analysis,
            original_filename=clean_name
        )

        # Align AI strategy with detected region
        if "Header" in corrupt_area and "Body" not in corrupt_area:
            ai_strat = "Binary Header Magic Byte Realignment"
        elif "Body" in corrupt_area and "Reference" not in corrupt_area:
            ai_strat = "Deep Content Stream & Page Object Reconstruction"
        elif "Images" in corrupt_area and "Body" not in corrupt_area:
            ai_strat = "Embedded Media Stream & Raster Graphic Salvage"
        elif "EOF" in corrupt_area and "Body" not in corrupt_area:
            ai_strat = "EOF Terminal Stabilization & Trailer Injection"
        elif "Reference" in corrupt_area:
            ai_strat = "Structural Cross-Reference Table Reconstruction"
        else:
            ai_strat = rec_result.get("report", {}).get("ai_strategy") or RecoveryReportGenerator._determine_ai_strategy(detected_fmt, analysis, rec_result)

        # Save individual record in recovery history
        rec_id = None
        try:
            rec_id = RecoveryHistoryService.record_recovery({
                "file_id": file_id,
                "filename": rec_result.get("filename") or clean_name,
                "original_type": detected_fmt,
                "recovered_type": rec_result.get("recovered_type") or detected_fmt,
                "original_size_human": format_size(os.path.getsize(local_save_path)),
                "recovered_size_human": format_size(os.path.getsize(rec_result["output_path"])) if rec_result.get("output_path") and os.path.exists(rec_result["output_path"]) else "0 B",
                "original_size_bytes": os.path.getsize(local_save_path),
                "recovered_size_bytes": os.path.getsize(rec_result["output_path"]) if rec_result.get("output_path") and os.path.exists(rec_result["output_path"]) else 0,
                "status": status,
                "confidence": rec_result.get("confidence", "HIGH"),
                "confidence_score": rec_score,
                "integrity_before": "Corrupted" if is_corrupt else "Intact",
                "integrity_after": "Intact" if rec_result.get("success") else "Corrupted",
                "corruption_area": corrupt_area,
                "recovery_method": rec_method,
                "storage_filename": rec_result.get("storage_filename", ""),
                "preview_snippet": rec_result.get("preview_snippet", ""),
                "summary": rec_result.get("summary", ""),
                "report": rec_result.get("report", {})
            })
        except Exception as e:
            logger.warning(f"Failed to record history for {clean_name}: {e}")

        # Collect for ZIP package if file exists
        if rec_result.get("output_path") and os.path.exists(rec_result["output_path"]):
            recovered_files_for_zip.append({
                "source_path": rec_result["output_path"],
                "archive_name": rec_result.get("filename") or f"{clean_name}_recovered"
            })

        summary_text = rec_result.get("summary") or f"The corrupted {detected_fmt} structure was reconstructed and recoverable data streams restored."

        file_entry = {
            "file_id": file_id,
            "recovery_id": rec_id,
            "filename": clean_name,
            "original_filename": clean_name,
            "recovered_filename": rec_result.get("filename") or clean_name,
            "detected_type": detected_fmt,
            "original_size": format_size(os.path.getsize(local_save_path)),
            "recovered_size": format_size(os.path.getsize(rec_result["output_path"])) if rec_result.get("output_path") and os.path.exists(rec_result["output_path"]) else "0 B",
            "integrity_status": analysis.get("integrity", {}).get("status", "CORRUPTED"),
            "corruption_detected": "Yes" if is_corrupt else "No",
            "corruption_area": corrupt_area,
            "corruption": analysis.get("corruption", {}),
            "recoverability": analysis.get("recoverability", "MEDIUM"),
            "classification": analysis.get("classification", "MODERATE"),
            "ai_strategy": ai_strat,
            "recovery_summary": summary_text,
            "strategy_tools": analysis.get("strategy_tools") or analysis.get("recommended_strategies") or [],
            "recommended_strategies": analysis.get("strategy_tools") or analysis.get("recommended_strategies") or [],
            "history_timeline": rec_result.get("report", {}).get("history_timeline", []),
            "preview_data": rec_result.get("report", {}).get("preview_data", {}),
            "ai_recommendation": {
                "tool": recommended_tool,
                "reason": plan.get("reason", ""),
                "fallbacks": fallback_sequence
            },
            "executed_tool": rec_method,
            "status": status,
            "recovery_score": rec_score,
            "preview_snippet": rec_result.get("preview_snippet", ""),
            "download_url": f"/api/recovery/{rec_id}/download" if rec_id else None,
            "view_url": f"/api/recovery/{rec_id}/view" if rec_id else None,
            "report_url": f"/api/recovery/{rec_id}/report.html" if rec_id else None
        }
        results.append(file_entry)

    # Clean up temp work dir
    import shutil
    try:
        shutil.rmtree(temp_work_dir, ignore_errors=True)
    except Exception:
        pass

    # Build ZIP archive if files exist
    zip_filename = f"{batch_id}_recovered_files.zip"
    zip_path = os.path.join(app.config["RECOVERED_FOLDER"], zip_filename)
    if recovered_files_for_zip:
        try:
            with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
                for item in recovered_files_for_zip:
                    if os.path.exists(item["source_path"]):
                        zf.write(item["source_path"], arcname=item["archive_name"])
        except Exception as e:
            logger.error(f"Failed to generate recovery zip: {e}")

    # Generate summary report HTML
    batch_summary_html = RecoveryReportGenerator.generate_batch_html_report(results, {
        "total": total_files,
        "successful": successful_count,
        "partial": partial_count,
        "failed": failed_count,
        "formats": format_counts,
        "tools": tool_counts
    }) if hasattr(RecoveryReportGenerator, "generate_batch_html_report") else ""

    if batch_summary_html:
        summary_html_path = os.path.join(app.config["REPORTS_FOLDER"], f"report_{batch_id}.html")
        try:
            with open(summary_html_path, "w", encoding="utf-8") as f:
                f.write(batch_summary_html)
        except Exception as e:
            logger.warning(f"Could not save batch summary report: {e}")

    return jsonify({
        "success": True,
        "batch_id": batch_id,
        "total_files": total_files,
        "successful_count": successful_count,
        "partial_count": partial_count,
        "failed_count": failed_count,
        "formats_breakdown": format_counts,
        "tools_breakdown": tool_counts,
        "results": results,
        "report_urls": {
            "html_report": f"/api/batch/{batch_id}/report.html",
            "json_report": f"/api/batch/{batch_id}/report?format=json",
            "zip_download": f"/api/batch/{batch_id}/download" if os.path.exists(zip_path) else None
        }
    }), 200

@app.route("/api/analyze/batch", methods=["POST"])
def api_analyze_batch():
    """
    Forensically analyzes multiple uploaded files without performing recovery yet.
    Returns corruption cards, confidence levels, and tool recommendations for each file.
    """
    uploaded_files = request.files.getlist("files[]") or request.files.getlist("files") or request.files.getlist("file")
    
    if not uploaded_files or len(uploaded_files) == 0 or (len(uploaded_files) == 1 and uploaded_files[0].filename == ""):
        return jsonify({
            "success": False,
            "error": "No files provided for batch analysis."
        }), 400

    from services.corruption_classifier import CorruptionClassifier
    from services.tool_recommender import ToolRecommender
    from services.tool_registry import ToolRegistry

    results = []
    temp_dir = os.path.join(app.config["TEMP_CORRUPTED_FOLDER"], "batch_analysis")
    ensure_upload_directory(temp_dir)

    for idx, f in enumerate(uploaded_files, start=1):
        if not f.filename:
            continue
        fid = f"file_{idx:03d}"
        clean_name, storage_name = generate_safe_filename(f.filename)
        save_path = os.path.join(temp_dir, f"{fid}_{storage_name}")
        f.save(save_path)

        try:
            analysis = FileAnalysisService.analyze_file(save_path, clean_name, fid)
            plan = RecoveryDecisionService.plan_recovery(analysis)
            analysis["ai_plan"] = plan

            # Granular corruption classification and recommendations
            classification = CorruptionClassifier.classify(save_path, analysis.get("detected_type"))
            recommendation = ToolRecommender.recommend(save_path)
            analysis["corruption_classification"] = classification
            analysis["tool_recommendation"] = recommendation
            
            # Format-matched candidate tools for manual selection
            fmt = analysis.get("detected_type", "").upper()
            all_tools = ToolRegistry.get_all_tools()
            matched_tools = [
                t for t in all_tools
                if any(f.upper() == fmt or f.upper() in fmt for f in t.get("supported_formats", []))
            ]
            analysis["available_candidate_tools"] = matched_tools

            results.append(analysis)
        except Exception as e:
            results.append({
                "file_id": fid,
                "filename": clean_name,
                "error": str(e)
            })

    return jsonify({"success": True, "files": results}), 200

@app.route("/api/tools", methods=["GET"])
def api_system_tools():
    """Returns registered forensic recovery tools and dependency readiness."""
    from services.tool_registry import ToolRegistry
    from services.tool_manager import ToolManager
    return jsonify({
        "success": True,
        "tools": ToolRegistry.get_all_tools(),
        "dependency_report": ToolManager.get_dependency_report()
    }), 200

@app.route("/api/clean-temp", methods=["POST"])
def api_clean_temp_sessions():
    """Safely purges temporary analysis and staged upload directories."""
    import shutil
    try:
        temp_multi = os.path.join(app.config["UPLOAD_FOLDER"], "temp_multi_recovery")
        temp_batch = os.path.join(app.config["TEMP_CORRUPTED_FOLDER"], "batch_analysis")
        if os.path.exists(temp_multi):
            shutil.rmtree(temp_multi, ignore_errors=True)
        if os.path.exists(temp_batch):
            shutil.rmtree(temp_batch, ignore_errors=True)
        return jsonify({"success": True, "message": "Temporary sessions safely cleared."}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/batch/<batch_id>", methods=["GET"])
def api_batch_status(batch_id):
    """Returns stored batch analysis status and JSON metrics."""
    batch_json_path = os.path.join(app.config["REPORTS_FOLDER"], f"report_{batch_id}.json")
    if not os.path.exists(batch_json_path):
        # Legacy subfolder check
        batch_json_path = os.path.join(app.config["REPORTS_FOLDER"], batch_id, "batch_report.json")
    if not os.path.exists(batch_json_path):
        return jsonify({"success": False, "error": "Batch record not found."}), 404

    try:
        with open(batch_json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return jsonify(data), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/batch/<batch_id>/report", methods=["GET"])
@app.route("/api/batch/<batch_id>/report.html", methods=["GET"])
def api_batch_report(batch_id):
    """Renders HTML batch report or serves JSON format."""
    rep_fmt = request.args.get("format", "html").lower()
    
    if rep_fmt == "json":
        json_path = os.path.join(app.config["REPORTS_FOLDER"], f"report_{batch_id}.json")
        if not os.path.exists(json_path):
            json_path = os.path.join(app.config["REPORTS_FOLDER"], batch_id, "batch_report.json")
        if not os.path.exists(json_path):
            return jsonify({"success": False, "error": "Report not found."}), 404
        return send_file(json_path, mimetype="application/json")

    html_path = os.path.join(app.config["REPORTS_FOLDER"], f"report_{batch_id}.html")
    if not os.path.exists(html_path):
        html_path = os.path.join(app.config["REPORTS_FOLDER"], batch_id, "batch_report.html")
    if not os.path.exists(html_path):
        return "Recovery summary report not found.", 404
    
    with open(html_path, "r", encoding="utf-8") as f:
        content = f.read()

    if request.args.get("download") == "1":
        return Response(
            content,
            mimetype="text/html",
            headers={"Content-Disposition": f'attachment; filename="recovery_summary_report_{batch_id}.html"'}
        )
    return content, 200, {"Content-Type": "text/html; charset=utf-8"}

@app.route("/api/batch/<batch_id>/download", methods=["GET"])
def api_batch_download_zip(batch_id):
    """Downloads all recovered files in the batch bundled in a single ZIP archive."""
    zip_path = os.path.join(app.config["RECOVERED_FOLDER"], f"{batch_id}_recovered_files.zip")
    if not os.path.exists(zip_path):
        # Legacy subfolder check
        zip_path = os.path.join(app.config["RECOVERED_FOLDER"], batch_id, f"{batch_id}_recovered_files.zip")
    if not os.path.exists(zip_path):
        flash("Recovered bundle archive was not found or has expired.", "error")
        return redirect(url_for("recover_page"))

    return send_file(
        zip_path,
        as_attachment=True,
        download_name=f"Recovered_Files_Bundle_{batch_id}.zip"
    )

@app.route("/api/tools/status", methods=["GET"])
def api_tools_status():
    """Returns detected external tools and Python recovery libraries."""
    tools = ToolManager.get_system_tools(force_refresh=True)
    return jsonify({"success": True, "tools": tools})

@app.route("/api/recovery/<rec_id>/tool-log", methods=["GET"])
def api_recovery_tool_log(rec_id):
    """Returns tool fallback timeline and execution attempt history."""
    record = RecoveryHistoryService.get_recovery_by_id(rec_id)
    if not record:
        return jsonify({"success": False, "error": "Record not found."}), 404

    rep = record.get("report") or {}
    return jsonify({
        "success": True,
        "filename": record.get("filename"),
        "recovery_method": record.get("recovery_method"),
        "applied_tools": rep.get("applied_tools", []),
        "fallback_timeline": rep.get("fallback_timeline", []),
        "confidence_score": record.get("confidence_score", 90)
    })


# =========================================================
# SINGLE-FILE RECOVERY ENDPOINTS (Preserved & Enhanced)
# =========================================================

@app.route("/api/recover", methods=["POST"])
def api_recover():
    """
    Recovers a corrupted or broken file using AI & deterministic stream reconstruction.
    Accepts:
      - 'file': uploaded corrupted file (optional if cache_id is provided)
      - 'cache_id': ID of temporary cached corrupted file from recent validation (optional)
      - 'file_type': target format ('auto', 'pdf', 'word', 'excel', 'pptx', 'csv', 'text', 'image')
      - 'original_file': optional reference original file for 1:1 fidelity comparison
    """
    file_type = request.form.get("file_type", "auto").strip().lower()
    cache_id = request.form.get("cache_id", "").strip()
    uploaded_file = request.files.get("file")
    original_ref_file = request.files.get("original_file")

    corrupted_path = None
    original_filename = "document"
    ref_path = None

    try:
        # Check if using cached corrupted file from assistant validation
        if cache_id and os.path.exists(app.config["TEMP_CORRUPTED_FOLDER"]):
            for fname in os.listdir(app.config["TEMP_CORRUPTED_FOLDER"]):
                if fname.startswith(f"{cache_id}_"):
                    corrupted_path = os.path.join(app.config["TEMP_CORRUPTED_FOLDER"], fname)
                    original_filename = fname[len(cache_id) + 1:]
                    break

        if not corrupted_path or not os.path.exists(corrupted_path):
            if not uploaded_file or uploaded_file.filename == "":
                return jsonify({
                    "success": False,
                    "error": "No corrupted file was provided for recovery."
                }), 400

            original_filename = uploaded_file.filename
            clean_name, storage_name = generate_safe_filename(original_filename)
            corrupted_path = os.path.join(app.config["UPLOAD_FOLDER"], f"corrupt_{storage_name}")
            uploaded_file.save(corrupted_path)

        # Handle optional original reference file
        if original_ref_file and original_ref_file.filename != "":
            _, ref_storage = generate_safe_filename(original_ref_file.filename)
            ref_path = os.path.join(app.config["UPLOAD_FOLDER"], f"ref_{ref_storage}")
            original_ref_file.save(ref_path)

        # Run Recovery Engine
        recovery_result = RecoveryService.recover_file(
            corrupted_path=corrupted_path,
            original_filename=original_filename,
            requested_type=file_type,
            original_ref_path=ref_path
        )

        # Record in audit log
        rec_id = RecoveryHistoryService.record_recovery({
            "filename": recovery_result["filename"],
            "original_type": recovery_result["original_type"],
            "recovered_type": recovery_result["recovered_type"],
            "original_size_human": recovery_result["original_size_human"],
            "recovered_size_human": recovery_result["recovered_size_human"],
            "original_size_bytes": recovery_result["original_size_bytes"],
            "recovered_size_bytes": recovery_result["recovered_size_bytes"],
            "status": recovery_result.get("status", "recovered"),
            "confidence": recovery_result.get("confidence", "high"),
            "confidence_score": recovery_result.get("confidence_score", 90),
            "integrity_before": recovery_result["integrity_before"],
            "integrity_after": recovery_result["integrity_after"],
            "recovery_method": recovery_result["recovery_method"],
            "storage_filename": recovery_result["storage_filename"],
            "preview_snippet": recovery_result["preview_snippet"],
            "summary": recovery_result["summary"],
            "report": recovery_result.get("report", {})
        })

        # Add URLs to result payload
        recovery_result["recovery_id"] = rec_id
        recovery_result["download_url"] = f"/api/recovery/{rec_id}/download"
        recovery_result["view_url"] = f"/api/recovery/{rec_id}/view"
        recovery_result["details_url"] = f"/api/recovery/{rec_id}"
        recovery_result["validate_url"] = f"/api/recover/validate/{rec_id}"
        recovery_result["report_json_url"] = f"/api/recovery/{rec_id}/report.json"
        recovery_result["report_html_url"] = f"/api/recovery/{rec_id}/report.html"

        return jsonify(recovery_result), 200

    except Exception as e:
        logger.error(f"Recovery failure: {str(e)}", exc_info=True)
        return jsonify({
            "success": False,
            "error": f"Recovery processing failed: {str(e)}"
        }), 500

    finally:
        if ref_path:
            cleanup_file(ref_path)

@app.route("/api/recovery/<path:rec_id>/report.json", methods=["GET"])
@app.route("/api/recover/report/<path:rec_id>.json", methods=["GET"])
def api_recover_report_json(rec_id):
    """Returns the structured JSON recovery report."""
    rec_id = str(rec_id).strip("/")
    record = RecoveryHistoryService.get_recovery_by_id(rec_id)
    if not record:
        return jsonify({"success": False, "error": "Recovery record not found."}), 404
    rep = record.get("report") or {}
    return jsonify(rep), 200, {"Content-Disposition": f'attachment; filename="recovery_report_{record.get("filename", "doc")}.json"'}

@app.route("/api/recovery/<path:rec_id>/report.html", methods=["GET"])
@app.route("/api/recovery/<path:rec_id>/report", methods=["GET"])
@app.route("/api/recover/report/<path:rec_id>", methods=["GET"])
def api_recover_report_html(rec_id):
    """Renders or downloads the standalone HTML recovery audit report."""
    rec_id = str(rec_id).strip("/")
    # Handle if 'report.html' was passed in path
    if rec_id.endswith("/report.html") or rec_id.endswith("/report"):
        rec_id = rec_id.split("/")[0]

    record = RecoveryHistoryService.get_recovery_by_id(rec_id)
    if not record:
        return "Recovery record not found. Please verify the recovery history or submit the file for recovery.", 404
    rep = record.get("report") or {}
    from services.recovery_report import RecoveryReportGenerator
    if rep and isinstance(rep, dict) and "recovery" in rep:
        html_content = RecoveryReportGenerator.generate_html_report(rep)
    else:
        structured = rep if rep and "recovery" in rep else {
            "file": record.get("filename", "Document"),
            "file_type": record.get("recovered_type", "Document"),
            "original_size": record.get("original_size_human", "0 B"),
            "corruption_status": record.get("integrity_before", "Corrupted"),
            "status": record.get("status", "SUCCESS"),
            "confidence_score": record.get("confidence_score", 90),
            "confidence": f"{record.get('confidence_score', 90)}%",
            "recovery": {
                "success": record.get("status") in ["FULLY_RECOVERED", "SUCCESS", "recovered", "PARTIALLY_RECOVERED", "PARTIAL"],
                "status": record.get("status", "SUCCESS"),
                "confidence_score": record.get("confidence_score", 90),
                "confidence": f"{record.get('confidence_score', 90)}%",
                "method": record.get("recovery_method", "Multi-Strategy Recovery Engine"),
                "pages_detected": 1,
                "pages_recovered": 1,
                "text_recovered": True,
                "output_filename": record.get("filename", "recovered_document")
            },
            "validation": {
                "validation_status": "PASSED" if record.get("status") in ["FULLY_RECOVERED", "SUCCESS", "recovered"] else "PARTIAL",
                "recovery_score": record.get("confidence_score", 90),
                "extracted_preview": record.get("preview_snippet", "")
            }
        }
        html_content = RecoveryReportGenerator.generate_html_report(structured)
    
    if request.args.get("download") == "1":
        return Response(
            html_content,
            mimetype="text/html",
            headers={"Content-Disposition": f'attachment; filename="recovery_report_{record.get("filename", "doc")}.html"'}
        )
    return html_content, 200, {"Content-Type": "text/html; charset=utf-8"}

@app.route("/api/recovery/<rec_id>/download", methods=["GET"])
@app.route("/api/recover/download/<rec_id>", methods=["GET"])
def api_recover_download(rec_id):
    """Downloads the recovered file."""
    record = RecoveryHistoryService.get_recovery_by_id(rec_id)
    if not record or not record.get("storage_filename"):
        flash("Recovered file not found.", "error")
        return redirect(url_for("recover_page"))

    file_path = os.path.join(app.config["RECOVERED_FOLDER"], record["storage_filename"])
    if not os.path.exists(file_path):
        flash("Physical recovered file was removed or expired.", "error")
        return redirect(url_for("recover_page"))

    return send_file(
        file_path,
        as_attachment=True,
        download_name=record.get("filename", "recovered_file")
    )

@app.route("/api/recovery/<rec_id>/view", methods=["GET"])
@app.route("/api/recover/view/<rec_id>", methods=["GET"])
def api_recover_view(rec_id):
    """Views the recovered file (raw inline stream or structured JSON content)."""
    record = RecoveryHistoryService.get_recovery_by_id(rec_id)
    if not record or not record.get("storage_filename"):
        return jsonify({"success": False, "error": "Record not found."}), 404

    file_path = os.path.join(app.config["RECOVERED_FOLDER"], record["storage_filename"])
    if not os.path.exists(file_path):
        return jsonify({"success": False, "error": "File not found on server."}), 404

    if request.args.get("raw") == "1":
        return send_file(file_path, as_attachment=False)

    from services.document_service import DocumentService
    category = record.get("recovered_type", "TEXT").lower()
    cat_map = {"word": "word", "excel": "excel", "pdf": "pdf", "csv": "csv", "text": "text"}
    norm_cat = cat_map.get(category, "text")
    doc_data = DocumentService.extract_text(file_path, norm_cat)

    return jsonify({
        "success": True,
        "record": record,
        "content": doc_data.get("text") or record.get("preview_snippet", ""),
        "char_count": doc_data.get("char_count", 0),
        "word_count": doc_data.get("word_count", 0),
        "pages": doc_data.get("pages", 1),
        "raw_url": f"/api/recovery/{rec_id}/view?raw=1"
    })

@app.route("/api/recovery/<rec_id>", methods=["GET"])
@app.route("/api/recover/details/<rec_id>", methods=["GET"])
def api_recover_details(rec_id):
    """Returns metadata and log details for a recovery entry."""
    record = RecoveryHistoryService.get_recovery_by_id(rec_id)
    if not record:
        return jsonify({"success": False, "error": "Recovery log not found."}), 404
    return jsonify({"success": True, "record": record})

@app.route("/api/clear", methods=["DELETE", "POST"])
def api_clear():
    """
    Clears uploaded, recovered, and temporary files associated with the current session.
    """
    try:
        cleaned_count = 0
        temp_dir = app.config.get("TEMP_CORRUPTED_FOLDER")
        if temp_dir and os.path.exists(temp_dir):
            for f in os.listdir(temp_dir):
                fp = os.path.join(temp_dir, f)
                try:
                    if os.path.isfile(fp):
                        os.remove(fp)
                        cleaned_count += 1
                except Exception:
                    pass

        rec_id = request.args.get("recovery_id")
        if rec_id:
            RecoveryHistoryService.delete_recovery(rec_id)

        return jsonify({
            "success": True,
            "message": f"Session cleared ({cleaned_count} temporary files purged)."
        }), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/recover/delete/<rec_id>", methods=["DELETE", "POST"])
@app.route("/api/recovery/<rec_id>/delete", methods=["DELETE", "POST"])
@app.route("/api/recovery/<rec_id>", methods=["DELETE"])
def api_recover_delete(rec_id):
    """Deletes a single recovery entry and its physical file."""
    success = RecoveryHistoryService.delete_recovery(rec_id)
    if success:
        return jsonify({"success": True, "message": "Recovery record deleted successfully."}), 200
    return jsonify({"success": False, "error": "Recovery record not found."}), 404

@app.route("/api/recover/clear-all", methods=["POST"])
@app.route("/api/clear-recovery-history", methods=["POST"])
def api_recover_clear_all():
    """Clears all recovery audit logs and files."""
    count = RecoveryHistoryService.clear_all()
    return jsonify({"success": True, "message": f"Cleared {count} recovery records and files."}), 200

@app.route("/api/recover/validate/<rec_id>", methods=["POST"])
def api_recover_validate(rec_id):
    """Validates the recovered file directly through the validation engine."""
    record = RecoveryHistoryService.get_recovery_by_id(rec_id)
    if not record or not record.get("storage_filename"):
        return jsonify({"success": False, "error": "Recovery record not found."}), 404

    src_path = os.path.join(app.config["RECOVERED_FOLDER"], record["storage_filename"])
    if not os.path.exists(src_path):
        return jsonify({"success": False, "error": "Recovered file not found on disk."}), 404

    import shutil
    clean_name, temp_storage = generate_safe_filename(record["filename"])
    temp_path = os.path.join(app.config["UPLOAD_FOLDER"], f"val_{temp_storage}")
    shutil.copy2(src_path, temp_path)

    prompt = request.form.get("prompt", f"Validate recovered {record.get('recovered_type', 'document')}")

    try:
        val_result = ValidationService.validate_upload(
            file_path=temp_path,
            original_filename=record["filename"],
            prompt=prompt
        )
        return jsonify(val_result), 200
    except Exception as e:
        cleanup_file(temp_path)
        return jsonify({"success": False, "error": str(e)}), 500


# =========================================================
# VALIDATION ENDPOINT
# =========================================================

@app.route("/api/validate", methods=["POST"])
def api_validate():
    """
    Primary validation endpoint.
    Accepts multipart form-data:
      - 'prompt': Natural language requirements (string)
      - 'file': Attached file upload
    """
    prompt = request.form.get("prompt", "").strip()
    uploaded_file = request.files.get("file")

    if not uploaded_file or uploaded_file.filename == "":
        return jsonify({
            "success": False,
            "validation_status": "failed",
            "score": 0,
            "violations": ["No file was attached to the validation request."],
            "ai_analysis": "Please attach a file along with your validation prompt."
        }), 400

    original_name = uploaded_file.filename
    clean_name, storage_name = generate_safe_filename(original_name)
    save_path = os.path.join(app.config["UPLOAD_FOLDER"], storage_name)

    try:
        uploaded_file.save(save_path)
        client_mime = uploaded_file.content_type or ""

        is_pure_analysis = not prompt or prompt.lower() in ["analyze", "validate", "check", "inspect"]

        from services.recovery_engine import RecoveryEngine
        from services.ai_service import AIService
        import uuid
        import shutil

        cache_id = uuid.uuid4().hex[:12]
        temp_cache_path = os.path.join(app.config["TEMP_CORRUPTED_FOLDER"], f"{cache_id}_{clean_name}")
        shutil.copy2(save_path, temp_cache_path)

        analysis = RecoveryEngine.analyze_file(save_path, clean_name)

        if is_pure_analysis:
            return jsonify({
                "success": True,
                "file_type": analysis.get("detected_type", "UNKNOWN"),
                "is_corrupted": analysis.get("integrity", {}).get("status") == "CORRUPTED",
                "corruption_regions": analysis.get("corruption_regions", []),
                "classification": analysis.get("classification", "MODERATE"),
                "can_recover": analysis.get("recoverability") != "UNRECOVERABLE",
                "file_size_bytes": os.path.getsize(save_path),
                "file_size_human": format_size(os.path.getsize(save_path)),
                "ai_explanation": AIService.explain_corruption(analysis.get("detected_type", "DOC"), analysis.get("corruption_regions", [])),
                "ai_strategy": AIService.suggest_strategy(analysis.get("detected_type", "DOC"), analysis.get("corruption_regions", [])),
                "summary": analysis.get("summary", ""),
                "cache_id": cache_id
            }), 200

        result = ValidationService.validate_upload(
            file_path=save_path,
            original_filename=clean_name,
            prompt=prompt,
            client_mime=client_mime
        )
        result["corruption_analysis"] = analysis
        result["cache_id"] = cache_id

        return jsonify(result), 200

    except Exception as e:
        logger.error(f"Validation failure on {clean_name}: {str(e)}", exc_info=True)
        cleanup_file(save_path)
        return jsonify({
            "success": False,
            "validation_status": "failed",
            "score": 0,
            "violations": [f"Processing error during validation: {str(e)}"],
            "ai_analysis": "The validation engine encountered an error while inspecting this file."
        }), 500

@app.route("/api/history", methods=["GET"])
def api_history():
    """Returns recent validation runs in JSON format."""
    limit = request.args.get("limit", 20, type=int)
    records = HistoryService.get_recent_validations(limit=limit)
    return jsonify({"success": True, "history": records})

@app.route("/api/stats", methods=["GET"])
def api_stats():
    """Returns system validation metrics and statistics."""
    stats = HistoryService.get_stats()
    return jsonify({"success": True, "stats": stats})

@app.route("/api/clear-history", methods=["POST"])
def api_clear_history():
    """Clears the validation audit history."""
    HistoryService.clear_history()
    return jsonify({"success": True, "message": "Validation history successfully cleared."})

@app.route("/api/history/<record_id>", methods=["DELETE"])
@app.route("/api/history/<record_id>/delete", methods=["POST", "DELETE"])
def api_delete_history_record(record_id):
    """Deletes a single validation record by ID or timestamp."""
    deleted = HistoryService.delete_record(record_id)
    if deleted:
        return jsonify({"success": True, "message": "Validation record deleted successfully."})
    return jsonify({"success": False, "error": "Validation record not found."}), 404


# =========================================================
# SURGICAL FILE CORRUPTION ENDPOINTS
# =========================================================

@app.route("/api/corrupt", methods=["POST"])
@app.route("/api/corrupt/upload", methods=["POST"])
def api_corrupt_file():
    """
    Surgically corrupts an uploaded file targeting selected structural regions:
    - header, body, reference, end_of_file, images, or all.
    """
    uploaded_file = request.files.get("file") or request.files.get("files[]")
    if not uploaded_file or uploaded_file.filename == "":
        return jsonify({"success": False, "error": "No file uploaded for corruption."}), 400

    # Parse targets
    targets = request.form.getlist("targets[]") or request.form.getlist("targets")
    if not targets:
        raw_targets = request.form.get("targets", "")
        if raw_targets:
            try:
                targets = json.loads(raw_targets)
            except Exception:
                targets = [t.strip() for t in raw_targets.split(",") if t.strip()]

    if not targets:
        for t_name in ["header", "body", "reference", "end_of_file", "eof", "images", "all"]:
            if request.form.get(t_name) in ["true", "1", "on", "yes", t_name]:
                targets.append(t_name)

    if not targets:
        targets = ["all"]

    original_name = uploaded_file.filename
    clean_name, storage_name = generate_safe_filename(original_name)
    temp_input_path = os.path.join(app.config["TEMP_CORRUPTED_FOLDER"], f"raw_{storage_name}")
    uploaded_file.save(temp_input_path)

    try:
        corr_clean_name = f"corrupted_{storage_name}"
        output_path = os.path.join(app.config["CORRUPTED_FOLDER"], corr_clean_name)

        result = FileCorruptor.corrupt_file(
            input_path=temp_input_path,
            output_path=output_path,
            selected_targets=targets,
            original_filename=original_name
        )

        result["storage_filename"] = corr_clean_name
        corr_id = CorruptionHistoryService.record_corruption(result)
        result["id"] = corr_id
        result["download_url"] = f"/api/corrupt/download/{corr_id}"
        result["report_url"] = f"/api/corrupt/report/{corr_id}"

        cleanup_file(temp_input_path)
        return jsonify({"success": True, "data": result}), 200

    except Exception as e:
        logger.error(f"Error corrupting file {clean_name}: {str(e)}", exc_info=True)
        cleanup_file(temp_input_path)
        return jsonify({"success": False, "error": f"Corruption failed: {str(e)}"}), 500

@app.route("/api/corrupt/download/<corr_id>", methods=["GET"])
def api_corrupt_download(corr_id):
    """Downloads the surgically corrupted file."""
    record = CorruptionHistoryService.get_corruption_by_id(corr_id)
    if not record or not record.get("storage_filename"):
        flash("Corrupted file record not found.", "error")
        return redirect(url_for("corrupt_page"))

    file_path = os.path.join(app.config["CORRUPTED_FOLDER"], record["storage_filename"])
    if not os.path.exists(file_path):
        flash("Physical corrupted file was removed or expired.", "error")
        return redirect(url_for("corrupt_page"))

    dl_name = record.get("corrupted_filename") or f"corrupted_{record.get('original_filename', 'file')}"

    return send_file(
        file_path,
        as_attachment=True,
        download_name=dl_name
    )

@app.route("/api/corrupt/report/<corr_id>", methods=["GET"])
def api_corrupt_report(corr_id):
    """Renders or downloads the standalone HTML corruption audit report."""
    record = CorruptionHistoryService.get_corruption_by_id(corr_id)
    if not record:
        return "Corruption record not found.", 404

    html_content = CorruptionReportService.generate_html_report(record)
    if request.args.get("download") == "1":
        return Response(
            html_content,
            mimetype="text/html",
            headers={"Content-Disposition": f'attachment; filename="corruption_report_{record.get("original_filename", "doc")}.html"'}
        )
    return html_content, 200, {"Content-Type": "text/html; charset=utf-8"}

@app.route("/api/corrupt/report/<corr_id>/json", methods=["GET"])
def api_corrupt_report_json(corr_id):
    """Returns structured JSON report for the corruption event."""
    record = CorruptionHistoryService.get_corruption_by_id(corr_id)
    if not record:
        return jsonify({"success": False, "error": "Corruption record not found."}), 404
    return jsonify({"success": True, "record": record})

@app.route("/api/corrupt/delete/<corr_id>", methods=["DELETE", "POST"])
@app.route("/api/corrupt/<corr_id>", methods=["DELETE"])
def api_corrupt_delete(corr_id):
    """Deletes an individual corruption audit log entry and its file."""
    success = CorruptionHistoryService.delete_corruption(corr_id)
    if success:
        return jsonify({"success": True, "message": "Corruption log entry deleted successfully."}), 200
    return jsonify({"success": False, "error": "Record not found."}), 404

@app.route("/api/corrupt/clear-all", methods=["POST"])
def api_corrupt_clear_all():
    """Clears all corruption audit logs and deletes all corrupted files."""
    count = CorruptionHistoryService.clear_all()
    return jsonify({"success": True, "message": f"Cleared all {count} corruption records and files."}), 200

@app.route("/api/corrupt/stats", methods=["GET"])
def api_corrupt_stats():
    """Returns aggregated corruption statistics."""
    stats = CorruptionHistoryService.get_stats()
    return jsonify({"success": True, "stats": stats})

@app.route("/api/corrupt/history", methods=["GET"])
def api_corrupt_history():
    """Returns recent corruption records."""
    limit = request.args.get("limit", 50, type=int)
    records = CorruptionHistoryService.get_recent_corruptions(limit=limit)
    return jsonify({"success": True, "history": records})



# =========================================================
# LEGACY WIZARD ROUTE REDIRECTS
# =========================================================

@app.route("/type-validation", methods=["GET", "POST"])
@app.route("/size-validation", methods=["GET", "POST"])
@app.route("/upload", methods=["GET", "POST"])
def legacy_redirects():
    flash("The 4-step wizard has been upgraded to FileGuard AI Assistant.", "info")
    return redirect(url_for("index"))


# =========================================================
# SERVER ENTRY POINT
# =========================================================

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )