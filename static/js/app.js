/**
 * FileGuard AI - Frontend Controller
 * Handles drag-and-drop file attachment, real-time client metadata,
 * asynchronous validation requests, animated progress steps, and dynamic result rendering.
 */

document.addEventListener("DOMContentLoaded", () => {
    // Elements
    const validationForm = document.getElementById("validationForm");
    const promptInput = document.getElementById("promptInput");
    const fileInput = document.getElementById("fileInput");
    const dropZone = document.getElementById("dropZone");
    const dropZonePrompt = document.getElementById("dropZonePrompt");
    const attachedCard = document.getElementById("attachedCard");
    const attachedName = document.getElementById("attachedName");
    const attachedSize = document.getElementById("attachedSize");
    const attachedExt = document.getElementById("attachedExt");
    const attachedIcon = document.getElementById("attachedIcon");
    const removeFileBtn = document.getElementById("removeFileBtn");
    const submitBtn = document.getElementById("submitBtn");
    const resetBtn = document.getElementById("resetBtn");
    const clientError = document.getElementById("clientError");
    const processingCard = document.getElementById("processingCard");
    const resultContainer = document.getElementById("resultContainer");

    // Only run on pages with the validation form
    if (!validationForm) return;

    // Detect browser reload (refresh / F5) vs page navigation (e.g. returning from Dashboard)
    function isPageReload() {
        try {
            const navEntries = performance.getEntriesByType("navigation");
            if (navEntries && navEntries.length > 0) {
                return navEntries[0].type === "reload";
            }
            if (window.performance && window.performance.navigation) {
                return window.performance.navigation.type === 1;
            }
        } catch (e) {}
        return false;
    }

    // If freshly reloaded or opened, ensure validate page is empty.
    // If navigated back from dashboard, restore the recent validation result.
    if (isPageReload()) {
        sessionStorage.removeItem("fileguard_last_result");
    } else {
        const savedResult = sessionStorage.getItem("fileguard_last_result");
        if (savedResult) {
            try {
                const data = JSON.parse(savedResult);
                renderValidationResult(data, false);
            } catch (e) {
                sessionStorage.removeItem("fileguard_last_result");
            }
        }
    }

    // Reset handler to clear results and form
    window.resetValidation = function() {
        sessionStorage.removeItem("fileguard_last_result");
        if (resultContainer) {
            resultContainer.style.display = "none";
            resultContainer.innerHTML = "";
        }
        if (validationForm) validationForm.reset();
        clearFileAttachment();
        hideError();
        window.scrollTo({ top: 0, behavior: "smooth" });
    };

    if (resetBtn) {
        resetBtn.addEventListener("click", () => {
            window.resetValidation();
        });
    }

    // Preset Prompt Chips
    document.querySelectorAll(".preset-chip").forEach(chip => {
        chip.addEventListener("click", () => {
            const promptText = chip.getAttribute("data-prompt");
            promptInput.value = promptText;
            promptInput.focus();
            hideError();
        });
    });

    // Drag and Drop Events
    ["dragenter", "dragover"].forEach(eventName => {
        dropZone.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropZone.classList.add("drag-active");
        });
    });

    ["dragleave", "drop"].forEach(eventName => {
        dropZone.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropZone.classList.remove("drag-active");
        });
    });

    dropZone.addEventListener("drop", (e) => {
        const dt = e.dataTransfer;
        const files = dt.files;
        if (files && files.length > 0) {
            fileInput.files = files;
            updateAttachedFileUI(files[0]);
        }
    });

    // Clicking drop zone triggers hidden file input (unless clicking remove button)
    dropZone.addEventListener("click", (e) => {
        if (e.target !== removeFileBtn && !removeFileBtn.contains(e.target)) {
            fileInput.click();
        }
    });

    fileInput.addEventListener("change", () => {
        if (fileInput.files && fileInput.files.length > 0) {
            updateAttachedFileUI(fileInput.files[0]);
        }
    });

    removeFileBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        clearFileAttachment();
    });

    resetBtn.addEventListener("click", () => {
        window.resetValidation();
    });

    function updateAttachedFileUI(file) {
        hideError();
        const filename = file.name;
        const sizeFormatted = formatBytes(file.size);
        const ext = getExtension(filename);

        attachedName.textContent = filename;
        attachedName.title = filename;
        attachedSize.textContent = sizeFormatted;
        attachedExt.textContent = ext || "no-ext";
        attachedIcon.textContent = getFileIcon(ext);

        dropZonePrompt.style.display = "none";
        attachedCard.style.display = "flex";
    }

    function clearFileAttachment() {
        fileInput.value = "";
        dropZonePrompt.style.display = "flex";
        attachedCard.style.display = "none";
    }

    function showError(message) {
        clientError.textContent = message;
        clientError.style.display = "block";
    }

    function hideError() {
        clientError.textContent = "";
        clientError.style.display = "none";
    }

    // Form Submission
    validationForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        hideError();

        const promptText = promptInput.value.trim();
        if (!promptText) {
            showError("Please enter a validation requirements prompt.");
            promptInput.focus();
            return;
        }

        if (!fileInput.files || fileInput.files.length === 0) {
            showError("Please attach a document or file to validate.");
            return;
        }

        // Prepare Form Data
        const formData = new FormData();
        formData.append("prompt", promptText);
        formData.append("file", fileInput.files[0]);

        // UI Transition to Processing
        submitBtn.disabled = true;
        submitBtn.innerHTML = `<span class="btn-spinner"></span> Validating...`;
        resultContainer.style.display = "none";
        processingCard.style.display = "block";

        // Animated progress steps simulation while waiting for server response
        const steps = [
            "step-prompt",
            "step-type",
            "step-size",
            "step-integrity",
            "step-ai"
        ];
        
        steps.forEach(id => {
            const el = document.getElementById(id);
            if (el) el.className = "step-item";
        });

        let currentStep = 0;
        const stepInterval = setInterval(() => {
            if (currentStep < steps.length) {
                const stepEl = document.getElementById(steps[currentStep]);
                if (stepEl) {
                    stepEl.classList.remove("active");
                    stepEl.classList.add("completed");
                }
                currentStep++;
                if (currentStep < steps.length) {
                    const nextEl = document.getElementById(steps[currentStep]);
                    if (nextEl) nextEl.classList.add("active");
                }
            }
        }, 350);

        try {
            const response = await fetch("/api/validate", {
                method: "POST",
                body: formData
            });

            clearInterval(stepInterval);
            // Mark all steps completed
            steps.forEach(id => {
                const el = document.getElementById(id);
                if (el) el.className = "step-item completed";
            });

            const data = await response.json();

            // Short pause for UX smoothness
            setTimeout(() => {
                processingCard.style.display = "none";
                submitBtn.disabled = false;
                submitBtn.innerHTML = `<span class="btn-icon">➤</span> Validate File`;
                renderValidationResult(data);
            }, 400);

        } catch (error) {
            clearInterval(stepInterval);
            processingCard.style.display = "none";
            submitBtn.disabled = false;
            submitBtn.innerHTML = `<span class="btn-icon">➤</span> Validate File`;
            showError("Network or server connection error. Please try again.");
        }
    });

    function renderValidationResult(data, shouldScroll = true) {
        // Cache result so page navigation retains recent validation state
        try {
            sessionStorage.setItem("fileguard_last_result", JSON.stringify(data));
        } catch (e) {}
        const isPassed = data.validation_status === "passed";
        const score = data.score || 0;
        const file = data.file || {};
        const reqs = data.requirements || {};
        const classification = data.classification || {};
        const checks = data.checks || [];
        const violations = data.violations || [];
        const warnings = data.warnings || [];

        const scoreClass = score >= 80 ? "score-high" : (score >= 50 ? "score-mid" : "score-low");

        let checksRows = checks.map(c => {
            const isOk = c.status === "passed";
            return `
                <tr class="${isOk ? 'row-passed' : 'row-failed'}">
                    <td><strong>${c.name}</strong></td>
                    <td>
                        <span class="badge ${isOk ? 'badge-success' : 'badge-danger'}">
                            ${isOk ? '✓ PASS' : '✗ FAIL'}
                        </span>
                    </td>
                    <td class="detail-cell">${c.detail}</td>
                </tr>
            `;
        }).join("");

        let violationsHtml = "";
        if (violations.length > 0) {
            violationsHtml = `
                <div class="result-violations-box">
                    <div class="violations-header">
                        <span class="v-icon">⚠️</span>
                        <strong>Validation Violations Detected (${violations.length})</strong>
                    </div>
                    <ul class="violations-list">
                        ${violations.map(v => `<li>${v}</li>`).join("")}
                    </ul>
                </div>
            `;
        }

        let warningsHtml = "";
        if (warnings.length > 0) {
            warningsHtml = `
                <div class="result-warnings-box">
                    <div class="warnings-header">
                        <span class="w-icon">ℹ️</span>
                        <strong>Security Warnings</strong>
                    </div>
                    <ul class="warnings-list">
                        ${warnings.map(w => `<li>${w}</li>`).join("")}
                    </ul>
                </div>
            `;
        }

        // If file is corrupted, build the AI File Recovery Callout Box
        let recoveryBannerHtml = "";
        if (file.is_corrupted) {
            recoveryBannerHtml = `
                <div class="assistant-recovery-callout card" style="margin: 20px 0; border: 1px solid var(--warning-border); background: rgba(245, 158, 11, 0.08);">
                    <div class="callout-header" style="display: flex; gap: 16px; align-items: flex-start;">
                        <div class="callout-icon" style="font-size: 32px; background: rgba(245, 158, 11, 0.15); border-radius: var(--radius-sm); padding: 8px 12px;">🛠️</div>
                        <div class="callout-text" style="flex: 1;">
                            <div class="badge badge-warning" style="margin-bottom: 6px;">Corrupted Document Detected</div>
                            <h3 style="font-size: 1.15rem; margin-bottom: 6px;">Repair and Recover "${file.name || 'File'}" with AI</h3>
                            <p style="color: var(--text-secondary); font-size: 0.92rem; margin-bottom: 12px;">
                                Structural damage was detected: <em>${file.integrity_detail || 'Damaged stream container'}</em>. 
                                FileGuard AI can salvage the raw text streams, repair XML/binary envelopes, and generate a fully restored, non-blank document.
                            </p>
                            <div class="callout-actions">
                                <button type="button" id="btnAssistantRepair" class="btn btn-primary btn-lg btn-glow">
                                    <span class="btn-icon">🛠️</span> Repair or Recover File with AI
                                </button>
                            </div>
                        </div>
                    </div>
                    <!-- Recovery State Container -->
                    <div id="assistantRecoveryState" style="display: none; margin-top: 18px; border-top: 1px solid rgba(255,255,255,0.08); padding-top: 18px;">
                    </div>
                </div>
            `;
        }

        resultContainer.innerHTML = `
            <div class="card result-card ${isPassed ? 'result-passed' : 'result-failed'}">
                <!-- Top Status Header -->
                <div class="result-header">
                    <div class="result-status-block">
                        <div class="status-indicator-icon ${isPassed ? 'icon-success' : 'icon-failed'}">
                            ${isPassed ? '✓' : '✗'}
                        </div>
                        <div>
                            <h2 class="result-heading">${isPassed ? 'VALIDATION SUCCESSFUL' : 'VALIDATION FAILED'}</h2>
                            <p class="result-subheading">
                                ${isPassed 
                                    ? 'The file satisfies all security policies and requested requirements.' 
                                    : 'The file failed one or more security or rule validation checks.'}
                            </p>
                        </div>
                    </div>
                    <div class="score-display">
                        <div class="score-circle ${scoreClass}">
                            <span class="score-number">${score}%</span>
                            <span class="score-text">Validation Score</span>
                        </div>
                    </div>
                </div>

                <!-- Detected File Specs Grid -->
                <div class="specs-grid">
                    <div class="spec-item">
                        <span class="spec-label">File Name</span>
                        <strong class="spec-value mono-text" title="${file.name || 'Unknown'}">${file.name || 'Unknown'}</strong>
                    </div>
                    <div class="spec-item">
                        <span class="spec-label">Detected Type</span>
                        <strong class="spec-value">${file.detected_type || 'Unknown'}</strong>
                    </div>
                    <div class="spec-item">
                        <span class="spec-label">File Size</span>
                        <strong class="spec-value">${file.size_human || '0 B'} <small>(${file.size_bytes ? file.size_bytes.toLocaleString() : 0} bytes)</small></strong>
                    </div>
                    <div class="spec-item">
                        <span class="spec-label">File Integrity</span>
                        <strong class="spec-value">
                            <span class="badge ${file.is_corrupted ? 'badge-danger' : 'badge-success'}">
                                ${file.is_corrupted ? '✗ Corrupted' : '✓ Intact'}
                            </span>
                        </strong>
                    </div>
                </div>

                ${recoveryBannerHtml}
                ${violationsHtml}
                ${warningsHtml}

                <!-- Detailed Checks Table -->
                <div class="checks-section">
                    <h3 class="checks-title">Deterministic Rule Breakdown</h3>
                    <div class="table-responsive">
                        <table class="checks-table">
                            <thead>
                                <tr>
                                    <th>Rule Requirement</th>
                                    <th>Status</th>
                                    <th>Inspection Detail</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${checksRows}
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- AI Analysis Narrative -->
                <div class="ai-analysis-box">
                    <div class="ai-box-header">
                        <span class="ai-badge">🤖 AI Analysis & Explanation</span>
                        <span class="ai-engine-badge">Engine: ${reqs.interpreted_by || 'Hybrid'}</span>
                    </div>
                    <p class="ai-box-text">${data.ai_analysis || 'No summary available.'}</p>
                    <div class="ai-recommendation">
                        <strong>Recommended Action:</strong>
                        <span>${data.recommended_action || 'Review findings.'}</span>
                    </div>
                </div>

                <!-- Action Footer -->
                <div class="result-footer">
                    <button type="button" class="btn btn-secondary" onclick="window.resetValidation();">
                        Validate Another File
                    </button>
                    <a href="/recover" class="btn btn-outline">
                        🛠️ Open Recover Files
                    </a>
                    <a href="/dashboard" class="btn btn-outline">
                        View in Audit Dashboard →
                    </a>
                </div>
            </div>
        `;

        resultContainer.style.display = "block";
        if (shouldScroll) {
            resultContainer.scrollIntoView({ behavior: "smooth", block: "start" });
        }

        // Bind Assistant Repair Button if corrupted
        const btnAssistantRepair = document.getElementById("btnAssistantRepair");
        const asstRecoveryState = document.getElementById("assistantRecoveryState");

        if (btnAssistantRepair && asstRecoveryState) {
            btnAssistantRepair.addEventListener("click", async () => {
                btnAssistantRepair.disabled = true;
                btnAssistantRepair.innerHTML = `<span class="btn-spinner"></span> Repairing File with AI...`;

                asstRecoveryState.style.display = "block";
                asstRecoveryState.innerHTML = `
                    <div class="processing-spinner" style="width: 32px; height: 32px; margin: 12px auto;"></div>
                    <p style="text-align: center; color: var(--text-secondary); font-size: 0.9rem;">
                        Extracting salvageable streams and synthesizing clean document...
                    </p>
                `;

                try {
                    const recFormData = new FormData();
                    if (file.corrupted_cache_id) {
                        recFormData.append("cache_id", file.corrupted_cache_id);
                    }
                    if (fileInput.files && fileInput.files.length > 0) {
                        recFormData.append("file", fileInput.files[0]);
                    }
                    recFormData.append("file_type", file.detected_category || "auto");

                    const recRes = await fetch("/api/recover", {
                        method: "POST",
                        body: recFormData
                    });

                    const recData = await recRes.json();

                    if (recData.success) {
                        asstRecoveryState.innerHTML = `
                            <div class="recovery-success-box" style="background: rgba(16, 185, 129, 0.1); border: 1px solid var(--success-border); border-radius: var(--radius-md); padding: 16px;">
                                <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 10px;">
                                    <span style="font-size: 20px; color: var(--success);">✓</span>
                                    <strong style="color: var(--success); font-size: 1.05rem;">File Recovered Successfully (Non-Blank Verified)</strong>
                                </div>
                                <p style="font-size: 0.9rem; color: var(--text-secondary); margin-bottom: 12px;">
                                    ${recData.summary}
                                </p>
                                <div class="recovered-preview-snippet" style="background: rgba(0,0,0,0.3); padding: 10px; border-radius: var(--radius-sm); font-family: var(--font-mono); font-size: 0.82rem; max-height: 120px; overflow-y: auto; margin-bottom: 16px; color: #cbd5e1;">
                                    ${escapeHtml(recData.preview_snippet || 'Document text successfully extracted and stabilized.')}
                                </div>
                                <div class="recovery-actions-group" style="display: flex; gap: 10px; flex-wrap: wrap;">
                                    <a href="${recData.download_url}" class="btn btn-primary btn-sm">
                                        ⬇️ Download Recovered File
                                    </a>
                                    <button type="button" class="btn btn-outline btn-sm" id="btnAsstViewDoc">
                                        👁️ View Recovered File
                                    </button>
                                    <a href="/recover#recoverLog" class="btn btn-outline btn-sm">
                                        📋 View in Recover Page Log
                                    </a>
                                    <button type="button" class="btn btn-validate-action btn-sm" id="btnAsstValidateDoc">
                                        ✓ Validate Recovered File
                                    </button>
                                </div>
                            </div>
                        `;

                        btnAssistantRepair.style.display = "none";

                        // View Recovered File Modal
                        document.getElementById("btnAsstViewDoc").addEventListener("click", () => {
                            openAssistantViewModal(recData.recovery_id);
                        });

                        // Validate Recovered File Button (links to assistant validation flow!)
                        document.getElementById("btnAsstValidateDoc").addEventListener("click", async () => {
                            const valBtn = document.getElementById("btnAsstValidateDoc");
                            valBtn.disabled = true;
                            valBtn.innerHTML = `<span class="btn-spinner"></span> Validating...`;

                            try {
                                const vForm = new FormData();
                                vForm.append("prompt", promptInput.value || `Validate this recovered ${recData.recovered_type} file.`);

                                const valRes = await fetch(`/api/recover/validate/${recData.recovery_id}`, {
                                    method: "POST",
                                    body: vForm
                                });

                                const newValData = await valRes.json();
                                if (newValData.success) {
                                    renderValidationResult(newValData);
                                } else {
                                    alert("Validation failed: " + (newValData.error || "Unknown error"));
                                    valBtn.disabled = false;
                                    valBtn.innerHTML = `✓ Validate Recovered File`;
                                }
                            } catch (e) {
                                alert("Failed to validate recovered file.");
                                valBtn.disabled = false;
                                valBtn.innerHTML = `✓ Validate Recovered File`;
                            }
                        });

                    } else {
                        asstRecoveryState.innerHTML = `
                            <div class="alert-error" style="display: block;">
                                <strong>Recovery Failed:</strong> ${recData.error || 'Could not reconstruct file.'}
                            </div>
                        `;
                        btnAssistantRepair.disabled = false;
                        btnAssistantRepair.innerHTML = `<span class="btn-icon">🛠️</span> Try Repair Again`;
                    }

                } catch (e) {
                    asstRecoveryState.innerHTML = `
                        <div class="alert-error" style="display: block;">
                            <strong>Connection Error:</strong> Could not connect to recovery service.
                        </div>
                    `;
                    btnAssistantRepair.disabled = false;
                    btnAssistantRepair.innerHTML = `<span class="btn-icon">🛠️</span> Try Repair Again`;
                }
            });
        }
    }

    // Modal Handling for Assistant Page
    const viewRecoveredModal = document.getElementById("viewRecoveredModal");
    const closeAsstViewModalBtn = document.getElementById("closeAsstViewModalBtn");
    const asstViewModalTitle = document.getElementById("asstViewModalTitle");
    const asstViewModalMeta = document.getElementById("asstViewModalMeta");
    const asstViewModalContent = document.getElementById("asstViewModalContent");
    const asstViewCharCount = document.getElementById("asstViewCharCount");
    const asstViewWordCount = document.getElementById("asstViewWordCount");
    const asstViewModalDownloadBtn = document.getElementById("asstViewModalDownloadBtn");
    const asstViewModalRawBtn = document.getElementById("asstViewModalRawBtn");

    async function openAssistantViewModal(recId) {
        if (!viewRecoveredModal) return;
        asstViewModalContent.innerHTML = `<div class="processing-spinner" style="margin: 40px auto;"></div>`;
        viewRecoveredModal.style.display = "flex";

        try {
            const res = await fetch(`/api/recover/view/${recId}`);
            const data = await res.json();
            if (data.success) {
                const rec = data.record || {};
                asstViewModalTitle.textContent = rec.filename || "Recovered Document";
                asstViewModalMeta.textContent = `${rec.recovered_type} • ${rec.recovered_size_human} • ${rec.timestamp}`;
                asstViewCharCount.textContent = `${(data.char_count || data.content.length).toLocaleString()} characters`;
                asstViewWordCount.textContent = `${(data.word_count || data.content.split(/\s+/).length).toLocaleString()} words`;

                asstViewModalDownloadBtn.href = `/api/recover/download/${recId}`;
                asstViewModalRawBtn.href = data.raw_url;

                asstViewModalContent.innerHTML = `
                    <div class="doc-text-rendered">
                        ${renderFormattedDoc(data.content)}
                    </div>
                `;
            } else {
                asstViewModalContent.innerHTML = `<p class="text-danger">${data.error || 'Failed to load preview.'}</p>`;
            }
        } catch (e) {
            asstViewModalContent.innerHTML = `<p class="text-danger">Unable to load document preview.</p>`;
        }
    }

    if (closeAsstViewModalBtn) {
        closeAsstViewModalBtn.addEventListener("click", () => {
            viewRecoveredModal.style.display = "none";
        });
    }

    window.addEventListener("click", (e) => {
        if (e.target === viewRecoveredModal) {
            viewRecoveredModal.style.display = "none";
        }
    });

    function renderFormattedDoc(content) {
        if (!content) return "<p>No content available.</p>";
        const lines = content.split("\n");
        let html = "";
        for (const line of lines) {
            const trimmed = line.trim();
            if (!trimmed) {
                html += "<br>";
            } else if (trimmed.startsWith("# ")) {
                html += `<h3>${escapeHtml(trimmed.replace(/^#\s*/, ''))}</h3>`;
            } else if (trimmed.startsWith("## ")) {
                html += `<h4>${escapeHtml(trimmed.replace(/^##\s*/, ''))}</h4>`;
            } else if (trimmed.startsWith("- ") || trimmed.startsWith("• ")) {
                html += `<li>${escapeHtml(trimmed.replace(/^[-•]\s*/, ''))}</li>`;
            } else {
                html += `<p>${escapeHtml(trimmed)}</p>`;
            }
        }
        return html;
    }

    function escapeHtml(str) {
        if (!str) return "";
        return str
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    // Helper functions
    function formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    function getExtension(filename) {
        const dot = filename.lastIndexOf(".");
        return dot !== -1 ? filename.substring(dot).toLowerCase() : "";
    }

    function getFileIcon(ext) {
        if (ext === ".pdf") return "📄";
        if ([".doc", ".docx"].includes(ext)) return "📝";
        if ([".xls", ".xlsx", ".csv"].includes(ext)) return "📊";
        if ([".ppt", ".pptx"].includes(ext)) return "📑";
        if ([".png", ".jpg", ".jpeg", ".gif", ".webp"].includes(ext)) return "🖼️";
        if (ext === ".txt") return "📃";
        if (ext === ".zip") return "📦";
        return "📁";
    }
});
