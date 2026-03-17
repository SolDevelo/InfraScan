document.addEventListener('DOMContentLoaded', () => {
    const tabs = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');
    const scanRepoBtn = document.getElementById('scan-repo-btn');
    const repoUrlInput = document.getElementById('repo-url');

    const scannerTypeSelect = document.getElementById('scanner-type');
    const loading = document.getElementById('loading');
    const resultsArea = document.getElementById('results-area');
    const resultsContent = document.getElementById('results-content');
    const shareBtn = document.getElementById('share-btn');
    const shareLinkContainer = document.getElementById('share-link-container');
    const shareUrlInput = document.getElementById('share-url');
    const copyShareBtn = document.getElementById('copy-share-btn');
    const scanInputContainer = document.getElementById('scan-input-container');
    const privateScanToggle = document.getElementById('private-scan-toggle');
    const newScanBtn = document.getElementById('new-scan-btn');
    const mainContainer = document.querySelector('.container');
    const scrollTopBtn = document.getElementById('scroll-to-top');
    const landingInfo = document.querySelector('.landing-info');

    // Feedback Elements
    const feedbackModal = document.getElementById('feedback-modal');
    const openFeedbackBtn = document.getElementById('open-feedback-btn');
    const closeFeedbackBtn = document.getElementById('close-feedback-btn');
    const submitFeedbackBtn = document.getElementById('submit-feedback-btn');
    const stars = document.querySelectorAll('.star');
    const feedbackReview = document.getElementById('feedback-review');
    const feedbackContact = document.getElementById('feedback-contact');
    let selectedRating = 0;

    let currentResults = null;
    let currentSummary = null;
    let currentMetadata = null;
    let currentGradeReport = null;
    let currentScanId = null;
    let hasAutoOpenedFeedback = false;

    // Pagination State for Recent Scans
    let allRecentScans = [];
    let recentScansCurrentPage = 1;
    const recentScansPageSize = 5;

    // Check for CLI Injected Data (Standalone HTML Report)
    if (window.CLI_INJECTED_DATA) {
        const data = window.CLI_INJECTED_DATA;
        if (scanInputContainer) scanInputContainer.style.display = 'none';
        if (document.querySelector('.tabs')) document.querySelector('.tabs').style.display = 'none';
        if (landingInfo) landingInfo.style.display = 'none';

        const gradeReport = {
            overall: data.overall,
            cost: data.cost,
            security: data.security,
            container: data.container,
            analysis: data.analysis
        };

        displayResults(data.results, data.summary, data.metadata, gradeReport);

        // Hide elements that don't make sense in standalone report
        if (newScanBtn) newScanBtn.style.display = 'none';
        if (shareBtn) shareBtn.style.display = 'none';

        return; // Skip normal web app initialization
    }

    // Check scanner availability on load
    checkScannerStatus();
    loadSharedResults();

    async function checkScannerStatus() {
        try {
            const response = await fetch('/api/scanner/status');
            const status = await response.json();

            const helpText = document.querySelector('.help-text');
            let warnings = [];

            // Check if comprehensive scanning is possible
            if (!status.comprehensive) {
                // No security or container scanners available
                const containersOption = scannerTypeSelect.querySelector('option[value="containers"]');
                const checkovOption = scannerTypeSelect.querySelector('option[value="checkov"]');
                const comprehensiveOption = scannerTypeSelect.querySelector('option[value="comprehensive"]');
                if (containersOption) containersOption.disabled = true;
                if (checkovOption) checkovOption.disabled = true;
                if (comprehensiveOption) comprehensiveOption.disabled = true;

                warnings.push('⚠️ Security scanners not installed (Checkov & container scanner)');
            } else {
                // At least one is available, but warn about missing ones
                if (!status.checkov) {
                    warnings.push('ℹ️ Checkov not installed (IaC security checks disabled)');
                }
                if (!status.containers) {
                    warnings.push('ℹ️ Container scanner not available');
                }
            }

            // Add warnings to help text
            if (helpText && warnings.length > 0) {
                helpText.innerHTML += ' <strong style="color: var(--warning);">' + warnings.join(' ') + '</strong>';
            }
        } catch (error) {
            console.error('Failed to check scanner status:', error);
        }
    }

    async function loadSharedResults() {
        const urlParams = new URLSearchParams(window.location.search);
        const scanId = urlParams.get('scan_id');

        if (scanId) {
            loading.classList.remove('hidden');
            try {
                const response = await fetch(`/api/results/${scanId}`);
                const data = await response.json();

                if (!response.ok) throw new Error(data.error || 'Failed to load results');

                currentResults = data.results;
                currentSummary = data.summary;
                currentMetadata = data.metadata || {};
                currentScanId = scanId;

                // Reconstruct grade report from saved data
                if (data.overall) {
                    currentGradeReport = {
                        overall: data.overall,
                        cost: data.cost,
                        security: data.security,
                        container: data.container,
                        analysis: data.analysis
                    };
                }

                displayResults(data.results, data.summary, data.metadata, currentGradeReport);

                // Hide share button when viewing shared results (or keep it to resharing)
                // shareBtn.classList.add('hidden');
            } catch (error) {
                console.error('Error loading shared results:', error);
                alert('Could not load shared results: ' + error.message);
            } finally {
                loading.classList.add('hidden');
            }
        }
    }

    // Helper to open feedback modal
    function openFeedbackModal() {
        feedbackModal.classList.remove('hidden');
    }

    // Tab Switching
    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            const targetTab = tab.dataset.tab;

            tabs.forEach(t => t.classList.remove('active'));
            tabContents.forEach(c => c.classList.remove('active'));

            tab.classList.add('active');
            document.getElementById(`${targetTab}-tab`).classList.add('active');

            // Handle results visibility and container width
            if (targetTab === 'github') {
                if (currentResults) {
                    resultsArea.classList.remove('hidden');
                    if (scanInputContainer) scanInputContainer.classList.add('hidden');
                    if (mainContainer) mainContainer.classList.add('expanded');
                } else {
                    resultsArea.classList.add('hidden');
                    if (scanInputContainer) scanInputContainer.classList.remove('hidden');
                    if (landingInfo) landingInfo.classList.remove('collapsed');
                    if (mainContainer) mainContainer.classList.remove('expanded');
                }
            } else if (targetTab === 'recent-scans') {
                resultsArea.classList.add('hidden');
                if (mainContainer) mainContainer.classList.remove('expanded');
                loadRecentScans();
            } else {
                resultsArea.classList.add('hidden');
                if (mainContainer) mainContainer.classList.remove('expanded');
                // Ensure tabs are visible if switching to non-github tab
                const tabsNav = document.querySelector('.tabs');
                if (tabsNav) tabsNav.style.display = 'flex';
            }
        });
    });

    function showToast(message, type = 'error') {
        const container = document.getElementById('toast-container');
        if (!container) return;

        const toast = document.createElement('div');
        toast.className = `toast ${type}`;

        const icon = type === 'error' ? '❌' : '✅';
        toast.innerHTML = `<span>${icon}</span> <span>${message}</span>`;

        container.appendChild(toast);

        // Auto remove
        setTimeout(() => {
            toast.classList.add('fadeOut');
            setTimeout(() => toast.remove(), 300);
        }, 4000);
    }

    // Scan Repo
    scanRepoBtn.addEventListener('click', async () => {
        const url = repoUrlInput.value.trim();
        if (!url) {
            showToast('Please enter a repository URL');
            return;
        }

        const recipient = '';
        const isPrivate = privateScanToggle ? privateScanToggle.checked : false;

        await performScan('/api/scan/github', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                url,
                scanner: scannerTypeSelect ? scannerTypeSelect.value : 'comprehensive',
                recipient,
                is_private: isPrivate
            })
        });
    });

    // Share Results
    shareBtn.addEventListener('click', async () => {
        if (!currentResults) return;

        shareBtn.disabled = true;
        shareBtn.textContent = 'Saving...';

        try {
            if (currentScanId) {
                const shareUrl = `${window.location.origin}${window.location.pathname}?scan_id=${currentScanId}`;
                shareUrlInput.value = shareUrl;
                shareLinkContainer.classList.remove('hidden');
                shareBtn.textContent = 'Results Shared';
                return;
            }

            const response = await fetch('/api/results/save', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    results: currentResults,
                    summary: currentSummary,
                    metadata: currentMetadata,
                    overall: currentGradeReport ? currentGradeReport.overall : null,
                    cost: currentGradeReport ? currentGradeReport.cost : null,
                    security: currentGradeReport ? currentGradeReport.security : null,
                    container: currentGradeReport ? currentGradeReport.container : null,
                    analysis: currentGradeReport ? currentGradeReport.analysis : null,
                    is_private: currentMetadata ? currentMetadata.is_private : false
                })
            });
            const data = await response.json();

            if (!response.ok) throw new Error(data.error || 'Failed to save results');

            currentScanId = data.id;
            const shareUrl = `${window.location.origin}${window.location.pathname}?scan_id=${data.id}`;
            shareUrlInput.value = shareUrl;
            shareLinkContainer.classList.remove('hidden');
            shareBtn.textContent = 'Results Shared';
        } catch (error) {
            alert('Error sharing results: ' + error.message);
            shareBtn.textContent = 'Share Results';
            shareBtn.disabled = false;
        }
    });

    copyShareBtn.addEventListener('click', () => {
        shareUrlInput.select();
        document.execCommand('copy');
        copyShareBtn.textContent = 'Copied!';
        setTimeout(() => {
            copyShareBtn.textContent = 'Copy';
        }, 2000);
    });

    // New Scan Button
    if (newScanBtn) {
        newScanBtn.addEventListener('click', () => {
            resultsArea.classList.add('hidden');
            if (scanInputContainer) scanInputContainer.classList.remove('hidden');
            if (landingInfo) landingInfo.classList.remove('collapsed');
            repoUrlInput.value = ''; // Optional: clear input or keep it
            // Reset results
            currentResults = null;
            currentSummary = null;
            currentMetadata = null;
            currentGradeReport = null;
            if (mainContainer) mainContainer.classList.remove('expanded');
        });
    }

    async function performScan(url, options) {
        loading.classList.remove('hidden');
        resultsArea.classList.add('hidden');
        if (scanInputContainer) scanInputContainer.classList.add('hidden'); // Hide input
        resultsContent.innerHTML = '';
        currentScanId = null;

        try {
            const response = await fetch(url, options);
            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'Scan failed');
            }

            currentResults = data.results;
            currentSummary = data.summary;
            currentMetadata = data.metadata || {};
            currentGradeReport = {
                overall: data.overall,
                cost: data.cost,
                security: data.security,
                container: data.container,
                analysis: data.analysis
            };

            displayResults(data.results, data.summary, data.metadata, currentGradeReport);

            // Auto-save scan so it appears in Recent Scans history
            autoSaveScan(data);

            // Reset share state
            shareLinkContainer.classList.add('hidden');
            shareBtn.textContent = 'Share Results';
            shareBtn.disabled = false;
        } catch (error) {
            showToast(error.message);
            if (scanInputContainer) scanInputContainer.classList.remove('hidden'); // Show input again on failure
            if (landingInfo) landingInfo.classList.remove('collapsed'); // Show info cards again on failure
            if (mainContainer) mainContainer.classList.remove('expanded');
        } finally {
            loading.classList.add('hidden');
        }
    }

    async function autoSaveScan(data) {
        try {
            const response = await fetch('/api/results/save', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    results: data.results,
                    summary: data.summary,
                    metadata: data.metadata,
                    overall: data.overall,
                    cost: data.cost,
                    security: data.security,
                    container: data.container,
                    analysis: data.analysis,
                    is_private: data.metadata ? data.metadata.is_private : false
                })
            });
            const result = await response.json();
            if (result.id) {
                currentScanId = result.id;
            }
        } catch (e) {
            // Silent fail – auto-save is best-effort
            console.warn('Auto-save failed:', e);
        }
    }

    async function loadRecentScans() {
        const loadingEl = document.getElementById('recent-scans-loading');
        const emptyEl = document.getElementById('recent-scans-empty');
        const listEl = document.getElementById('recent-scans-list');
        const paginationEl = document.getElementById('recent-scans-pagination');

        if (!listEl) return;

        loadingEl.classList.remove('hidden');
        emptyEl.classList.add('hidden');
        if (paginationEl) paginationEl.classList.add('hidden');
        listEl.innerHTML = '';

        try {
            const response = await fetch('/api/scans/recent');
            const data = await response.json();
            allRecentScans = data.scans || [];
            recentScansCurrentPage = 1;

            loadingEl.classList.add('hidden');

            if (allRecentScans.length === 0) {
                emptyEl.classList.remove('hidden');
                return;
            }

            displayRecentScansPage();
        } catch (e) {
            loadingEl.classList.add('hidden');
            listEl.innerHTML = `<p class="recent-scans-error">Could not load scan history.</p>`;
        }
    }

    function displayRecentScansPage() {
        const listEl = document.getElementById('recent-scans-list');
        const paginationEl = document.getElementById('recent-scans-pagination');
        if (!listEl) return;

        const start = (recentScansCurrentPage - 1) * recentScansPageSize;
        const end = start + recentScansPageSize;
        const pageScans = allRecentScans.slice(start, end);

        listEl.innerHTML = pageScans.map(scan => renderScanHistoryCard(scan)).join('');

        if (allRecentScans.length > recentScansPageSize) {
            if (paginationEl) paginationEl.classList.remove('hidden');
            updatePaginationControls();
        } else {
            if (paginationEl) paginationEl.classList.add('hidden');
        }
    }

    function updatePaginationControls() {
        const prevBtn = document.getElementById('prev-page-btn');
        const nextBtn = document.getElementById('next-page-btn');
        const pageNumbers = document.getElementById('page-numbers');

        const totalPages = Math.ceil(allRecentScans.length / recentScansPageSize);

        if (prevBtn) prevBtn.disabled = recentScansCurrentPage === 1;
        if (nextBtn) nextBtn.disabled = recentScansCurrentPage === totalPages;

        if (pageNumbers) {
            let html = '';
            // Show up to 5 page buttons
            let startPage = Math.max(1, recentScansCurrentPage - 2);
            let endPage = Math.min(totalPages, startPage + 4);
            if (endPage - startPage < 4) startPage = Math.max(1, endPage - 4);

            for (let i = startPage; i <= endPage; i++) {
                html += `<div class="page-number ${i === recentScansCurrentPage ? 'active' : ''}" data-page="${i}">${i}</div>`;
            }

            if (totalPages > 1) {
                html += `<span class="pagination-info">Page ${recentScansCurrentPage} of ${totalPages}</span>`;
            }

            pageNumbers.innerHTML = html;

            // Add listeners to page numbers
            pageNumbers.querySelectorAll('.page-number').forEach(btn => {
                btn.onclick = () => {
                    recentScansCurrentPage = parseInt(btn.dataset.page);
                    displayRecentScansPage();
                    document.getElementById('recent-scans-tab').scrollTop = 0;
                };
            });
        }
    }

    // Add event listeners for pagination buttons
    const prevPageBtn = document.getElementById('prev-page-btn');
    const nextPageBtn = document.getElementById('next-page-btn');

    if (prevPageBtn) {
        prevPageBtn.onclick = () => {
            if (recentScansCurrentPage > 1) {
                recentScansCurrentPage--;
                displayRecentScansPage();
                document.getElementById('recent-scans-tab').scrollTop = 0;
            }
        };
    }

    if (nextPageBtn) {
        nextPageBtn.onclick = () => {
            const totalPages = Math.ceil(allRecentScans.length / recentScansPageSize);
            if (recentScansCurrentPage < totalPages) {
                recentScansCurrentPage++;
                displayRecentScansPage();
                document.getElementById('recent-scans-tab').scrollTop = 0;
            }
        };
    }

    function renderScanHistoryCard(scan) {
        const gradeColor = { A: '#10b981', B: '#3b82f6', C: '#f59e0b', D: '#ef4444', F: '#dc2626' };

        const gradePill = (grade, label) => {
            if (!grade) return '';
            const color = gradeColor[grade.letter] || '#6b7280';
            return `<span class="grade-pill" style="background:${color}22; border-color:${color}; color:${color}" title="${label}: ${grade.percentage}%">${label} ${grade.letter}</span>`;
        };

        const recipientBadge = '';

        const viewUrl = `${window.location.origin}${window.location.pathname}?scan_id=${scan.id}`;

        return `
        <div class="scan-history-card">
            <div class="scan-history-main">
                <a class="scan-repo-name" href="${escapeHtml(scan.repository_url)}" target="_blank" rel="noopener noreferrer">
                    <span class="scan-repo-icon">📦</span>${escapeHtml(scan.repository_name)}
                </a>
                <div class="scan-grades">
                    ${gradePill(scan.overall_grade, 'Overall')}
                    ${gradePill(scan.cost_grade, 'Cost')}
                    ${gradePill(scan.security_grade, 'Sec')}
                    ${scan.container_grade ? gradePill(scan.container_grade, 'Container') : ''}
                </div>
            </div>
            <div class="scan-history-meta">
                <span class="scan-date">🕐 ${escapeHtml(scan.scan_timestamp)}</span>
                <span class="scan-type">🔬 ${escapeHtml(formatScannerName(scan.scanner_type))}</span>
                <span class="scan-findings">⚠️ ${scan.total_findings} findings</span>
                ${recipientBadge}
            </div>
            <div class="scan-history-actions">
                <a class="scan-view-btn" href="${viewUrl}" target="_blank">View Full Report →</a>
            </div>
        </div>`;
    }

    function displayResults(results, summary, metadata, gradeReport) {
        resultsArea.classList.remove('hidden');
        if (landingInfo) landingInfo.classList.add('collapsed');
        if (mainContainer) mainContainer.classList.add('expanded');

        // Add metadata header if available
        let metadataHtml = '';
        if (metadata && metadata.repository_url) {
            metadataHtml = `
                <div class="report-metadata">
                    <div class="metadata-header">
                        <h3>📋 Report Information</h3>
                    </div>
                    <div class="metadata-grid">
                        <div class="metadata-item">
                            <span class="metadata-label">Repository:</span>
                            <span class="metadata-value">
                                <a href="${metadata.repository_url}" target="_blank" rel="noopener noreferrer">
                                    ${metadata.repository_name || metadata.repository_url}
                                </a>
                            </span>
                        </div>

                        ${metadata.scan_timestamp ? `
                        <div class="metadata-item">
                            <span class="metadata-label">Scanned:</span>
                            <span class="metadata-value">${metadata.scan_timestamp}</span>
                        </div>
                        ` : ''}
                        ${metadata.resource_count ? `
                        <div class="metadata-item">
                            <span class="metadata-label">Resources Scanned:</span>
                            <span class="metadata-value">${metadata.resource_count}</span>
                        </div>
                        ` : ''}
                    </div>
                </div>
            `;
        }

        // Add grade report if available
        let gradeHtml = '';
        if (gradeReport) {
            gradeHtml = renderGradeReport(gradeReport);
        }

        // Add summary if available
        if (summary) {
            const summaryHtml = `
                <div class="summary-grid">
                    <div class="stat-card total">
                        <div class="stat-value">${summary.total}</div>
                        <div class="stat-label">Total Findings</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">${summary.unique_rules || 0}</div>
                        <div class="stat-label">Unique Rules</div>
                    </div>
                    ${summary.regex_findings !== undefined ? `
                    <div class="stat-card">
                        <div class="stat-value">${summary.regex_findings}</div>
                        <div class="stat-label">Cost Findings</div>
                    </div>` : ''}
                    ${summary.checkov_findings !== undefined ? `
                    <div class="stat-card">
                        <div class="stat-value">${summary.checkov_findings}</div>
                        <div class="stat-label">IaC Security</div>
                    </div>` : ''}
                    ${summary.grype_findings !== undefined ? `
                    <div class="stat-card">
                        <div class="stat-value">${summary.grype_findings}</div>
                        <div class="stat-label">Container Vulnerabilities</div>
                    </div>` : ''}
                    <div class="stat-card">
                        <div class="stat-value scanner-name">${formatScannerName(summary.scanner_used)}</div>
                        <div class="stat-label">Scanner Used</div>
                    </div>
                </div>
            `;
        }

        resultsContent.innerHTML = metadataHtml + gradeHtml + (summary ? summaryHtml : '');

        if (results.length === 0) {
            resultsContent.innerHTML += `
                <div class="finding-card" style="border-left-color: var(--success)">
                    <div class="finding-header">
                        <span class="finding-title">No Issues Found</span>
                    </div>
                    <p>Great job! No issues found in the scanned infrastructure.</p>
                </div>
            `;
            return;
        }

        // Group results by rule_id
        const groupedResults = groupByRule(results);

        // Sort groups by severity
        const severityOrder = { 'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4 };
        const sortedGroups = Object.entries(groupedResults).sort(([, a], [, b]) => {
            return severityOrder[a[0].severity] - severityOrder[b[0].severity];
        });

        const costFindings = sortedGroups.filter(([ruleId, findings]) => findings[0].scanner === 'regex');
        const iacSecurityFindings = sortedGroups.filter(([ruleId, findings]) => findings[0].scanner === 'checkov');
        const containerFindings = sortedGroups.filter(([ruleId, findings]) => findings[0].scanner === 'docker-scout' || findings[0].scanner === 'grype');

        let html = '<div class="results-grid-layout">';

        // Cost Column
        if (costFindings.length > 0) {
            html += `
                <div class="results-column">
                    <h3 class="column-title cost">💰 Cost Optimization</h3>
                    ${renderFindingsList(costFindings)}
                </div>
            `;
        }

        // IaC Security Column
        if (iacSecurityFindings.length > 0) {
            html += `
                <div class="results-column">
                    <h3 class="column-title security">🔒 IaC Security</h3>
                    ${renderFindingsList(iacSecurityFindings)}
                </div>
            `;
        }

        // Container Security Column
        if (containerFindings.length > 0) {
            html += `
                <div class="results-column">
                    <h3 class="column-title security">🐳 Container Security</h3>
                    ${renderContainerFindings(containerFindings)}
                </div>
            `;
        }

        html += '</div>';
        resultsContent.innerHTML += html;
    }

    function renderFindingsList(groups) {
        return groups.map(([ruleId, findings]) => {
            const first = findings[0];
            const fileCount = findings.length;

            return `
            <div class="finding-card ${first.severity}">
                <div class="finding-header">
                    <span class="finding-title">${first.rule_name}</span>
                    <span class="severity-badge ${first.severity}">${first.severity}</span>
                </div>
                ${first.description && first.description !== 'null' ? `
                <div class="finding-detail" title="${escapeHtml(first.full_description || first.description)}">
                    <strong>Problem:</strong> ${first.description}
                </div>
                ` : ''}
                ${first.scanner === 'regex' ? `
                <div class="finding-detail">
                    <strong>Potential Savings:</strong> <span style="color: var(--success); font-weight: 600;">${first.estimated_savings}</span>
                </div>` : ''}
                <div class="finding-detail">
                    <strong>Occurrences:</strong> ${fileCount} ${fileCount === 1 ? 'location' : 'locations'}
                </div>
                <div class="occurrences-list">
                    ${findings.map(f => {
                // Different display for different scanners
                let displayText = `📄 ${f.file}${f.line ? `:${f.line}` : ''}`;

                if (f.scanner === 'checkov' && f.match_content && f.match_content.startsWith('Resource: ')) {
                    // Checkov - show resource name
                    const resourceName = f.match_content.replace('Resource: ', '');
                    displayText = `🔹 ${resourceName} <span style="color: var(--text-secondary); font-size: 0.9em;">(${f.file}:${f.line})</span>`;
                } else if ((f.scanner === 'docker-scout' || f.scanner === 'grype') && f.image) {
                    // Docker Scout / Grype - show image and package info
                    const cveNumber = f.rule_id || 'UNKNOWN';
                    displayText = `🐳 ${f.image}<br/><span style="color: var(--text-secondary); font-size: 0.9em;">Package: ${f.package}@${f.package_version}</span><br/><span style="color: var(--warning); font-size: 0.85em; font-weight: 500;">${cveNumber}</span>`;
                }

                return `
                        <div class="occurrence-item">
                            <strong>${displayText}</strong>
                            ${f.scanner !== 'checkov' && f.scanner !== 'docker-scout' && f.scanner !== 'grype' && f.match_content ? `<div class="code-block">${escapeHtml(f.match_content)}</div>` : ''}
                        </div>
                    `}).join('')}
                </div>
                <div class="finding-detail">
                    <strong>Fix:</strong> <span>${linkifyUrls(first.remediation, 500)}</span>
                </div>
            </div>
        `;
        }).join('');
    }

    function renderContainerFindings(groups) {
        // Flatten all findings from groups
        const allFindings = [];
        groups.forEach(([ruleId, findings]) => {
            findings.forEach(f => allFindings.push(f));
        });

        // Group by image
        const imageMap = {};
        allFindings.forEach(finding => {
            const image = finding.image || 'Unknown Image';
            if (!imageMap[image]) {
                imageMap[image] = [];
            }
            imageMap[image].push(finding);
        });

        // Sort images by severity (worst first)
        const severityValue = { 'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'Info': 0 };
        const sortedImages = Object.entries(imageMap).sort((a, b) => {
            const maxSevA = Math.max(...a[1].map(f => severityValue[f.severity] || 0));
            const maxSevB = Math.max(...b[1].map(f => severityValue[f.severity] || 0));
            return maxSevB - maxSevA;
        });

        return sortedImages.map(([image, findings]) => {
            // Count by severity
            const severityCount = { 'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0 };
            const packages = new Set();
            let fixableCount = 0;

            findings.forEach(f => {
                severityCount[f.severity] = (severityCount[f.severity] || 0) + 1;
                if (f.package) packages.add(f.package);
                if (f.fix_version && f.fix_version !== 'N/A' && f.fix_version !== null) fixableCount++;
            });

            const imageId = `image-${image.replace(/[^a-zA-Z0-9]/g, '-')}`;
            const totalVulns = findings.length;

            // Determine highest severity for border color
            const highestSeverity =
                severityCount.Critical > 0 ? 'Critical' :
                    severityCount.High > 0 ? 'High' :
                        severityCount.Medium > 0 ? 'Medium' :
                            severityCount.Low > 0 ? 'Low' : '';

            // Group findings by severity for display
            const bySeverity = {
                'Critical': findings.filter(f => f.severity === 'Critical'),
                'High': findings.filter(f => f.severity === 'High'),
                'Medium': findings.filter(f => f.severity === 'Medium'),
                'Low': findings.filter(f => f.severity === 'Low')
            };

            // Determine which severity group to auto-expand (highest with findings)
            const firstNonEmptySeverity =
                bySeverity.Critical.length > 0 ? 'Critical' :
                    bySeverity.High.length > 0 ? 'High' :
                        bySeverity.Medium.length > 0 ? 'Medium' :
                            bySeverity.Low.length > 0 ? 'Low' : '';

            return `
                <div class="image-card ${highestSeverity}">
                    <div class="image-card-header" onclick="toggleImageCard('${imageId}')">
                        <div class="image-card-title">
                            <span class="image-icon">🐳</span>
                            <span class="image-name">${escapeHtml(image)}</span>
                            <span class="expand-icon" id="${imageId}-icon">▶</span>
                        </div>
                        <div class="image-summary">
                            ${severityCount.Critical > 0 ? `<span class="severity-count critical-count">🔴 ${severityCount.Critical} Critical</span>` : ''}
                            ${severityCount.High > 0 ? `<span class="severity-count high-count">🟠 ${severityCount.High} High</span>` : ''}
                            ${severityCount.Medium > 0 ? `<span class="severity-count medium-count">🟡 ${severityCount.Medium} Medium</span>` : ''}
                            ${severityCount.Low > 0 ? `<span class="severity-count low-count">⚪ ${severityCount.Low} Low</span>` : ''}
                        </div>
                        <div class="image-meta">
                            <span>📦 ${packages.size} packages affected</span>
                            ${fixableCount > 0 ? `<span class="fixable-notice">⚠️ Fix available for ${fixableCount} ${fixableCount === 1 ? 'issue' : 'issues'}</span>` : ''}
                        </div>
                    </div>
                    <div class="image-card-content" id="${imageId}" style="display: none;">
                        ${Object.entries(bySeverity).map(([severity, vulns]) => {
                if (vulns.length === 0) return '';
                const severityIcon = { 'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '⚪' };
                const severityGroupId = `severity-${imageId}-${severity}`;

                // Auto-expand the highest severity group with findings
                const isExpanded = severity === firstNonEmptySeverity;

                return `
                                <div class="severity-group">
                                    <div class="severity-group-header" onclick="toggleSeverityGroup('${severityGroupId}')">
                                        <span>${severityIcon[severity]} ${severity} (${vulns.length})</span>
                                        <span class="severity-expand-icon" id="${severityGroupId}-icon">${isExpanded ? '▼' : '▶'}</span>
                                    </div>
                                    <div class="cve-list" id="${severityGroupId}" style="display: ${isExpanded ? 'flex' : 'none'};">
                                        ${vulns.map((v, idx) => {
                    const cveId = `cve-${imageId}-${severity}-${idx}`;
                    return `
                                                <div class="cve-item">
                                                    <div class="cve-summary" onclick="toggleCVE('${cveId}')">
                                                        <span class="cve-id">${v.rule_id}</span>
                                                        <span class="cve-package">${v.package}@${v.package_version}${v.fix_version && v.fix_version !== 'N/A' && v.fix_version !== null ? ` → ${v.fix_version}` : ''}</span>
                                                        <span class="cve-short-desc">${v.description ? (v.description.substring(0, 60) + (v.description.length > 60 ? '...' : '')) : ''}</span>
                                                        <span class="cve-expand-icon" id="${cveId}-icon">▼</span>
                                                    </div>
                                                    <div class="cve-details" id="${cveId}" style="display: none;">
                                                        ${v.scanner === 'grype' && (v.full_description || v.description) ? `
                                                            <div class="cve-detail-section">
                                                                <strong>Description:</strong>
                                                                <p>${escapeHtml(v.full_description || v.description)}</p>
                                                            </div>
                                                        ` : ''}
                                                        <div class="cve-detail-section">
                                                            <strong>Package:</strong> ${v.package}@${v.package_version}
                                                        </div>
                                                        ${v.remediation ? `
                                                            <div class="cve-detail-section">
                                                                <strong>${v.fix_version && v.fix_version !== 'N/A' && v.fix_version !== null ? 'Fix' : 'Status'}:</strong> <span>${linkifyUrls(v.remediation, 500)}</span>
                                                            </div>
                                                        ` : ''}
                                                    </div>
                                                </div>
                                            `;
                }).join('')}
                                    </div>
                                </div>
                            `;
            }).join('')}
                    </div>
                </div>
            `;
        }).join('');
    }

    function groupByRule(results) {
        const grouped = {};
        results.forEach(finding => {
            if (!grouped[finding.rule_id]) {
                grouped[finding.rule_id] = [];
            }

            // Check for duplicates - same file and line
            const isDuplicate = grouped[finding.rule_id].some(existing =>
                existing.file === finding.file &&
                existing.line === finding.line &&
                existing.match_content === finding.match_content
            );

            if (!isDuplicate) {
                grouped[finding.rule_id].push(finding);
            }
        });
        return grouped;
    }

    function escapeHtml(text) {
        if (!text) return '';
        return text
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    function truncateText(text, maxLength = 100) {
        if (!text || text.length <= maxLength) return text;
        return text.substring(0, maxLength) + '...';
    }

    function linkifyUrls(text, maxLength = null) {
        if (!text) return '';

        // First escape HTML to prevent XSS
        let escaped = escapeHtml(text);

        // Find URLs and replace them with links
        const urlPattern = /(https?:\/\/[^\s<]+)/g;
        escaped = escaped.replace(urlPattern, (fullUrl) => {
            // Keep full URL for href
            const displayUrl = maxLength && fullUrl.length > maxLength
                ? fullUrl.substring(0, maxLength) + '...'
                : fullUrl;
            return `<a href="${fullUrl}" target="_blank" rel="noopener noreferrer" class="remediation-link">${displayUrl}</a>`;
        });

        // If the whole text (not just URLs) needs truncating
        if (maxLength && text.length > maxLength && !text.match(urlPattern)) {
            escaped = truncateText(text, maxLength);
        }

        return escaped;
    }

    // Feedback Logic
    if (openFeedbackBtn) {
        openFeedbackBtn.addEventListener('click', () => {
            openFeedbackModal();
        });
    }

    if (closeFeedbackBtn) {
        closeFeedbackBtn.addEventListener('click', (e) => {
            e.preventDefault();
            feedbackModal.classList.add('hidden');
        });
    }

    if (feedbackModal) {
        window.addEventListener('click', (e) => {
            if (e.target === feedbackModal) {
                feedbackModal.classList.add('hidden');
            }
        });

        // Global scroll listener for feedback and scroll-to-top button
        window.addEventListener('scroll', () => {
            // 1. Handle Scroll-to-Top Button visibility
            if (window.scrollY > 400) {
                scrollTopBtn.classList.remove('hidden');
            } else {
                scrollTopBtn.classList.add('hidden');
            }

            // 2. Handle Auto-open feedback on scroll
            if (hasAutoOpenedFeedback || !currentResults || resultsArea.classList.contains('hidden')) return;

            // Check if user scrolled near the bottom (80% of the page)
            const scrollPercent = (window.innerHeight + window.scrollY) / document.documentElement.scrollHeight;
            if (scrollPercent > 0.8) {
                hasAutoOpenedFeedback = true;
                setTimeout(openFeedbackModal, 1000); // Small delay for better feel
            }
        });

        // Scroll to top execution
        if (scrollTopBtn) {
            scrollTopBtn.addEventListener('click', () => {
                window.scrollTo({
                    top: 0,
                    behavior: 'smooth'
                });
            });
        }
    }

    stars.forEach(star => {
        star.addEventListener('mouseover', () => {
            const val = parseInt(star.dataset.value);
            highlightStars(val);
        });

        star.addEventListener('mouseout', () => {
            highlightStars(selectedRating);
        });

        star.addEventListener('click', () => {
            selectedRating = parseInt(star.dataset.value);
            highlightStars(selectedRating);
        });
    });

    function highlightStars(count) {
        stars.forEach(s => {
            if (parseInt(s.dataset.value) <= count) {
                s.classList.add('active');
            } else {
                s.classList.remove('active');
            }
        });
    }

    function renderGradeReport(gradeReport) {
        if (!gradeReport || !gradeReport.overall) return '';

        const getGradeColor = (letter) => {
            const colors = {
                'A': '#10b981', 'B': '#3b82f6', 'C': '#f59e0b',
                'D': '#ef4444', 'F': '#dc2626'
            };
            return colors[letter] || '#6b7280';
        };

        const getRiskIcon = (risk) => {
            const icons = {
                'Low': '✅', 'Medium': '⚠️', 'Medium-High': '⚠️',
                'High': '🔴', 'Critical': '🚨'
            };
            return icons[risk] || '●';
        };

        const getGradeExplanation = (title) => {
            const explanations = {
                'Overall Grade': 'Weighted average: ~33% Cost + ~33% IaC Security + ~33% Container Security.\nSeverity caps: Critical → max C, High → max B.\nSeverity breakdown aggregates: Cost findings + IaC resources + Container images.',
                'Cost Optimization': 'Formula: 100 - (Weighted Score / Max Score × 100)\nWeighted Score = Σ(severity × count)\nMax Score = (resources + rules) × 4\nSeverity weights: Critical=4, High=3, Medium=2, Low=1, Info=0.5',
                'IaC Security': 'Only most severe finding per resource scored.\nFormula: 100 - (Weighted Score / Max Score × 100)\nMax Score = resource_count × 4\nSeverity weights: Critical=4, High=3, Medium=2, Low=1, Info=0.5',
                'Container Security': 'Aggregated by container image - worst severity per image counted.\nFormula: 100 - (Σ severity_weight / image_count × 4 × 100)\nSeverity breakdown shows count of images at each level.\nSeverity weights: Critical=4, High=3, Medium=2, Low=1, Info=0.5'
            };
            return explanations[title] || '';
        };

        const renderGradeCard = (title, grade, icon) => {
            if (!grade || grade.violations === 0) return '';

            // Context-aware label for violations
            let violationsLabel = 'Violations:';
            if (title === 'Container Security') {
                violationsLabel = 'Affected Images:';
            } else if (title === 'Overall Grade') {
                violationsLabel = 'Total Issues:';
            }

            return `
                <div class="grade-card">
                    <div class="grade-card-header">
                        <span class="grade-card-icon">${icon}</span>
                        <span class="grade-card-title">${title}</span>
                        <span class="grade-help-icon" title="${getGradeExplanation(title)}">?</span>
                    </div>
                    <div class="grade-letter" style="background: ${getGradeColor(grade.letter)}">
                        ${grade.letter}
                    </div>
                    <div class="grade-percentage">${grade.percentage}%</div>
                    <div class="grade-details">
                        <div class="grade-detail-item">
                            <span class="grade-detail-label">Risk Level:</span>
                            <span class="grade-detail-value">${getRiskIcon(grade.risk_level)} ${grade.risk_level}</span>
                        </div>
                        <div class="grade-detail-item">
                            <span class="grade-detail-label">${violationsLabel}</span>
                            <span class="grade-detail-value">${grade.violations}</span>
                        </div>
                        ${grade.severity_breakdown ? `
                        <div class="grade-severity-breakdown">
                            ${grade.severity_breakdown.critical > 0 ? `<span class="severity-tag critical-tag">${grade.severity_breakdown.critical} Critical</span>` : ''}
                            ${grade.severity_breakdown.high > 0 ? `<span class="severity-tag high-tag">${grade.severity_breakdown.high} High</span>` : ''}
                            ${grade.severity_breakdown.medium > 0 ? `<span class="severity-tag medium-tag">${grade.severity_breakdown.medium} Medium</span>` : ''}
                            ${grade.severity_breakdown.low > 0 ? `<span class="severity-tag low-tag">${grade.severity_breakdown.low} Low</span>` : ''}
                        </div>
                        ` : ''}
                    </div>
                </div>
            `;
        };

        const recommendations = gradeReport.analysis?.recommendations || [];

        return `
            <div class="grade-report-section">
                <h2 class="section-title">📊 Infrastructure Report Card</h2>
                <div class="grade-cards-container">
                    ${renderGradeCard('Overall Grade', gradeReport.overall, '🎯')}
                    ${renderGradeCard('Cost Optimization', gradeReport.cost, '💰')}
                    ${renderGradeCard('IaC Security', gradeReport.security, '🔒')}
                    ${renderGradeCard('Container Security', gradeReport.container, '🐳')}
                </div>
                ${recommendations.length > 0 ? `
                <div class="recommendations-section">
                    <h3 class="recommendations-title">💡 Recommendations</h3>
                    <ul class="recommendations-list">
                        ${recommendations.map(rec => `<li>${rec}</li>`).join('')}
                    </ul>
                </div>
                ` : ''}
            </div>
        `;
    }

    submitFeedbackBtn.addEventListener('click', async () => {
        const review = feedbackReview.value.trim();
        const contact = feedbackContact.value.trim();

        if (selectedRating === 0) {
            alert('Please select a star rating');
            return;
        }

        if (!review) {
            alert('Please provide a review or suggestion');
            return;
        }

        submitFeedbackBtn.disabled = true;
        submitFeedbackBtn.textContent = 'Sending...';

        try {
            const response = await fetch('/api/feedback', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    rating: selectedRating,
                    review: review,
                    contact: contact
                })
            });

            const data = await response.json();

            if (!response.ok) throw new Error(data.error || 'Failed to send feedback');

            showToast('Thank you for your feedback!', 'success');
            feedbackModal.classList.add('hidden');
            // Reset form
            selectedRating = 0;
            highlightStars(0);
            feedbackReview.value = '';
            feedbackContact.value = '';
        } catch (error) {
            alert('Error: ' + error.message);
        } finally {
            submitFeedbackBtn.disabled = false;
            submitFeedbackBtn.textContent = 'Submit Feedback';
        }
    });
    // Footer Copy Logic
    document.addEventListener('click', (e) => {
        const copyBtn = e.target.closest('.copy-btn, .copy-btn-premium');
        if (copyBtn) {
            const textToCopy = copyBtn.getAttribute('data-copy');
            if (textToCopy) {
                navigator.clipboard.writeText(textToCopy).then(() => {
                    const originalContent = copyBtn.innerHTML;
                    const isPremium = copyBtn.classList.contains('copy-btn-premium');

                    if (isPremium) {
                        copyBtn.innerHTML = '<span>Copied!</span>';
                    } else {
                        copyBtn.textContent = 'Copied!';
                    }

                    copyBtn.classList.add('success');
                    setTimeout(() => {
                        copyBtn.innerHTML = originalContent;
                        copyBtn.classList.remove('success');
                    }, 2000);
                }).catch(err => {
                    console.error('Failed to copy: ', err);
                });
            }
        }
    });

    function formatScannerName(name) {
        if (!name) return 'Unknown';
        if (name === 'regex') return 'Cost';
        if (name === 'checkov') return 'Security';
        if (name === 'containers') return 'Containers';
        if (name === 'comprehensive' || name === 'both') return 'Comprehensive';
        return name;
    }

    function toggleImageCard(imageId) {
        const content = document.getElementById(imageId);
        const icon = document.getElementById(`${imageId}-icon`);

        if (content.style.display === 'none') {
            content.style.display = 'block';
            icon.textContent = '▼';
        } else {
            content.style.display = 'none';
            icon.textContent = '▶';
        }
    }

    function toggleSeverityGroup(severityGroupId) {
        const content = document.getElementById(severityGroupId);
        const icon = document.getElementById(`${severityGroupId}-icon`);

        if (content.style.display === 'none') {
            content.style.display = 'flex';
            icon.textContent = '▼';
        } else {
            content.style.display = 'none';
            icon.textContent = '▶';
        }
    }

    function toggleCVE(cveId) {
        const details = document.getElementById(cveId);
        const icon = document.getElementById(`${cveId}-icon`);

        if (details.style.display === 'none') {
            details.style.display = 'block';
            icon.textContent = '▲';
        } else {
            details.style.display = 'none';
            icon.textContent = '▼';
        }
    }
});
