function initApp() {
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
    const branchSelectionContainer = document.getElementById('branch-selection-container');
    const branchSelect = document.getElementById('branch-select');
    const repoLoader = document.getElementById('repo-loader');

    // Feedback Elements
    const feedbackModal = document.getElementById('feedback-modal');
    const openFeedbackBtn = document.getElementById('open-feedback-btn');
    const closeFeedbackBtn = document.getElementById('close-feedback-btn');
    const submitFeedbackBtn = document.getElementById('submit-feedback-btn');
    const stars = document.querySelectorAll('.star');
    const feedbackReview = document.getElementById('feedback-review');
    const feedbackContact = document.getElementById('feedback-contact');
    let selectedRating = 0;

    // Newsletter Elements
    const newsletterModal = document.getElementById('newsletter-modal');
    const closeNewsletterBtn = document.getElementById('close-newsletter-btn');
    const subscribeBtn = document.getElementById('subscribe-btn');
    const newsletterEmail = document.getElementById('newsletter-email');
    const newsletterConsent = document.getElementById('newsletter-consent');

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

    let progressInterval = null;
    let lastFetchedUrl = '';
    let fetchBranchesTimeout = null;

    // Check for CLI Injected Data (Standalone HTML Report)
    if (window.CLI_INJECTED_DATA || window.CLI_INJECTED_DATA_B64) {
        let data = null;
        if (window.CLI_INJECTED_DATA_B64) {
            try {
                // Decode base64 to string, then parse JSON.
                // Using decodeURIComponent(escape(atob())) to gracefully handle UTF-8 chars
                data = JSON.parse(decodeURIComponent(escape(atob(window.CLI_INJECTED_DATA_B64))));
            } catch (e) {
                console.error("Failed to decode Base64 CLI data", e);
                data = window.CLI_INJECTED_DATA;
            }
        } else {
            data = window.CLI_INJECTED_DATA;
        }

        if (!data) return;

        // Hide all web app specific UI parts
        if (scanInputContainer) scanInputContainer.style.display = 'none';
        if (document.querySelector('.tabs')) document.querySelector('.tabs').style.display = 'none';
        if (landingInfo) landingInfo.style.display = 'none';
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        if (newsletterModal) newsletterModal.style.display = 'none';
        if (feedbackModal) feedbackModal.style.display = 'none';

        const gradeReport = {
            overall: data.overall,
            cost: data.cost,
            security: data.security,
            container: data.container,
            analysis: data.analysis
        };

        displayResults(data.results, data.summary, data.metadata, gradeReport);

        // Setup PDF export for standalone mode
        setupPdfExport();

        // Hide elements that don't make sense in standalone report
        if (newScanBtn) newScanBtn.style.display = 'none';
        if (shareBtn) shareBtn.style.display = 'none';

        // Ensure container is correctly styled for full-width report
        if (mainContainer) mainContainer.classList.add('expanded');

        return; // Skip normal web app initialization
    }

    // Check scanner availability on load
    checkScannerStatus();
    loadSharedResults();

    // Trigger Newsletter Modal after 3 seconds if not already closed
    if (!localStorage.getItem('newsletter_closed') && !window.location.search.includes('scan_id')) {
        setTimeout(() => {
            if (newsletterModal) newsletterModal.classList.remove('hidden');
        }, 3000);
    }

    async function checkScannerStatus() {
        try {
            const response = await fetch('/api/scanner/status');
            if (!response.ok) return;

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

    function setupPdfExport() {
        const exportPdfBtn = document.getElementById('export-pdf-btn');
        if (!exportPdfBtn) return;

        // Remove old listener if any (to prevent doubles)
        const newBtn = exportPdfBtn.cloneNode(true);
        exportPdfBtn.parentNode.replaceChild(newBtn, exportPdfBtn);

        newBtn.addEventListener('click', async () => {
            if (!currentResults) return;

            newBtn.classList.add('exporting');
            newBtn.disabled = true;
            newBtn.innerHTML = '<span class="export-pdf-icon">⏳</span> Preparing PDF...';

            try {
                const html = buildPdfDocument(
                    currentResults,
                    currentSummary,
                    currentMetadata,
                    currentGradeReport
                );
                const win = window.open('', '_blank', 'width=1050,height=820,scrollbars=yes,resizable=yes');
                if (!win) {
                    alert('Popup blocked! Please allow popups for this site to export PDF.');
                    return;
                }
                win.document.open();
                win.document.write(html);
                win.document.close();
                win.focus();

                // Wait for fonts to load before printing for perfect rendering
                if (win.document.fonts) {
                    await win.document.fonts.ready;
                }
                win.print();
            } catch (e) {
                console.error('PDF generation error:', e);
                alert('Could not generate PDF: ' + e.message);
            } finally {
                newBtn.classList.remove('exporting');
                newBtn.disabled = false;
                newBtn.innerHTML = '<span class="export-pdf-icon">⬇</span> Export PDF';
            }
        });
    }

    async function loadSharedResults() {
        const urlParams = new URLSearchParams(window.location.search);
        const scanId = urlParams.get('scan_id');

        if (scanId) {
            resetScanProgress();

            // Hide tabs during shared result loading
            const tabsNav = document.querySelector('.tabs');
            if (tabsNav) tabsNav.style.display = 'none';
            tabContents.forEach(c => c.classList.remove('active'));

            const progressDetails = document.querySelector('.progress-bar-container');
            const stepsDetails = document.querySelector('.loading-steps');
            const titleEl = document.getElementById('loading-title');
            const statusEl = document.getElementById('loading-status');

            if (titleEl) titleEl.textContent = 'Loading Report';
            if (statusEl) statusEl.textContent = 'Fetching shared results from server...';
            if (progressDetails) progressDetails.style.display = 'none';
            if (stepsDetails) stepsDetails.style.display = 'none';

            loading.classList.remove('hidden');
            try {
                const response = await fetch(`/api/results/${scanId}`);

                let data = {};
                if (response.headers.get('content-type')?.includes('application/json')) {
                    data = await response.json();
                }

                if (!response.ok) throw new Error(data.error || `Failed to load results (${response.status})`);

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
                branch: (branchSelectionContainer && !branchSelectionContainer.classList.contains('hidden')) ? branchSelect.value : 'main',
                scanner: scannerTypeSelect ? scannerTypeSelect.value : 'comprehensive',
                recipient,
                is_private: isPrivate
            })
        });
    });

    // Branch Fetching Logic

    repoUrlInput.addEventListener('input', () => {
        const url = repoUrlInput.value.trim();
        if (url === lastFetchedUrl) return;

        if (fetchBranchesTimeout) clearTimeout(fetchBranchesTimeout);
        fetchBranchesTimeout = setTimeout(() => {
            fetchBranches(url);
        }, 1000);
    });

    // Also fetch on blur to be sure
    repoUrlInput.addEventListener('blur', () => {
        const url = repoUrlInput.value.trim();
        if (url !== lastFetchedUrl) {
            if (fetchBranchesTimeout) clearTimeout(fetchBranchesTimeout);
            fetchBranches(url);
        }
    });

    async function fetchBranches(url) {
        if (!url || (!url.startsWith('http') && !url.includes('git@'))) {
            if (branchSelectionContainer) branchSelectionContainer.classList.add('hidden');
            return;
        }

        lastFetchedUrl = url;
        if (repoLoader) repoLoader.classList.remove('hidden');
        if (branchSelectionContainer) branchSelectionContainer.classList.add('hidden');

        try {
            const response = await fetch('/api/repo/branches', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url })
            });

            if (!response.ok) throw new Error('Failed to fetch branches');

            const data = await response.json();
            if (data.branches && data.branches.length > 0) {
                if (branchSelect) {
                    branchSelect.innerHTML = data.branches.map(b => `<option value="${escapeHtml(b)}">${escapeHtml(b)}</option>`).join('');
                }
                if (branchSelectionContainer) branchSelectionContainer.classList.remove('hidden');
            }
        } catch (error) {
            console.error('Error fetching branches:', error);
            // Fallback: hide branch selection on error
            if (branchSelectionContainer) branchSelectionContainer.classList.add('hidden');
        } finally {
            if (repoLoader) repoLoader.classList.add('hidden');
        }
    }

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
            let data = {};
            if (response.headers.get('content-type')?.includes('application/json')) {
                data = await response.json();
            }

            if (!response.ok) throw new Error(data.error || `Server error (${response.status})`);

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

            // Restore tabs
            const tabsNav = document.querySelector('.tabs');
            if (tabsNav) tabsNav.style.display = 'flex';
            const activeTabBtn = document.querySelector('.tab-btn.active');
            if (activeTabBtn) {
                const targetTab = activeTabBtn.dataset.tab;
                const tabEl = document.getElementById(`${targetTab}-tab`);
                if (tabEl) tabEl.classList.add('active');
            }

            // Reset results
            currentResults = null;
            currentSummary = null;
            currentMetadata = null;
            currentGradeReport = null;
            if (mainContainer) mainContainer.classList.remove('expanded');
        });
    }

    // Export PDF Button
    setupPdfExport();


    function resetScanProgress() {
        if (progressInterval) clearInterval(progressInterval);
        const steps = ['step-clone', 'step-init', 'step-iac', 'step-containers', 'step-report'];
        steps.forEach(id => {
            const el = document.getElementById(id);
            if (el) {
                el.classList.remove('active', 'completed');
                const icon = el.querySelector('.step-icon');
                if (icon) icon.textContent = '⏳';
            }
        });
        const bar = document.getElementById('progress-bar-fill');
        if (bar) bar.style.width = '0%';
        const status = document.getElementById('loading-status');
        if (status) status.textContent = 'Connecting to repository...';

        const titleEl = document.getElementById('loading-title');
        if (titleEl) titleEl.textContent = 'Analyzing Infrastructure';

        const progressDetails = document.querySelector('.progress-bar-container');
        const stepsDetails = document.querySelector('.loading-steps');
        if (progressDetails) progressDetails.style.display = 'block';
        if (stepsDetails) stepsDetails.style.display = 'flex';
    }

    function startScanProgress() {
        resetScanProgress();
        let progress = 0;
        const bar = document.getElementById('progress-bar-fill');
        const status = document.getElementById('loading-status');

        const steps = [
            { id: 'step-clone', threshold: 15, text: 'Cloning repository...' },
            { id: 'step-init', threshold: 30, text: 'Initializing scanners...' },
            { id: 'step-iac', threshold: 60, text: 'Running IaC Security & Cost Audit...' },
            { id: 'step-containers', threshold: 85, text: 'Scanning for container vulnerabilities...' },
            { id: 'step-report', threshold: 95, text: 'Finalizing report...' }
        ];

        let currentStepIdx = 0;

        progressInterval = setInterval(() => {
            // Slower progress as it gets higher to avoid "finishing" too early
            const increment = progress < 70 ? 0.8 : (progress < 90 ? 0.3 : 0.05);
            progress = Math.min(progress + increment, 98);

            if (bar) bar.style.width = `${progress}%`;

            // Update steps based on progress
            steps.forEach((step, idx) => {
                const el = document.getElementById(step.id);
                if (!el) return;

                if (progress >= step.threshold) {
                    if (!el.classList.contains('completed')) {
                        el.classList.add('completed');
                        el.classList.remove('active');
                        const icon = el.querySelector('.step-icon');
                        if (icon) icon.textContent = '✅';
                    }
                } else {
                    // Check if this should be the active step
                    const prevStepCompleted = idx === 0 || progress >= steps[idx - 1].threshold;
                    if (prevStepCompleted && !el.classList.contains('completed')) {
                        if (!el.classList.contains('active')) {
                            el.classList.add('active');
                            if (status) status.textContent = step.text;
                            currentStepIdx = idx;
                        }
                    }
                }
            });
        }, 100);
    }

    function completeScanProgress() {
        if (progressInterval) clearInterval(progressInterval);
        const bar = document.getElementById('progress-bar-fill');
        if (bar) {
            bar.style.width = '100%';
            bar.style.transition = 'width 0.2s ease-out';
        }

        const steps = ['step-clone', 'step-init', 'step-iac', 'step-containers', 'step-report'];
        steps.forEach(id => {
            const el = document.getElementById(id);
            if (el) {
                el.classList.add('completed');
                el.classList.remove('active');
                const icon = el.querySelector('.step-icon');
                if (icon) icon.textContent = '✅';
            }
        });
        const status = document.getElementById('loading-status');
        if (status) status.textContent = 'Scan completed successfully!';
    }

    async function performScan(url, options) {
        loading.classList.remove('hidden');
        resultsArea.classList.add('hidden');

        // Hide tabs and active content to avoid "empty bar" during loading
        const tabsNav = document.querySelector('.tabs');
        if (tabsNav) tabsNav.style.display = 'none';
        tabContents.forEach(c => c.classList.remove('active'));

        if (scanInputContainer) scanInputContainer.classList.add('hidden'); // Hide input
        resultsContent.innerHTML = '';
        currentScanId = null;

        startScanProgress();

        try {
            const response = await fetch(url, options);

            let data = {};
            if (response.headers.get('content-type')?.includes('application/json')) {
                data = await response.json();
            }

            if (!response.ok) {
                throw new Error(data.error || `Scan failed (${response.status})`);
            }

            completeScanProgress();

            // Small delay to let the user see the "100%" state
            await new Promise(resolve => setTimeout(resolve, 500));

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
            if (progressInterval) clearInterval(progressInterval);
            showToast(error.message);

            // Restore tabs and active content on failure
            const tabsNav = document.querySelector('.tabs');
            if (tabsNav) tabsNav.style.display = 'flex';
            const activeTabBtn = document.querySelector('.tab-btn.active');
            if (activeTabBtn) {
                const targetTab = activeTabBtn.dataset.tab;
                const tabEl = document.getElementById(`${targetTab}-tab`);
                if (tabEl) tabEl.classList.add('active');
            }

            if (scanInputContainer) scanInputContainer.classList.remove('hidden'); // Show input again on failure
            if (landingInfo) landingInfo.classList.remove('collapsed'); // Show info cards again on failure
            if (mainContainer) mainContainer.classList.remove('expanded');
        } finally {
            loading.classList.add('hidden');
            resetScanProgress();
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
            if (!response.ok) {
                console.warn(`Auto-save failed with status ${response.status}`);
                return;
            }

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
            if (!response.ok) throw new Error(`Server error (${response.status})`);

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
                ${scan.branch ? `<span class="scan-branch"><svg style="display:inline-block;vertical-align:text-bottom;margin-right:4px;" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="6" y1="3" x2="6" y2="15"></line><circle cx="18" cy="6" r="3"></circle><circle cx="6" cy="18" r="3"></circle><path d="M18 9a9 9 0 0 1-9 9"></path></svg>${escapeHtml(scan.branch)}</span>` : ''}
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
                                <a href="${escapeHtml(metadata.repository_url)}" target="_blank" rel="noopener noreferrer">
                                    ${escapeHtml(metadata.repository_name || metadata.repository_url)}
                                </a>
                            </span>
                        </div>

                        ${metadata.scan_timestamp ? `
                        <div class="metadata-item">
                            <span class="metadata-label">Scanned:</span>
                            <span class="metadata-value">${escapeHtml(metadata.scan_timestamp)}</span>
                        </div>
                        ` : ''}
                        ${metadata.branch ? `
                        <div class="metadata-item">
                            <span class="metadata-label"><svg style="display:inline-block;vertical-align:text-bottom;margin-right:4px;opacity:0.7;" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="6" y1="3" x2="6" y2="15"></line><circle cx="18" cy="6" r="3"></circle><circle cx="6" cy="18" r="3"></circle><path d="M18 9a9 9 0 0 1-9 9"></path></svg> Branch:</span>
                            <span class="metadata-value">${escapeHtml(metadata.branch)}</span>
                        </div>
                        ` : ''}
                        ${metadata.resource_count ? `
                        <div class="metadata-item">
                            <span class="metadata-label">Resources Scanned:</span>
                            <span class="metadata-value">${escapeHtml(metadata.resource_count)}</span>
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
        let summaryHtml = '';
        if (summary) {
            summaryHtml = `
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

        resultsContent.innerHTML = metadataHtml + gradeHtml + summaryHtml;

        // Determine which sections to show based on scanner_used
        const scannerUsed = (summary && summary.scanner_used) ? summary.scanner_used : 'comprehensive';
        const isComprehensive = scannerUsed === 'comprehensive' || scannerUsed === 'both' || scannerUsed === 'all';
        const usedScanners = scannerUsed.split(',').map(s => s.trim());

        const showCost = isComprehensive || usedScanners.includes('regex');
        const showIaC = isComprehensive || usedScanners.includes('checkov');
        const showContainers = isComprehensive || usedScanners.includes('containers');

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
        if (showCost) {
            html += `
                <div class="results-column">
                    <h3 class="column-title cost">💰 Cost Optimization</h3>
                    ${costFindings.length > 0 ? renderFindingsList(costFindings) : '<div class="empty-state">✅ No cost issues found.</div>'}
                </div>
            `;
        }

        // IaC Security Column
        if (showIaC) {
            html += `
                <div class="results-column">
                    <h3 class="column-title security">🔒 IaC Security</h3>
                    ${iacSecurityFindings.length > 0 ? renderFindingsList(iacSecurityFindings) : '<div class="empty-state">✅ No IaC security issues found.</div>'}
                </div>
            `;
        }

        // Container Security Column
        if (showContainers) {
            html += `
                <div class="results-column">
                    <h3 class="column-title security">🐳 Container Security</h3>
                    ${containerFindings.length > 0 ? renderContainerFindings(containerFindings) : '<div class="empty-state">✅ No container vulnerabilities found.</div>'}
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
                        <span class="finding-title">${escapeHtml(first.rule_name)}</span>
                        <span class="severity-badge ${first.severity}">${first.severity}</span>
                    </div>
                ${first.description && first.description !== 'null' ? `
                <div class="finding-detail" title="${escapeHtml(first.full_description || first.description)}">
                    <strong>Problem:</strong> ${escapeHtml(first.description)}
                </div>
                ` : ''}
                ${first.scanner === 'regex' ? `
                <div class="finding-detail">
                    <strong>Potential Savings:</strong> <span style="color: var(--success); font-weight: 600;">${escapeHtml(first.estimated_savings)}</span>
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
                                                        <span class="cve-id">${escapeHtml(v.rule_id)}</span>
                                                        <span class="cve-package">${escapeHtml(v.package)}@${escapeHtml(v.package_version)}${v.fix_version && v.fix_version !== 'N/A' && v.fix_version !== null ? ` → ${escapeHtml(v.fix_version)}` : ''}</span>
                                                        <span class="cve-short-desc">${v.description ? escapeHtml(v.description.substring(0, 60) + (v.description.length > 60 ? '...' : '')) : ''}</span>
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
                                                            <strong>Package:</strong> ${escapeHtml(v.package)}@${escapeHtml(v.package_version)}
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
        if (text === null || text === undefined) return '';
        return String(text)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    function truncateText(text, maxLength = 100) {
        if (text === null || text === undefined) return '';
        const str = String(text);
        if (str.length <= maxLength) return str;
        return str.substring(0, maxLength) + '...';
    }

    function linkifyUrls(text, maxLength = null) {
        if (text === null || text === undefined) return '';
        const str = String(text);

        // First escape HTML to prevent XSS
        let escaped = escapeHtml(str);

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
        if (maxLength && str.length > maxLength && !str.match(urlPattern)) {
            escaped = truncateText(str, maxLength);
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
            if (!grade) return '';

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
                        ${recommendations.map(rec => `<li>${escapeHtml(rec)}</li>`).join('')}
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

            let data = {};
            if (response.headers.get('content-type')?.includes('application/json')) {
                data = await response.json();
            }

            if (!response.ok) throw new Error(data.error || `Failed to send feedback (${response.status})`);

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


    // Newsletter Event Listeners
    if (closeNewsletterBtn) {
        closeNewsletterBtn.onclick = () => {
            newsletterModal.classList.add('hidden');
            localStorage.setItem('newsletter_closed', 'true');
        };
    }

    if (subscribeBtn) {
        subscribeBtn.onclick = async () => {
            const email = newsletterEmail.value.trim();
            const consent = newsletterConsent.checked;

            if (!email || !email.includes('@')) {
                showToast('Please enter a valid email address');
                return;
            }

            if (!consent) {
                showToast('Please agree to the consent terms');
                return;
            }

            subscribeBtn.disabled = true;
            subscribeBtn.textContent = 'Subscribing...';

            try {
                const response = await fetch('/api/subscribe', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ email: email })
                });

                let data = {};
                if (response.headers.get('content-type')?.includes('application/json')) {
                    data = await response.json();
                }

                if (response.ok) {
                    showToast(data.message || 'Thank you for subscribing!', 'success');
                    newsletterModal.classList.add('hidden');
                    localStorage.setItem('newsletter_closed', 'true');
                } else {
                    throw new Error(data.error || `Subscription failed (${response.status})`);
                }
            } catch (e) {
                showToast(e.message || 'Subscription failed. Please try again.');
            } finally {
                subscribeBtn.disabled = false;
                subscribeBtn.innerHTML = '<span>✉️</span> Subscribe Now';
            }
        };
    }
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initApp);
} else {
    initApp();
}

function toggleImageCard(imageId) {
    const content = document.getElementById(imageId);
    const icon = document.getElementById(`${imageId}-icon`);

    if (content.style.display === 'none') {
        content.style.display = 'block';
        if (icon) icon.textContent = '▼';
    } else {
        content.style.display = 'none';
        if (icon) icon.textContent = '▶';
    }
}

function toggleSeverityGroup(severityGroupId) {
    const content = document.getElementById(severityGroupId);
    const icon = document.getElementById(`${severityGroupId}-icon`);

    if (content.style.display === 'none') {
        content.style.display = 'flex';
        if (icon) icon.textContent = '▼';
    } else {
        content.style.display = 'none';
        if (icon) icon.textContent = '▶';
    }
}

function toggleCVE(cveId) {
    const details = document.getElementById(cveId);
    const icon = document.getElementById(`${cveId}-icon`);

    if (details.style.display === 'none') {
        details.style.display = 'block';
        if (icon) icon.textContent = '▲';
    } else {
        details.style.display = 'none';
        if (icon) icon.textContent = '▼';
    }
}
