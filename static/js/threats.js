/**
 * Threats Management JavaScript Module
 * Handles threat detection, analysis, and management functionality
 */

let threatUpdateInterval = null;
let selectedThreats = new Set();
let currentFilter = {
    search: '',
    level: '',
    status: '',
    dateRange: ''
};

/**
 * Initialize threats page functionality
 */
function initializeThreatsPage() {
    // Initialize threat monitoring
    startThreatMonitoring();
    
    // Initialize filter functionality
    initializeFilters();
    
    // Initialize bulk actions
    initializeBulkActions();
    
    // Initialize threat analysis
    initializeThreatAnalysis();
    
    // Load initial threat data
    loadThreatStatistics();
    
    console.log('Threats page initialized successfully');
}

/**
 * Start real-time threat monitoring
 */
function startThreatMonitoring() {
    // Update threat counts every 30 seconds
    threatUpdateInterval = setInterval(() => {
        updateThreatCounts();
        refreshThreatTable();
    }, 30000);
    
    // Listen for visibility changes
    document.addEventListener('visibilitychange', function() {
        if (document.hidden) {
            stopThreatMonitoring();
        } else {
            startThreatMonitoring();
        }
    });
}

/**
 * Stop threat monitoring
 */
function stopThreatMonitoring() {
    if (threatUpdateInterval) {
        clearInterval(threatUpdateInterval);
        threatUpdateInterval = null;
    }
}

/**
 * Initialize filter functionality
 */
function initializeFilters() {
    const searchInput = document.getElementById('searchInput');
    const levelFilter = document.getElementById('levelFilter');
    const statusFilter = document.getElementById('statusFilter');
    const dateFilter = document.getElementById('dateFilter');
    
    // Debounced search
    if (searchInput) {
        searchInput.addEventListener('input', debounce((e) => {
            currentFilter.search = e.target.value.toLowerCase();
            applyFilters();
        }, 300));
    }
    
    // Filter dropdowns
    if (levelFilter) {
        levelFilter.addEventListener('change', (e) => {
            currentFilter.level = e.target.value;
            applyFilters();
        });
    }
    
    if (statusFilter) {
        statusFilter.addEventListener('change', (e) => {
            currentFilter.status = e.target.value;
            applyFilters();
        });
    }
    
    if (dateFilter) {
        dateFilter.addEventListener('change', (e) => {
            currentFilter.dateRange = e.target.value;
            applyFilters();
        });
    }
}

/**
 * Initialize bulk actions functionality
 */
function initializeBulkActions() {
    const selectAllCheckbox = document.getElementById('selectAllCheckbox');
    
    if (selectAllCheckbox) {
        selectAllCheckbox.addEventListener('change', (e) => {
            const isChecked = e.target.checked;
            const visibleCheckboxes = document.querySelectorAll('.threat-checkbox:not([style*="display: none"])');
            
            visibleCheckboxes.forEach(checkbox => {
                checkbox.checked = isChecked;
                const threatId = checkbox.value;
                
                if (isChecked) {
                    selectedThreats.add(threatId);
                } else {
                    selectedThreats.delete(threatId);
                }
            });
            
            updateBulkActionButtons();
        });
    }
    
    // Individual checkboxes
    document.querySelectorAll('.threat-checkbox').forEach(checkbox => {
        checkbox.addEventListener('change', (e) => {
            const threatId = e.target.value;
            
            if (e.target.checked) {
                selectedThreats.add(threatId);
            } else {
                selectedThreats.delete(threatId);
                document.getElementById('selectAllCheckbox').checked = false;
            }
            
            updateBulkActionButtons();
        });
    });
}

/**
 * Initialize threat analysis functionality
 */
function initializeThreatAnalysis() {
    // Initialize threat detail modals
    initializeThreatModals();
    
    // Initialize threat action handlers
    initializeThreatActions();
}

/**
 * Initialize threat detail modals
 */
function initializeThreatModals() {
    const threatModal = document.getElementById('threatModal');
    if (threatModal) {
        threatModal.addEventListener('show.bs.modal', (e) => {
            const button = e.relatedTarget;
            const threatId = button.getAttribute('data-threat-id');
            loadThreatDetails(threatId);
        });
    }
}

/**
 * Initialize threat action handlers
 */
function initializeThreatActions() {
    // Quarantine buttons
    document.querySelectorAll('[data-action="quarantine"]').forEach(button => {
        button.addEventListener('click', (e) => {
            const threatId = e.target.closest('button').getAttribute('data-threat-id');
            handleQuarantineAction(threatId);
        });
    });
    
    // Restore buttons
    document.querySelectorAll('[data-action="restore"]').forEach(button => {
        button.addEventListener('click', (e) => {
            const threatId = e.target.closest('button').getAttribute('data-threat-id');
            handleRestoreAction(threatId);
        });
    });
    
    // False positive buttons
    document.querySelectorAll('[data-action="false-positive"]').forEach(button => {
        button.addEventListener('click', (e) => {
            const threatId = e.target.closest('button').getAttribute('data-threat-id');
            handleFalsePositiveReport(threatId);
        });
    });
}

/**
 * Apply current filters to threat table
 */
function applyFilters() {
    const rows = document.querySelectorAll('.threat-row');
    let visibleCount = 0;
    
    rows.forEach(row => {
        const shouldShow = shouldShowThreatRow(row);
        row.style.display = shouldShow ? '' : 'none';
        
        if (shouldShow) {
            visibleCount++;
        }
    });
    
    // Update filter results info
    updateFilterResults(visibleCount);
    
    // Reset select all checkbox
    document.getElementById('selectAllCheckbox').checked = false;
    selectedThreats.clear();
    updateBulkActionButtons();
}

/**
 * Determine if threat row should be shown based on filters
 */
function shouldShowThreatRow(row) {
    const filePath = row.querySelector('td:nth-child(2)').textContent.toLowerCase();
    const threatLevel = row.dataset.threatLevel;
    const threatStatus = row.dataset.status;
    const detectionDate = new Date(row.dataset.detectionDate || 0);
    
    // Search filter
    if (currentFilter.search && !filePath.includes(currentFilter.search)) {
        return false;
    }
    
    // Level filter
    if (currentFilter.level && threatLevel !== currentFilter.level) {
        return false;
    }
    
    // Status filter
    if (currentFilter.status && threatStatus !== currentFilter.status) {
        return false;
    }
    
    // Date filter
    if (currentFilter.dateRange && !isWithinDateRange(detectionDate, currentFilter.dateRange)) {
        return false;
    }
    
    return true;
}

/**
 * Check if date is within specified range
 */
function isWithinDateRange(date, range) {
    const now = new Date();
    let cutoff;
    
    switch (range) {
        case 'today':
            cutoff = new Date(now.getFullYear(), now.getMonth(), now.getDate());
            break;
        case 'week':
            cutoff = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
            break;
        case 'month':
            cutoff = new Date(now.getFullYear(), now.getMonth(), 1);
            break;
        default:
            return true;
    }
    
    return date >= cutoff;
}

/**
 * Update filter results display
 */
function updateFilterResults(visibleCount) {
    const resultsInfo = document.getElementById('filterResults');
    if (resultsInfo) {
        const totalCount = document.querySelectorAll('.threat-row').length;
        resultsInfo.textContent = visibleCount < totalCount ? 
            `Showing ${visibleCount} of ${totalCount} threats` : '';
    }
}

/**
 * Update bulk action buttons based on selection
 */
function updateBulkActionButtons() {
    const selectedCount = selectedThreats.size;
    const bulkActions = document.querySelectorAll('.bulk-action');
    
    bulkActions.forEach(button => {
        button.disabled = selectedCount === 0;
        const countSpan = button.querySelector('.selection-count');
        if (countSpan) {
            countSpan.textContent = selectedCount;
        }
    });
}

/**
 * Load threat statistics
 */
async function loadThreatStatistics() {
    try {
        const response = await fetch('/api/threat_stats');
        if (!response.ok) throw new Error('Failed to load threat statistics');
        
        const stats = await response.json();
        updateThreatStatistics(stats);
        
    } catch (error) {
        console.error('Error loading threat statistics:', error);
        showErrorState('Unable to load threat statistics');
    }
}

/**
 * Update threat count displays
 */
async function updateThreatCounts() {
    try {
        const response = await fetch('/api/threat_counts');
        if (!response.ok) throw new Error('Failed to update threat counts');
        
        const counts = await response.json();
        
        // Update count displays
        const countElements = {
            'criticalCount': counts.critical || 0,
            'highCount': counts.high || 0,
            'mediumCount': counts.medium || 0,
            'lowCount': counts.low || 0
        };
        
        Object.entries(countElements).forEach(([id, count]) => {
            const element = document.getElementById(id);
            if (element) {
                animateCounter(element, count);
            }
        });
        
    } catch (error) {
        console.error('Error updating threat counts:', error);
    }
}

/**
 * Refresh threat table data
 */
async function refreshThreatTable() {
    try {
        const response = await fetch('/api/threats/recent');
        if (!response.ok) throw new Error('Failed to refresh threat table');
        
        const threats = await response.json();
        
        if (threats.length > 0) {
            // Check for new threats and show notifications
            checkForNewThreats(threats);
        }
        
    } catch (error) {
        console.error('Error refreshing threat table:', error);
    }
}

/**
 * Check for new threats and notify user
 */
function checkForNewThreats(currentThreats) {
    // In a real implementation, this would compare against previously loaded threats
    // For now, we'll just check if there are any high/critical threats
    const highPriorityThreats = currentThreats.filter(t => 
        t.threat_level === 'critical' || t.threat_level === 'high'
    );
    
    if (highPriorityThreats.length > 0) {
        const message = `${highPriorityThreats.length} high-priority threat${highPriorityThreats.length > 1 ? 's' : ''} detected!`;
        showNotification('New Threats Detected', message, 'warning');
    }
}

/**
 * Load detailed threat information
 */
async function loadThreatDetails(threatId) {
    const modalBody = document.getElementById('threatModalBody');
    if (!modalBody) return;
    
    // Show loading state
    modalBody.innerHTML = `
        <div class="text-center py-4">
            <div class="spinner-border text-primary" role="status">
                <span class="visually-hidden">Loading...</span>
            </div>
            <p class="mt-2 text-muted">Loading threat details...</p>
        </div>
    `;
    
    try {
        const response = await fetch(`/api/threats/${threatId}/details`);
        if (!response.ok) throw new Error('Failed to load threat details');
        
        const threat = await response.json();
        displayThreatDetails(threat);
        
    } catch (error) {
        console.error('Error loading threat details:', error);
        modalBody.innerHTML = `
            <div class="alert alert-danger">
                <i class="bi bi-exclamation-triangle me-2"></i>
                Failed to load threat details: ${error.message}
            </div>
        `;
    }
}

/**
 * Display threat details in modal
 */
function displayThreatDetails(threat) {
    const modalBody = document.getElementById('threatModalBody');
    const modalQuarantineBtn = document.getElementById('modalQuarantineBtn');
    
    const riskFactors = threat.risk_factors || [];
    const metadata = threat.metadata || {};
    
    modalBody.innerHTML = `
        <div class="row g-3">
            <div class="col-12">
                <h6 class="border-bottom pb-2 mb-3">
                    <i class="bi bi-file-earmark-text me-2"></i>
                    File Information
                </h6>
                <table class="table table-dark table-sm">
                    <tr>
                        <th width="30%">Full Path:</th>
                        <td class="font-monospace">${escapeHtml(threat.file_path)}</td>
                    </tr>
                    <tr>
                        <th>File Size:</th>
                        <td>${formatBytes(threat.file_size || 0)}</td>
                    </tr>
                    <tr>
                        <th>File Hash:</th>
                        <td class="font-monospace">${escapeHtml(threat.file_hash || 'N/A')}</td>
                    </tr>
                    <tr>
                        <th>Created:</th>
                        <td>${formatDateTime(metadata.created || threat.detected_at)}</td>
                    </tr>
                    <tr>
                        <th>Modified:</th>
                        <td>${formatDateTime(metadata.modified || threat.detected_at)}</td>
                    </tr>
                    <tr>
                        <th>Permissions:</th>
                        <td class="font-monospace">${escapeHtml(metadata.permissions || 'N/A')}</td>
                    </tr>
                </table>
            </div>
            
            <div class="col-md-6">
                <h6 class="border-bottom pb-2 mb-3">
                    <i class="bi bi-shield-exclamation me-2"></i>
                    Threat Analysis
                </h6>
                <table class="table table-dark table-sm">
                    <tr>
                        <th>Threat Type:</th>
                        <td>${escapeHtml(threat.threat_type || 'Unknown')}</td>
                    </tr>
                    <tr>
                        <th>Severity:</th>
                        <td>
                            <span class="badge bg-${getThreatLevelColor(threat.threat_level)}">
                                ${threat.threat_level.toUpperCase()}
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <th>Confidence:</th>
                        <td>${(threat.confidence_score * 100).toFixed(1)}%</td>
                    </tr>
                    <tr>
                        <th>Detection Time:</th>
                        <td>${formatDateTime(threat.detected_at)}</td>
                    </tr>
                    <tr>
                        <th>Detection Method:</th>
                        <td>ML Analysis, Entropy Check</td>
                    </tr>
                    <tr>
                        <th>Status:</th>
                        <td>
                            <span class="badge bg-${threat.quarantined ? 'warning' : 'danger'}">
                                ${threat.quarantined ? 'Quarantined' : 'Active'}
                            </span>
                        </td>
                    </tr>
                </table>
            </div>
            
            <div class="col-md-6">
                <h6 class="border-bottom pb-2 mb-3">
                    <i class="bi bi-exclamation-triangle me-2"></i>
                    Risk Factors
                </h6>
                ${riskFactors.length > 0 ? `
                    <ul class="list-unstyled">
                        ${riskFactors.map(factor => `
                            <li class="mb-2">
                                <i class="bi bi-arrow-right text-warning me-2"></i>
                                ${escapeHtml(factor)}
                            </li>
                        `).join('')}
                    </ul>
                ` : '<p class="text-muted">No specific risk factors identified.</p>'}
                
                <h6 class="border-bottom pb-2 mb-3 mt-4">
                    <i class="bi bi-graph-up me-2"></i>
                    Analysis Metrics
                </h6>
                <div class="mb-2">
                    <small class="text-muted">File Entropy:</small>
                    <div class="progress" style="height: 6px;">
                        <div class="progress-bar ${(metadata.entropy || 0) > 7.5 ? 'bg-danger' : 'bg-success'}" 
                             style="width: ${((metadata.entropy || 0) / 8) * 100}%"></div>
                    </div>
                    <small class="text-muted">${(metadata.entropy || 0).toFixed(2)} / 8.0</small>
                </div>
                
                <div class="mb-2">
                    <small class="text-muted">ML Confidence:</small>
                    <div class="progress" style="height: 6px;">
                        <div class="progress-bar bg-primary" 
                             style="width: ${(threat.confidence_score * 100)}%"></div>
                    </div>
                    <small class="text-muted">${(threat.confidence_score * 100).toFixed(1)}%</small>
                </div>
            </div>
        </div>
    `;
    
    // Update quarantine button
    if (modalQuarantineBtn) {
        if (threat.quarantined) {
            modalQuarantineBtn.textContent = 'Already Quarantined';
            modalQuarantineBtn.disabled = true;
            modalQuarantineBtn.className = 'btn btn-secondary';
        } else {
            modalQuarantineBtn.textContent = 'Quarantine Threat';
            modalQuarantineBtn.disabled = false;
            modalQuarantineBtn.className = 'btn btn-warning';
            modalQuarantineBtn.onclick = () => handleQuarantineAction(threat.id);
        }
    }
}

/**
 * Handle quarantine action
 */
async function handleQuarantineAction(threatId) {
    const confirmation = confirm(
        'Quarantine this threat?\n\n' +
        '• The file will be safely isolated\n' +
        '• A backup will be created automatically\n' +
        '• The action can be reversed later\n\n' +
        'Continue with quarantine?'
    );
    
    if (!confirmation) return;
    
    try {
        showLoadingState('Quarantining threat...');
        
        const response = await fetch(`/quarantine_threat/${threatId}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCSRFToken()
            }
        });
        
        if (!response.ok) throw new Error('Quarantine request failed');
        
        // Redirect will be handled by the server
        showToast('Threat quarantined successfully!', 'success');
        
        // Update UI immediately
        updateThreatRowStatus(threatId, 'quarantined');
        
        // Close modal if open
        const modal = bootstrap.Modal.getInstance(document.getElementById('threatModal'));
        if (modal) modal.hide();
        
    } catch (error) {
        console.error('Quarantine error:', error);
        showToast(`Quarantine failed: ${error.message}`, 'danger');
    } finally {
        hideLoadingState();
    }
}

/**
 * Handle restore action
 */
async function handleRestoreAction(threatId) {
    const confirmation = confirm(
        'Restore this file from quarantine?\n\n' +
        '• The file will be moved back to its original location\n' +
        '• This action should only be done if you\'re sure the file is safe\n\n' +
        'Continue with restore?'
    );
    
    if (!confirmation) return;
    
    try {
        showLoadingState('Restoring file...');
        
        const response = await fetch(`/api/threats/${threatId}/restore`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCSRFToken()
            }
        });
        
        if (!response.ok) throw new Error('Restore request failed');
        
        const result = await response.json();
        
        if (result.success) {
            showToast('File restored successfully!', 'success');
            updateThreatRowStatus(threatId, 'active');
        } else {
            throw new Error(result.error || 'Restore failed');
        }
        
    } catch (error) {
        console.error('Restore error:', error);
        showToast(`Restore failed: ${error.message}`, 'danger');
    } finally {
        hideLoadingState();
    }
}

/**
 * Handle false positive report
 */
async function handleFalsePositiveReport(threatId) {
    const reason = prompt(
        'Report this detection as a false positive?\n\n' +
        'Please provide a brief reason (optional):\n' +
        '• File is actually safe\n' +
        '• Known legitimate software\n' +
        '• Other (please specify)'
    );
    
    if (reason === null) return; // User cancelled
    
    try {
        const response = await fetch(`/api/threats/${threatId}/report-false-positive`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCSRFToken()
            },
            body: JSON.stringify({
                reason: reason || 'No reason provided'
            })
        });
        
        if (!response.ok) throw new Error('Failed to report false positive');
        
        const result = await response.json();
        
        if (result.success) {
            showToast('Thank you for the feedback! This detection has been reported for review.', 'info');
        } else {
            throw new Error(result.error || 'Report failed');
        }
        
    } catch (error) {
        console.error('False positive report error:', error);
        showToast(`Report failed: ${error.message}`, 'danger');
    }
}

/**
 * Update threat row status in UI
 */
function updateThreatRowStatus(threatId, status) {
    const row = document.querySelector(`[data-threat-id="${threatId}"]`);
    if (!row) return;
    
    // Update dataset
    row.dataset.status = status;
    
    // Update status badge
    const statusBadge = row.querySelector('td:nth-child(5) .badge');
    if (statusBadge) {
        if (status === 'quarantined') {
            statusBadge.className = 'badge bg-warning';
            statusBadge.innerHTML = '<i class="bi bi-shield"></i> Quarantined';
        } else {
            statusBadge.className = 'badge bg-danger';
            statusBadge.innerHTML = '<i class="bi bi-exclamation-triangle"></i> Active';
        }
    }
    
    // Update action buttons
    const actionButtons = row.querySelector('td:nth-child(6) .btn-group');
    if (actionButtons) {
        const quarantineBtn = actionButtons.querySelector('[data-action="quarantine"]');
        const restoreBtn = actionButtons.querySelector('[data-action="restore"]');
        
        if (status === 'quarantined') {
            if (quarantineBtn) quarantineBtn.style.display = 'none';
            if (restoreBtn) restoreBtn.style.display = 'inline-block';
        } else {
            if (quarantineBtn) quarantineBtn.style.display = 'inline-block';
            if (restoreBtn) restoreBtn.style.display = 'none';
        }
    }
}

/**
 * Bulk quarantine selected threats
 */
async function bulkQuarantine() {
    if (selectedThreats.size === 0) {
        showToast('No threats selected for quarantine.', 'warning');
        return;
    }
    
    const confirmation = confirm(
        `Quarantine ${selectedThreats.size} selected threat(s)?\n\n` +
        '• Files will be safely isolated\n' +
        '• Backups will be created automatically\n' +
        '• Actions can be reversed later\n\n' +
        'Continue with bulk quarantine?'
    );
    
    if (!confirmation) return;
    
    try {
        showLoadingState(`Quarantining ${selectedThreats.size} threats...`);
        
        const promises = Array.from(selectedThreats).map(threatId => 
            fetch(`/quarantine_threat/${threatId}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': getCSRFToken()
                }
            })
        );
        
        const results = await Promise.allSettled(promises);
        
        let successCount = 0;
        let failCount = 0;
        
        results.forEach((result, index) => {
            const threatId = Array.from(selectedThreats)[index];
            
            if (result.status === 'fulfilled' && result.value.ok) {
                successCount++;
                updateThreatRowStatus(threatId, 'quarantined');
            } else {
                failCount++;
            }
        });
        
        if (successCount > 0) {
            showToast(`${successCount} threat(s) quarantined successfully!`, 'success');
        }
        
        if (failCount > 0) {
            showToast(`${failCount} threat(s) failed to quarantine.`, 'warning');
        }
        
        // Clear selection
        selectedThreats.clear();
        document.getElementById('selectAllCheckbox').checked = false;
        document.querySelectorAll('.threat-checkbox').forEach(cb => cb.checked = false);
        updateBulkActionButtons();
        
    } catch (error) {
        console.error('Bulk quarantine error:', error);
        showToast(`Bulk quarantine failed: ${error.message}`, 'danger');
    } finally {
        hideLoadingState();
    }
}

/**
 * Export threats data
 */
function exportThreats() {
    const threats = [];
    document.querySelectorAll('.threat-row').forEach(row => {
        if (row.style.display !== 'none') {
            threats.push({
                id: row.dataset.threatId,
                filePath: row.querySelector('td:nth-child(2)').textContent.trim(),
                threatLevel: row.dataset.threatLevel,
                status: row.dataset.status,
                detectionDate: row.dataset.detectionDate
            });
        }
    });
    
    const csvContent = convertToCSV(threats);
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = `threats_report_${new Date().toISOString().split('T')[0]}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    showToast('Threats report exported successfully!', 'success');
}

/**
 * Convert threats data to CSV format
 */
function convertToCSV(data) {
    const headers = ['ID', 'File Path', 'Threat Level', 'Status', 'Detection Date'];
    const rows = data.map(threat => [
        threat.id,
        threat.filePath,
        threat.threatLevel,
        threat.status,
        threat.detectionDate
    ]);
    
    return [headers, ...rows]
        .map(row => row.map(cell => `"${cell}"`).join(','))
        .join('\n');
}

// Utility functions

function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

function getThreatLevelColor(level) {
    const colors = {
        'critical': 'danger',
        'high': 'warning',
        'medium': 'info',
        'low': 'success'
    };
    return colors[level] || 'secondary';
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function formatDateTime(dateString) {
    const date = new Date(dateString);
    return date.toLocaleString();
}

function escapeHtml(unsafe) {
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function getCSRFToken() {
    const token = document.querySelector('meta[name="csrf-token"]');
    return token ? token.getAttribute('content') : '';
}

function showLoadingState(message) {
    // Show loading overlay or spinner
    const loadingDiv = document.createElement('div');
    loadingDiv.id = 'loadingOverlay';
    loadingDiv.className = 'position-fixed top-0 start-0 w-100 h-100 d-flex align-items-center justify-content-center';
    loadingDiv.style.cssText = 'background: rgba(0,0,0,0.7); z-index: 9999;';
    loadingDiv.innerHTML = `
        <div class="text-center text-white">
            <div class="spinner-border mb-2" role="status"></div>
            <div>${message}</div>
        </div>
    `;
    document.body.appendChild(loadingDiv);
}

function hideLoadingState() {
    const loadingDiv = document.getElementById('loadingOverlay');
    if (loadingDiv) {
        loadingDiv.remove();
    }
}

function animateCounter(element, target) {
    const start = parseInt(element.textContent) || 0;
    const increment = (target - start) / 20;
    let current = start;
    
    const timer = setInterval(() => {
        current += increment;
        if ((increment > 0 && current >= target) || (increment < 0 && current <= target)) {
            element.textContent = target;
            clearInterval(timer);
        } else {
            element.textContent = Math.floor(current);
        }
    }, 50);
}

function showToast(message, type = 'info') {
    if (window.dashboardAPI && window.dashboardAPI.showToast) {
        window.dashboardAPI.showToast(message, type);
        return;
    }
    
    // Fallback toast implementation
    const toast = document.createElement('div');
    toast.className = `alert alert-${type} alert-dismissible position-fixed`;
    toast.style.cssText = 'top: 20px; right: 20px; z-index: 9999; min-width: 300px;';
    toast.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 5000);
}

function showNotification(title, message, type = 'info') {
    if ('Notification' in window && Notification.permission === 'granted') {
        new Notification(title, {
            body: message,
            icon: '/static/img/logo.png'
        });
    }
    
    showToast(`${title}: ${message}`, type);
}

function showErrorState(message) {
    const errorDiv = document.createElement('div');
    errorDiv.className = 'alert alert-danger';
    errorDiv.innerHTML = `<i class="bi bi-exclamation-triangle me-2"></i>${message}`;
    
    const container = document.querySelector('.container-fluid') || document.body;
    container.prepend(errorDiv);
}

// Export functions for global access
window.threatsAPI = {
    initializeThreatsPage,
    bulkQuarantine,
    exportThreats,
    handleQuarantineAction,
    handleRestoreAction,
    handleFalsePositiveReport,
    loadThreatDetails
};

console.log('Threats management module loaded successfully');
