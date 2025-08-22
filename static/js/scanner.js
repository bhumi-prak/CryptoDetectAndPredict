/**
 * Scanner JavaScript Module
 * Handles scan operations, progress monitoring, and file management
 */

let scanProgressInterval = null;
let scanStartTime = null;
let currentScanId = null;

/**
 * Initialize scanner functionality
 */
function initializeScanner() {
    // Check if there's an active scan
    checkActiveScan();
    
    // Initialize file path suggestions
    initializePathSuggestions();
    
    // Initialize scan progress monitoring
    initializeProgressMonitoring();
    
    console.log('Scanner initialized successfully');
}

/**
 * Check for active scan on page load
 */
function checkActiveScan() {
    const scanProgress = document.getElementById('scanProgress');
    const urlParams = new URLSearchParams(window.location.search);
    const scanId = urlParams.get('scan_id');
    
    if (scanId && scanProgress) {
        // Resume monitoring active scan
        currentScanId = scanId;
        startScanProgress();
        monitorScanProgress(scanId);
    }
}

/**
 * Initialize file path suggestions
 */
function initializePathSuggestions() {
    const targetPath = document.getElementById('target_path');
    if (!targetPath) return;
    
    const commonPaths = [
        '/home',
        '/tmp',
        '/var/tmp',
        '/usr/local',
        '/opt',
        '~/Desktop',
        '~/Documents',
        '~/Downloads'
    ];
    
    // Add datalist for path suggestions
    const datalist = document.createElement('datalist');
    datalist.id = 'pathSuggestions';
    
    commonPaths.forEach(path => {
        const option = document.createElement('option');
        option.value = path;
        datalist.appendChild(option);
    });
    
    targetPath.setAttribute('list', 'pathSuggestions');
    targetPath.parentNode.appendChild(datalist);
}

/**
 * Initialize progress monitoring
 */
function initializeProgressMonitoring() {
    // Set up progress bar animations
    const progressBar = document.getElementById('progressBar');
    if (progressBar) {
        progressBar.style.transition = 'width 0.3s ease';
    }
}

/**
 * Start scan progress display
 */
function startScanProgress() {
    const scanProgress = document.getElementById('scanProgress');
    const startScanBtn = document.getElementById('startScanBtn');
    
    if (scanProgress) {
        scanProgress.style.display = 'block';
        scanProgress.scrollIntoView({ behavior: 'smooth' });
    }
    
    if (startScanBtn) {
        startScanBtn.disabled = true;
        startScanBtn.innerHTML = '<i class="bi bi-hourglass-split"></i> Scanning...';
    }
    
    // Initialize progress counters
    updateScanProgress(0, 0, 0, 'Initializing scan...');
    
    scanStartTime = Date.now();
    startProgressTimer();
}

/**
 * Stop scan progress display
 */
function stopScanProgress() {
    const scanProgress = document.getElementById('scanProgress');
    const startScanBtn = document.getElementById('startScanBtn');
    
    if (scanProgress) {
        scanProgress.style.display = 'none';
    }
    
    if (startScanBtn) {
        startScanBtn.disabled = false;
        startScanBtn.innerHTML = '<i class="bi bi-play-circle"></i> Start Scan';
    }
    
    stopProgressTimer();
}

/**
 * Update scan progress display
 */
function updateScanProgress(filesScanned, threatsFound, percentage, status) {
    // Update progress bar
    const progressBar = document.getElementById('progressBar');
    if (progressBar) {
        progressBar.style.width = `${percentage}%`;
        progressBar.setAttribute('aria-valuenow', percentage);
    }
    
    // Update counters
    const elements = {
        'filesScanned': filesScanned.toLocaleString(),
        'threatsFound': threatsFound.toLocaleString(),
        'scanPercent': `${Math.round(percentage)}%`,
        'scanStatus': status
    };
    
    Object.entries(elements).forEach(([id, value]) => {
        const element = document.getElementById(id);
        if (element) {
            element.textContent = value;
        }
    });
    
    // Update progress bar color based on threats found
    if (progressBar) {
        if (threatsFound > 0) {
            progressBar.className = 'progress-bar bg-danger progress-bar-striped progress-bar-animated';
        } else {
            progressBar.className = 'progress-bar bg-success progress-bar-striped progress-bar-animated';
        }
    }
}

/**
 * Start progress timer
 */
function startProgressTimer() {
    const scanTimeElement = document.getElementById('scanTime');
    if (!scanTimeElement || !scanStartTime) return;
    
    scanProgressInterval = setInterval(() => {
        const elapsed = Date.now() - scanStartTime;
        const minutes = Math.floor(elapsed / 60000);
        const seconds = Math.floor((elapsed % 60000) / 1000);
        scanTimeElement.textContent = `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
    }, 1000);
}

/**
 * Stop progress timer
 */
function stopProgressTimer() {
    if (scanProgressInterval) {
        clearInterval(scanProgressInterval);
        scanProgressInterval = null;
    }
}

/**
 * Monitor scan progress via API
 */
async function monitorScanProgress(scanId) {
    if (!scanId) return;
    
    try {
        const response = await fetch(`/api/scan_status/${scanId}`);
        if (!response.ok) throw new Error('Failed to fetch scan status');
        
        const status = await response.json();
        
        if (status.error) {
            console.error('Scan status error:', status.error);
            stopScanProgress();
            showScanError(status.error);
            return;
        }
        
        // Update progress display
        const percentage = status.total_files > 0 ? 
            (status.files_scanned / status.total_files) * 100 : 0;
        
        updateScanProgress(
            status.files_scanned,
            status.threats_found,
            percentage,
            status.current_status
        );
        
        // Continue monitoring if scan is still active
        if (status.status === 'scanning') {
            setTimeout(() => monitorScanProgress(scanId), 2000); // Poll every 2 seconds
        } else {
            // Scan completed
            stopScanProgress();
            if (status.status === 'completed') {
                showScanComplete(status);
            } else if (status.status === 'failed') {
                showScanError('Scan failed. Please try again.');
            }
        }
        
    } catch (error) {
        console.error('Error monitoring scan progress:', error);
        stopScanProgress();
        showScanError('Unable to monitor scan progress.');
    }
}

/**
 * Show scan completion message
 */
function showScanComplete(results) {
    const message = `Scan completed! ${results.files_scanned.toLocaleString()} files scanned, ${results.threats_found} threats found.`;
    
    if (results.threats_found > 0) {
        showToast(message, 'warning');
        showNotification('Scan Complete', `${results.threats_found} threats detected!`, 'warning');
    } else {
        showToast(message, 'success');
        showNotification('Scan Complete', 'No threats detected. Your system is clean!', 'success');
    }
    
    // Refresh page to show results
    setTimeout(() => {
        window.location.reload();
    }, 2000);
}

/**
 * Show scan error message
 */
function showScanError(message) {
    showToast(`Scan Error: ${message}`, 'danger');
    console.error('Scan error:', message);
}

/**
 * Validate scan form before submission
 */
function validateScanForm(formData) {
    const scanType = formData.get('scan_type');
    const targetPath = formData.get('target_path');
    
    if (!scanType) {
        showToast('Please select a scan type.', 'warning');
        return false;
    }
    
    if (!targetPath || targetPath.trim() === '') {
        showToast('Please specify a target path.', 'warning');
        return false;
    }
    
    // Validate path format (basic validation)
    if (scanType === 'custom' && !isValidPath(targetPath)) {
        showToast('Please enter a valid file path.', 'warning');
        return false;
    }
    
    return true;
}

/**
 * Basic path validation
 */
function isValidPath(path) {
    // Basic validation - check if path looks reasonable
    if (path.length < 1 || path.length > 500) return false;
    
    // Check for dangerous characters
    const dangerousChars = ['<', '>', '|', '*', '?', '"'];
    if (dangerousChars.some(char => path.includes(char))) return false;
    
    return true;
}

/**
 * Estimate scan time based on scan type and path
 */
function estimateScanTime(scanType, targetPath) {
    const estimates = {
        'quick': { min: 30, max: 120 }, // 30 seconds to 2 minutes
        'full': { min: 300, max: 1800 }, // 5 to 30 minutes
        'custom': { min: 60, max: 600 }  // 1 to 10 minutes
    };
    
    const estimate = estimates[scanType] || estimates['custom'];
    const avgTime = (estimate.min + estimate.max) / 2;
    
    return formatDuration(avgTime);
}

/**
 * Format duration in seconds to human readable string
 */
function formatDuration(seconds) {
    if (seconds < 60) return `${seconds} seconds`;
    
    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = seconds % 60;
    
    if (minutes < 60) {
        return remainingSeconds > 0 ? 
            `${minutes}m ${remainingSeconds}s` : 
            `${minutes} minute${minutes > 1 ? 's' : ''}`;
    }
    
    const hours = Math.floor(minutes / 60);
    const remainingMinutes = minutes % 60;
    
    return remainingMinutes > 0 ? 
        `${hours}h ${remainingMinutes}m` : 
        `${hours} hour${hours > 1 ? 's' : ''}`;
}

/**
 * Show scan type information
 */
function showScanTypeInfo(scanType) {
    const info = {
        'quick': {
            title: 'Quick Scan',
            description: 'Scans common locations where threats are typically found',
            paths: 'Desktop, Documents, Downloads, Temporary folders',
            time: 'Usually completes in 1-2 minutes'
        },
        'full': {
            title: 'Full System Scan',
            description: 'Comprehensive scan of the entire file system',
            paths: 'All accessible files and directories',
            time: 'May take 10-30 minutes or more'
        },
        'custom': {
            title: 'Custom Scan',
            description: 'Scan a specific directory or file path',
            paths: 'User-specified location only',
            time: 'Varies based on target size'
        }
    };
    
    const scanInfo = info[scanType];
    if (scanInfo) {
        showToast(`${scanInfo.title}: ${scanInfo.description}`, 'info');
    }
}

/**
 * Browse for directory (placeholder for file system integration)
 */
function browsePath() {
    // In a real implementation, this would integrate with file system APIs
    const commonPaths = [
        '/home',
        '/tmp',
        '/var/tmp',
        '/usr/local',
        '/opt',
        '~/Desktop',
        '~/Documents',
        '~/Downloads'
    ];
    
    const pathList = commonPaths.map(path => `• ${path}`).join('\n');
    const selectedPath = prompt(`Enter a path to scan:\n\nCommon paths:\n${pathList}`, '/home');
    
    if (selectedPath) {
        document.getElementById('target_path').value = selectedPath;
    }
}

/**
 * Handle file quarantine action
 */
async function quarantineFile(threatId, fileName) {
    if (!confirm(`Quarantine "${fileName}"?\n\nThis will safely isolate the file and create a backup.`)) {
        return;
    }
    
    try {
        const response = await fetch(`/api/quarantine/${threatId}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        if (!response.ok) throw new Error('Quarantine failed');
        
        const result = await response.json();
        
        if (result.success) {
            showToast('File quarantined successfully!', 'success');
            // Update UI to reflect quarantine status
            updateThreatStatus(threatId, 'quarantined');
        } else {
            throw new Error(result.error || 'Quarantine failed');
        }
        
    } catch (error) {
        console.error('Quarantine error:', error);
        showToast(`Quarantine failed: ${error.message}`, 'danger');
    }
}

/**
 * Update threat status in UI
 */
function updateThreatStatus(threatId, status) {
    const threatRow = document.querySelector(`[data-threat-id="${threatId}"]`);
    if (threatRow) {
        const statusBadge = threatRow.querySelector('.badge');
        const actionButton = threatRow.querySelector('.btn-outline-warning');
        
        if (status === 'quarantined') {
            if (statusBadge) statusBadge.textContent = 'Quarantined';
            if (actionButton) {
                actionButton.disabled = true;
                actionButton.innerHTML = '<i class="bi bi-check"></i> Quarantined';
            }
        }
    }
}

/**
 * Show/hide advanced scan options
 */
function toggleAdvancedOptions() {
    const advancedOptions = document.getElementById('advancedOptions');
    const toggleButton = document.getElementById('advancedToggle');
    
    if (advancedOptions && toggleButton) {
        const isVisible = advancedOptions.style.display !== 'none';
        
        advancedOptions.style.display = isVisible ? 'none' : 'block';
        toggleButton.innerHTML = isVisible ? 
            '<i class="bi bi-chevron-down"></i> Show Advanced Options' :
            '<i class="bi bi-chevron-up"></i> Hide Advanced Options';
    }
}

/**
 * Export scan results
 */
function exportScanResults(scanId) {
    // Create downloadable CSV/JSON report
    const timestamp = new Date().toISOString().split('T')[0];
    const filename = `scan_results_${timestamp}.json`;
    
    // In a real implementation, this would fetch actual scan data
    const reportData = {
        scanId: scanId,
        timestamp: new Date().toISOString(),
        results: 'Scan results would be exported here'
    };
    
    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    showToast('Scan results exported successfully!', 'success');
}

// Utility functions from dashboard.js
function showToast(message, type = 'info') {
    if (window.dashboardAPI && window.dashboardAPI.showToast) {
        window.dashboardAPI.showToast(message, type);
        return;
    }
    
    // Fallback toast implementation
    console.log(`Toast [${type}]: ${message}`);
    alert(message);
}

function showNotification(title, message, type = 'info') {
    if (window.dashboardAPI && window.dashboardAPI.showNotification) {
        window.dashboardAPI.showNotification(title, message, type);
        return;
    }
    
    // Fallback notification
    console.log(`Notification [${type}]: ${title} - ${message}`);
}

// Export functions for use in other scripts
window.scannerAPI = {
    initializeScanner,
    startScanProgress,
    stopScanProgress,
    monitorScanProgress,
    quarantineFile,
    exportScanResults,
    validateScanForm,
    browsePath,
    toggleAdvancedOptions
};

console.log('Scanner module loaded successfully');
