/**
 * Dashboard JavaScript Module
 * Handles real-time updates, charts, and interactive elements
 */

let systemMetricsChart = null;
let threatChart = null;
let metricsUpdateInterval = null;

/**
 * Initialize dashboard functionality
 */
function initializeDashboard() {
    // Initialize system metrics chart
    initializeSystemMetricsChart();
    
    // Start real-time updates
    startRealTimeUpdates();
    
    // Initialize threat distribution chart if data exists
    const threatData = window.threatData;
    if (threatData && threatData.length > 0) {
        initializeThreatChart(threatData);
    }
    
    // Add event listeners
    addEventListeners();
    
    // Load initial data
    loadSystemMetrics();
    
    console.log('Dashboard initialized successfully');
}

/**
 * Initialize system metrics chart
 */
function initializeSystemMetricsChart() {
    const ctx = document.getElementById('systemMetricsChart');
    if (!ctx) return;
    
    systemMetricsChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'CPU Usage (%)',
                    data: [],
                    borderColor: '#0d6efd',
                    backgroundColor: 'rgba(13, 110, 253, 0.1)',
                    tension: 0.4,
                    fill: true
                },
                {
                    label: 'Memory Usage (%)',
                    data: [],
                    borderColor: '#0dcaf0',
                    backgroundColor: 'rgba(13, 202, 240, 0.1)',
                    tension: 0.4,
                    fill: true
                },
                {
                    label: 'Disk Usage (%)',
                    data: [],
                    borderColor: '#ffc107',
                    backgroundColor: 'rgba(255, 193, 7, 0.1)',
                    tension: 0.4,
                    fill: true
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    labels: {
                        color: '#ffffff'
                    }
                },
                tooltip: {
                    mode: 'index',
                    intersect: false,
                    backgroundColor: 'rgba(0, 0, 0, 0.8)',
                    titleColor: '#ffffff',
                    bodyColor: '#ffffff',
                    borderColor: '#ffffff',
                    borderWidth: 1
                }
            },
            scales: {
                x: {
                    ticks: {
                        color: '#ffffff'
                    },
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    }
                },
                y: {
                    beginAtZero: true,
                    max: 100,
                    ticks: {
                        color: '#ffffff',
                        callback: function(value) {
                            return value + '%';
                        }
                    },
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    }
                }
            },
            interaction: {
                mode: 'nearest',
                axis: 'x',
                intersect: false
            }
        }
    });
}

/**
 * Initialize threat distribution chart
 */
function initializeThreatChart(threatData) {
    const ctx = document.getElementById('threatChart');
    if (!ctx || !threatData) return;
    
    const data = threatData.map(item => ({
        label: item[0].charAt(0).toUpperCase() + item[0].slice(1),
        count: item[1]
    }));
    
    const colors = {
        'Critical': '#dc3545',
        'High': '#fd7e14',
        'Medium': '#ffc107',
        'Low': '#28a745'
    };
    
    threatChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: data.map(item => item.label),
            datasets: [{
                data: data.map(item => item.count),
                backgroundColor: data.map(item => colors[item.label] || '#6c757d'),
                borderColor: '#212529',
                borderWidth: 2,
                hoverBorderWidth: 3
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#ffffff',
                        padding: 20,
                        usePointStyle: true,
                        pointStyle: 'circle'
                    }
                },
                tooltip: {
                    backgroundColor: 'rgba(0, 0, 0, 0.8)',
                    titleColor: '#ffffff',
                    bodyColor: '#ffffff',
                    borderColor: '#ffffff',
                    borderWidth: 1,
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = context.parsed || 0;
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = ((value / total) * 100).toFixed(1);
                            return `${label}: ${value} (${percentage}%)`;
                        }
                    }
                }
            },
            cutout: '60%',
            animation: {
                animateRotate: true,
                animateScale: true
            }
        }
    });
}

/**
 * Load system metrics from API
 */
async function loadSystemMetrics() {
    try {
        const response = await fetch('/api/system_metrics');
        if (!response.ok) throw new Error('Failed to fetch metrics');
        
        const metrics = await response.json();
        
        if (metrics.error) {
            console.error('Metrics error:', metrics.error);
            return;
        }
        
        updateMetricsDisplay(metrics);
        updateSystemMetricsChart(metrics);
        
    } catch (error) {
        console.error('Error loading system metrics:', error);
        showMetricsError();
    }
}

/**
 * Update metrics display elements
 */
function updateMetricsDisplay(metrics) {
    // Update progress bars and text
    updateProgressBar('cpuProgress', 'cpuUsage', metrics.cpu_usage);
    updateProgressBar('memoryProgress', 'memoryUsage', metrics.memory_usage);
    updateProgressBar('diskProgress', 'diskUsage', metrics.disk_usage);
    
    // Update threat level
    const threatLevelElement = document.getElementById('threatLevel');
    if (threatLevelElement) {
        threatLevelElement.textContent = metrics.threat_level.charAt(0).toUpperCase() + metrics.threat_level.slice(1);
        threatLevelElement.className = `badge bg-${getThreatLevelColor(metrics.threat_level)}`;
    }
    
    // Update system status
    const systemStatusElement = document.getElementById('systemStatus');
    if (systemStatusElement) {
        const status = metrics.threat_level === 'low' ? 'Protected' : 'At Risk';
        systemStatusElement.textContent = status;
    }
}

/**
 * Update progress bar and text
 */
function updateProgressBar(progressId, textId, value) {
    const progressElement = document.getElementById(progressId);
    const textElement = document.getElementById(textId);
    
    if (progressElement) {
        progressElement.style.width = `${value}%`;
        progressElement.setAttribute('aria-valuenow', value);
        
        // Update color based on value
        progressElement.className = `progress-bar bg-${getUsageColor(value)}`;
    }
    
    if (textElement) {
        textElement.textContent = `${value.toFixed(1)}%`;
    }
}

/**
 * Get color based on usage percentage
 */
function getUsageColor(value) {
    if (value >= 90) return 'danger';
    if (value >= 75) return 'warning';
    if (value >= 50) return 'info';
    return 'success';
}

/**
 * Get color based on threat level
 */
function getThreatLevelColor(level) {
    const colors = {
        'low': 'success',
        'medium': 'info',
        'high': 'warning',
        'critical': 'danger'
    };
    return colors[level] || 'secondary';
}

/**
 * Update system metrics chart with new data
 */
function updateSystemMetricsChart(metrics) {
    if (!systemMetricsChart) return;
    
    const now = new Date().toLocaleTimeString();
    const maxPoints = 20; // Keep last 20 data points
    
    // Add new data point
    systemMetricsChart.data.labels.push(now);
    systemMetricsChart.data.datasets[0].data.push(metrics.cpu_usage);
    systemMetricsChart.data.datasets[1].data.push(metrics.memory_usage);
    systemMetricsChart.data.datasets[2].data.push(metrics.disk_usage);
    
    // Remove old data points
    if (systemMetricsChart.data.labels.length > maxPoints) {
        systemMetricsChart.data.labels.shift();
        systemMetricsChart.data.datasets.forEach(dataset => {
            dataset.data.shift();
        });
    }
    
    systemMetricsChart.update('none'); // No animation for real-time updates
}

/**
 * Start real-time updates
 */
function startRealTimeUpdates() {
    // Update every 30 seconds
    metricsUpdateInterval = setInterval(loadSystemMetrics, 30000);
}

/**
 * Stop real-time updates
 */
function stopRealTimeUpdates() {
    if (metricsUpdateInterval) {
        clearInterval(metricsUpdateInterval);
        metricsUpdateInterval = null;
    }
}

/**
 * Add event listeners
 */
function addEventListeners() {
    // Handle page visibility changes
    document.addEventListener('visibilitychange', function() {
        if (document.hidden) {
            stopRealTimeUpdates();
        } else {
            loadSystemMetrics();
            startRealTimeUpdates();
        }
    });
    
    // Handle window beforeunload
    window.addEventListener('beforeunload', function() {
        stopRealTimeUpdates();
    });
}

/**
 * Show metrics error state
 */
function showMetricsError() {
    const elements = ['cpuUsage', 'memoryUsage', 'diskUsage', 'threatLevel'];
    elements.forEach(id => {
        const element = document.getElementById(id);
        if (element) {
            element.textContent = '--';
        }
    });
}

/**
 * Refresh dashboard data
 */
function refreshDashboard() {
    loadSystemMetrics();
    
    // Show loading indicator
    const refreshBtn = document.querySelector('[onclick="refreshDashboard()"]');
    if (refreshBtn) {
        const originalContent = refreshBtn.innerHTML;
        refreshBtn.innerHTML = '<i class="bi bi-arrow-clockwise spin"></i> Refreshing...';
        refreshBtn.disabled = true;
        
        setTimeout(() => {
            refreshBtn.innerHTML = originalContent;
            refreshBtn.disabled = false;
        }, 2000);
    }
}

/**
 * Load threat statistics for charts
 */
async function loadThreatStats() {
    try {
        const response = await fetch('/api/threat_stats');
        if (!response.ok) throw new Error('Failed to fetch threat stats');
        
        const stats = await response.json();
        
        // Update threat timeline chart if exists
        if (stats.length > 0) {
            updateThreatTimeline(stats);
        }
        
    } catch (error) {
        console.error('Error loading threat stats:', error);
    }
}

/**
 * Update threat timeline chart
 */
function updateThreatTimeline(data) {
    // Implementation for threat timeline chart
    console.log('Updating threat timeline with data:', data);
}

/**
 * Format bytes to human readable format
 */
function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

/**
 * Format timestamp to relative time
 */
function formatRelativeTime(timestamp) {
    const now = new Date();
    const date = new Date(timestamp);
    const diff = now - date;
    
    const seconds = Math.floor(diff / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);
    
    if (days > 0) return `${days} day${days > 1 ? 's' : ''} ago`;
    if (hours > 0) return `${hours} hour${hours > 1 ? 's' : ''} ago`;
    if (minutes > 0) return `${minutes} minute${minutes > 1 ? 's' : ''} ago`;
    return 'Just now';
}

/**
 * Show notification to user
 */
function showNotification(title, message, type = 'info') {
    // Check if notifications are supported and permitted
    if ('Notification' in window && Notification.permission === 'granted') {
        new Notification(title, {
            body: message,
            icon: '/static/img/logo.png',
            badge: '/static/img/logo.png'
        });
    }
    
    // Also show in-app notification
    showToast(message, type);
}

/**
 * Show toast notification
 */
function showToast(message, type = 'info') {
    const toastContainer = document.getElementById('toastContainer') || createToastContainer();
    
    const toast = document.createElement('div');
    toast.className = `toast align-items-center text-white bg-${type} border-0`;
    toast.setAttribute('role', 'alert');
    toast.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">
                ${message}
            </div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
        </div>
    `;
    
    toastContainer.appendChild(toast);
    
    const bsToast = new bootstrap.Toast(toast);
    bsToast.show();
    
    // Remove toast element after it's hidden
    toast.addEventListener('hidden.bs.toast', function() {
        toast.remove();
    });
}

/**
 * Create toast container if it doesn't exist
 */
function createToastContainer() {
    const container = document.createElement('div');
    container.id = 'toastContainer';
    container.className = 'toast-container position-fixed top-0 end-0 p-3';
    container.style.zIndex = '9999';
    document.body.appendChild(container);
    return container;
}

/**
 * Animate counter numbers
 */
function animateCounter(element, target, duration = 1000) {
    const start = parseInt(element.textContent) || 0;
    const increment = (target - start) / (duration / 16);
    let current = start;
    
    const timer = setInterval(() => {
        current += increment;
        if ((increment > 0 && current >= target) || (increment < 0 && current <= target)) {
            element.textContent = target;
            clearInterval(timer);
        } else {
            element.textContent = Math.floor(current);
        }
    }, 16);
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Add some delay to ensure all elements are rendered
    setTimeout(initializeDashboard, 100);
});

// Export functions for use in other scripts
window.dashboardAPI = {
    refreshDashboard,
    loadSystemMetrics,
    loadThreatStats,
    showNotification,
    showToast,
    formatBytes,
    formatRelativeTime,
    animateCounter
};
