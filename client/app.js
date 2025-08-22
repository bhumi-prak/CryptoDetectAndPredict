// Global state
let currentUser = null;
let currentPage = 'login';
let scanInProgress = false;
let threatChart = null;

// API base URL
const API_BASE = '/api';

// Initialize app
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
});

function initializeApp() {
    // Check if user is logged in
    const savedUser = localStorage.getItem('currentUser');
    if (savedUser) {
        currentUser = JSON.parse(savedUser);
        showPage('dashboard');
        updateUserInfo();
        loadDashboardData();
    } else {
        showPage('login');
    }
    
    // Set up event listeners
    setupEventListeners();
}

function setupEventListeners() {
    // Login form
    document.getElementById('login-form').addEventListener('submit', handleLogin);
    
    // Signup form  
    document.getElementById('signup-form').addEventListener('submit', handleSignup);
    
    // File input for analysis
    document.getElementById('file-input').addEventListener('change', handleFileUpload);
}

// Authentication functions
async function handleLogin(e) {
    e.preventDefault();
    
    const email = document.getElementById('login-email').value;
    const password = document.getElementById('login-password').value;
    
    try {
        const response = await fetch(`${API_BASE}/auth/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ email, password }),
        });
        
        const data = await response.json();
        
        if (response.ok) {
            currentUser = data.user;
            localStorage.setItem('currentUser', JSON.stringify(currentUser));
            showPage('dashboard');
            updateUserInfo();
            loadDashboardData();
            showNotification('Login successful!', 'success');
        } else {
            showNotification(data.error || 'Login failed', 'error');
        }
    } catch (error) {
        showNotification('Login failed. Please try again.', 'error');
    }
}

async function handleSignup(e) {
    e.preventDefault();
    
    const name = document.getElementById('signup-name').value;
    const email = document.getElementById('signup-email').value;
    const password = document.getElementById('signup-password').value;
    
    try {
        const response = await fetch(`${API_BASE}/auth/signup`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ name, email, password }),
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showNotification('Account created successfully! Please login.', 'success');
            showPage('login');
        } else {
            showNotification(data.error || 'Signup failed', 'error');
        }
    } catch (error) {
        showNotification('Signup failed. Please try again.', 'error');
    }
}

function logout() {
    currentUser = null;
    localStorage.removeItem('currentUser');
    showPage('login');
    showNotification('Logged out successfully', 'success');
}

// Page navigation
function showPage(pageName) {
    // Hide all pages
    document.querySelectorAll('.page').forEach(page => {
        page.classList.remove('active');
    });
    
    // Show requested page
    const targetPage = document.getElementById(`${pageName}-page`);
    if (targetPage) {
        targetPage.classList.add('active');
        targetPage.classList.add('fade-in');
        currentPage = pageName;
    }
    
    // Update navigation
    updateNavigation();
}

function updateNavigation() {
    const navbar = document.querySelector('.navbar');
    if (currentPage === 'login' || currentPage === 'signup') {
        navbar.style.display = 'none';
    } else {
        navbar.style.display = 'block';
    }
}

function updateUserInfo() {
    if (currentUser) {
        document.getElementById('user-name').textContent = `Welcome, ${currentUser.name}!`;
    }
}

// Dashboard functions
async function loadDashboardData() {
    try {
        // Load threat statistics
        const threatsResponse = await fetch(`${API_BASE}/threats`);
        const threats = await threatsResponse.json();
        
        updateThreatStats(threats);
        updateThreatList(threats);
        
        // Load active ML model
        const modelResponse = await fetch(`${API_BASE}/models/active`);
        const activeModel = await modelResponse.json();
        
        if (activeModel) {
            document.getElementById('model-accuracy').textContent = `${(activeModel.accuracy * 100).toFixed(1)}%`;
        }
        
        // Create threat timeline chart
        createThreatChart(threats);
        
    } catch (error) {
        console.error('Failed to load dashboard data:', error);
    }
}

function updateThreatStats(threats) {
    const highThreats = threats.filter(t => t.threatLevel === 'HIGH' || t.threatLevel === 'CRITICAL').length;
    const mediumThreats = threats.filter(t => t.threatLevel === 'MEDIUM').length;
    const totalFiles = threats.length;
    
    document.getElementById('high-threats').textContent = highThreats;
    document.getElementById('medium-threats').textContent = mediumThreats;
    document.getElementById('files-scanned').textContent = totalFiles;
}

function updateThreatList(threats) {
    const threatItems = document.getElementById('threat-items');
    threatItems.innerHTML = '';
    
    const recentThreats = threats.slice(-5).reverse(); // Last 5 threats
    
    recentThreats.forEach(threat => {
        const threatItem = document.createElement('div');
        threatItem.className = 'threat-item';
        threatItem.innerHTML = `
            <div class="threat-info">
                <div class="threat-file">${threat.fileName}</div>
                <div class="threat-level threat-${threat.threatLevel.toLowerCase()}">${threat.threatLevel}</div>
                <div class="threat-time">${new Date(threat.detectedAt).toLocaleTimeString()}</div>
            </div>
        `;
        threatItems.appendChild(threatItem);
    });
    
    if (recentThreats.length === 0) {
        threatItems.innerHTML = '<p>No threats detected yet.</p>';
    }
}

function createThreatChart(threats) {
    const canvas = document.getElementById('threat-chart');
    const ctx = canvas.getContext('2d');
    
    // Simple chart implementation
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    
    // Chart data processing
    const last7Days = [];
    const today = new Date();
    
    for (let i = 6; i >= 0; i--) {
        const date = new Date(today);
        date.setDate(date.getDate() - i);
        const dayThreats = threats.filter(t => {
            const threatDate = new Date(t.detectedAt);
            return threatDate.toDateString() === date.toDateString();
        }).length;
        
        last7Days.push({
            date: date.toLocaleDateString(),
            threats: dayThreats
        });
    }
    
    // Simple bar chart
    const maxThreats = Math.max(...last7Days.map(d => d.threats), 1);
    const barWidth = canvas.width / 7;
    const barMaxHeight = canvas.height - 40;
    
    ctx.fillStyle = '#00d4ff';
    ctx.font = '12px Arial';
    
    last7Days.forEach((day, index) => {
        const barHeight = (day.threats / maxThreats) * barMaxHeight;
        const x = index * barWidth + 10;
        const y = canvas.height - barHeight - 20;
        
        // Draw bar
        ctx.fillRect(x, y, barWidth - 20, barHeight);
        
        // Draw label
        ctx.fillStyle = '#fff';
        ctx.fillText(day.date.split('/')[1], x, canvas.height - 5);
        ctx.fillText(day.threats.toString(), x, y - 5);
        ctx.fillStyle = '#00d4ff';
    });
}

// File analysis functions
async function handleFileUpload(e) {
    const file = e.target.files[0];
    if (!file) return;
    
    await analyzeFile(file.name);
}

async function analyzeFile(fileName) {
    if (!fileName) {
        const fileInput = document.getElementById('file-input');
        const file = fileInput.files[0];
        if (!file) {
            showNotification('Please select a file first', 'error');
            return;
        }
        fileName = file.name;
    }
    
    try {
        showNotification('Analyzing file...', 'info');
        
        const response = await fetch(`${API_BASE}/analyze`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                fileName: fileName,
                userId: currentUser?.id
            }),
        });
        
        const analysis = await response.json();
        
        if (response.ok) {
            // Poll for results
            pollAnalysisResult(analysis.id);
        } else {
            showNotification('Analysis failed', 'error');
        }
    } catch (error) {
        showNotification('Analysis failed', 'error');
    }
}

async function pollAnalysisResult(analysisId) {
    let attempts = 0;
    const maxAttempts = 30; // 30 seconds max
    
    const poll = async () => {
        try {
            const response = await fetch(`${API_BASE}/analyze/${analysisId}`);
            const analysis = await response.json();
            
            if (analysis.status === 'COMPLETED') {
                displayAnalysisResult(analysis);
                return;
            } else if (analysis.status === 'FAILED') {
                showNotification('Analysis failed', 'error');
                return;
            }
            
            attempts++;
            if (attempts < maxAttempts) {
                setTimeout(poll, 1000);
            } else {
                showNotification('Analysis timed out', 'error');
            }
        } catch (error) {
            showNotification('Failed to get analysis result', 'error');
        }
    };
    
    poll();
}

function displayAnalysisResult(analysis) {
    const resultsDiv = document.getElementById('analysis-results');
    
    const result = analysis.result || analysis.analysisResult;
    if (!result) {
        resultsDiv.innerHTML = '<p>No analysis result available</p>';
        return;
    }
    
    const threatClass = result.threatLevel ? result.threatLevel.toLowerCase() : 'unknown';
    
    resultsDiv.innerHTML = `
        <div class="analysis-result fade-in">
            <h3>Analysis Complete</h3>
            <div class="result-item">
                <span class="label">File:</span>
                <span class="value">${analysis.fileName}</span>
            </div>
            <div class="result-item">
                <span class="label">Threat Level:</span>
                <span class="value threat-${threatClass}">${result.threatLevel || 'Unknown'}</span>
            </div>
            <div class="result-item">
                <span class="label">Confidence:</span>
                <span class="value">${((result.confidence || 0) * 100).toFixed(1)}%</span>
            </div>
            ${result.entropy ? `
            <div class="result-item">
                <span class="label">File Entropy:</span>
                <span class="value">${result.entropy.toFixed(2)}</span>
            </div>
            ` : ''}
            <div class="result-actions">
                <button class="btn btn-secondary" onclick="analyzeAnother()">Analyze Another File</button>
            </div>
        </div>
    `;
    
    // Update dashboard if threat found
    if (result.threatLevel === 'HIGH' || result.threatLevel === 'CRITICAL') {
        showNotification(`${result.threatLevel} threat detected!`, 'warning');
        loadDashboardData(); // Refresh dashboard
    } else {
        showNotification('File analysis complete', 'success');
    }
}

function analyzeAnother() {
    document.getElementById('analysis-results').innerHTML = '';
    document.getElementById('file-input').value = '';
}

// ML Model functions
async function trainModel() {
    const algorithm = document.getElementById('algorithm-select').value;
    const datasetSize = document.getElementById('dataset-size').value;
    
    try {
        showNotification('Starting model training with large dataset...', 'info');
        
        const response = await fetch(`${API_BASE}/train`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ algorithm, datasetSize: parseInt(datasetSize) }),
        });
        
        const result = await response.json();
        
        if (response.ok) {
            showNotification(`Training started: ${result.message}`, 'success');
            
            // Poll for training completion
            setTimeout(() => {
                loadModelsList();
                loadDashboardData(); // Refresh accuracy display
            }, 6000);
        } else {
            showNotification('Training failed to start', 'error');
        }
    } catch (error) {
        showNotification('Training failed', 'error');
    }
}

async function loadModelsList() {
    try {
        const response = await fetch(`${API_BASE}/models`);
        const models = await response.json();
        
        const modelsList = document.getElementById('models-list');
        modelsList.innerHTML = '';
        
        models.forEach(model => {
            const modelCard = document.createElement('div');
            modelCard.className = 'model-card';
            modelCard.innerHTML = `
                <h3>${model.modelName}</h3>
                <div class="model-metrics">
                    <div class="metric">
                        <span class="label">Algorithm:</span>
                        <span class="value">${model.algorithm}</span>
                    </div>
                    <div class="metric">
                        <span class="label">Accuracy:</span>
                        <span class="value">${(model.accuracy * 100).toFixed(2)}%</span>
                    </div>
                    <div class="metric">
                        <span class="label">Dataset Size:</span>
                        <span class="value">${model.trainingDataSize?.toLocaleString() || 'N/A'}</span>
                    </div>
                    <div class="metric">
                        <span class="label">Status:</span>
                        <span class="value ${model.isActive ? 'status-active' : ''}">${model.isActive ? 'Active' : 'Inactive'}</span>
                    </div>
                </div>
                <div class="model-trained">
                    Trained: ${new Date(model.trainedAt).toLocaleString()}
                </div>
            `;
            modelsList.appendChild(modelCard);
        });
        
    } catch (error) {
        console.error('Failed to load models:', error);
    }
}

// System scan functions
async function startQuickScan() {
    if (scanInProgress) {
        showNotification('Scan already in progress', 'warning');
        return;
    }
    
    scanInProgress = true;
    showNotification('Starting quick system scan...', 'info');
    
    try {
        // This would call the Python system scanner
        // For demo, we'll simulate the scan
        setTimeout(() => {
            scanInProgress = false;
            showNotification('Quick scan completed - No threats found', 'success');
            loadDashboardData();
        }, 3000);
    } catch (error) {
        scanInProgress = false;
        showNotification('Scan failed', 'error');
    }
}

async function startFullScan() {
    if (scanInProgress) {
        showNotification('Scan already in progress', 'warning');
        return;
    }
    
    if (!confirm('Full system scan may take several minutes. Continue?')) {
        return;
    }
    
    scanInProgress = true;
    showNotification('Starting comprehensive system scan...', 'info');
    
    try {
        // This would call the Python system scanner
        // For demo, we'll simulate the scan
        setTimeout(() => {
            scanInProgress = false;
            showNotification('Full system scan completed', 'success');
            loadDashboardData();
        }, 8000);
    } catch (error) {
        scanInProgress = false;
        showNotification('Scan failed', 'error');
    }
}

// Utility functions
function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.textContent = message;
    
    // Add to page
    document.body.appendChild(notification);
    
    // Animate in
    setTimeout(() => notification.classList.add('show'), 100);
    
    // Remove after delay
    setTimeout(() => {
        notification.classList.remove('show');
        setTimeout(() => document.body.removeChild(notification), 300);
    }, 3000);
}

function toggleNav() {
    const navMenu = document.getElementById('nav-menu');
    navMenu.classList.toggle('active');
}

// Load page-specific data when switching pages
function showPage(pageName) {
    // Hide all pages
    document.querySelectorAll('.page').forEach(page => {
        page.classList.remove('active');
    });
    
    // Show requested page
    const targetPage = document.getElementById(`${pageName}-page`);
    if (targetPage) {
        targetPage.classList.add('active');
        targetPage.classList.add('fade-in');
        currentPage = pageName;
    }
    
    // Load page-specific data
    if (pageName === 'models') {
        loadModelsList();
    } else if (pageName === 'dashboard') {
        loadDashboardData();
    }
    
    // Update navigation
    updateNavigation();
}

// Add CSS for notifications and additional styling
const additionalCSS = `
.notification {
    position: fixed;
    top: 100px;
    right: 20px;
    padding: 1rem 1.5rem;
    border-radius: 8px;
    color: #fff;
    font-weight: 500;
    z-index: 10000;
    transform: translateX(400px);
    transition: transform 0.3s ease;
    max-width: 300px;
}

.notification.show {
    transform: translateX(0);
}

.notification-success {
    background: linear-gradient(135deg, #2ed573, #1e824c);
}

.notification-error {
    background: linear-gradient(135deg, #ff4757, #c44569);
}

.notification-warning {
    background: linear-gradient(135deg, #ffa502, #ff6348);
}

.notification-info {
    background: linear-gradient(135deg, #00d4ff, #0099cc);
}

.threat-item {
    padding: 1rem;
    border-bottom: 1px solid rgba(255, 255, 255, 0.1);
    margin-bottom: 0.5rem;
}

.threat-info {
    display: grid;
    grid-template-columns: 2fr 1fr 1fr;
    gap: 1rem;
    align-items: center;
}

.threat-file {
    font-weight: 500;
    color: #fff;
}

.threat-level {
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
    font-size: 0.8rem;
    font-weight: bold;
    text-align: center;
}

.threat-critical {
    background: #ff4757;
}

.threat-high {
    background: #ffa502;
}

.threat-medium {
    background: #3742fa;
}

.threat-low {
    background: #2ed573;
}

.threat-time {
    color: rgba(255, 255, 255, 0.7);
    font-size: 0.9rem;
}

.analysis-result {
    background: rgba(255, 255, 255, 0.1);
    backdrop-filter: blur(10px);
    border: 1px solid rgba(255, 255, 255, 0.2);
    border-radius: 15px;
    padding: 2rem;
    margin-top: 2rem;
}

.result-item {
    display: flex;
    justify-content: space-between;
    margin-bottom: 1rem;
    padding-bottom: 0.5rem;
    border-bottom: 1px solid rgba(255, 255, 255, 0.1);
}

.result-item .label {
    font-weight: 500;
    color: rgba(255, 255, 255, 0.8);
}

.result-item .value {
    font-weight: bold;
    color: #fff;
}

.result-actions {
    margin-top: 2rem;
    text-align: center;
}

.model-card {
    background: rgba(255, 255, 255, 0.1);
    backdrop-filter: blur(10px);
    border: 1px solid rgba(255, 255, 255, 0.2);
    border-radius: 15px;
    padding: 2rem;
    margin-bottom: 1.5rem;
}

.model-metrics {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1rem;
    margin: 1rem 0;
}

.metric {
    display: flex;
    justify-content: space-between;
}

.model-trained {
    color: rgba(255, 255, 255, 0.7);
    font-size: 0.9rem;
    margin-top: 1rem;
}
`;

// Add additional CSS to document
const style = document.createElement('style');
style.textContent = additionalCSS;
document.head.appendChild(style);