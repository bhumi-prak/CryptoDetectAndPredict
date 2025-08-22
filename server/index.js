const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const { spawn } = require('child_process');

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../client')));

// In-memory storage for demo
let users = [];
let threatDetections = [];
let mlModels = [];
let fileAnalyses = [];
let nextId = 1;

// Authentication routes
app.post('/api/auth/signup', (req, res) => {
    const { email, password, name } = req.body;
    
    // Check if user exists
    const existingUser = users.find(u => u.email === email);
    if (existingUser) {
        return res.status(400).json({ error: 'User already exists' });
    }
    
    const newUser = {
        id: nextId++,
        email,
        password, // In production, hash this
        name,
        createdAt: new Date()
    };
    
    users.push(newUser);
    const { password: _, ...userWithoutPassword } = newUser;
    res.status(201).json({ user: userWithoutPassword });
});

app.post('/api/auth/login', (req, res) => {
    const { email, password } = req.body;
    
    const user = users.find(u => u.email === email && u.password === password);
    if (!user) {
        return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const { password: _, ...userWithoutPassword } = user;
    res.json({ user: userWithoutPassword });
});

// Threat detection routes
app.get('/api/threats', (req, res) => {
    res.json(threatDetections);
});

app.post('/api/threats', (req, res) => {
    const newThreat = {
        id: nextId++,
        ...req.body,
        detectedAt: new Date()
    };
    threatDetections.push(newThreat);
    res.status(201).json(newThreat);
});

// ML Model routes
app.get('/api/models', (req, res) => {
    res.json(mlModels);
});

app.get('/api/models/active', (req, res) => {
    const activeModel = mlModels.find(m => m.isActive);
    res.json(activeModel || null);
});

// File analysis routes
app.post('/api/analyze', (req, res) => {
    const { fileName, userId } = req.body;
    
    const analysis = {
        id: nextId++,
        fileName,
        userId,
        status: 'ANALYZING',
        uploadedAt: new Date(),
        result: null
    };
    
    fileAnalyses.push(analysis);
    
    // Call Python ML service for analysis
    const pythonProcess = spawn('python3', ['ml_service/analyze_file.py', fileName]);
    
    pythonProcess.stdout.on('data', (data) => {
        try {
            const result = JSON.parse(data.toString());
            analysis.status = 'COMPLETED';
            analysis.result = result;
            analysis.completedAt = new Date();
        } catch (error) {
            analysis.status = 'FAILED';
            analysis.error = 'Analysis failed';
        }
    });
    
    pythonProcess.stderr.on('data', (data) => {
        console.error(`Python error: ${data}`);
        analysis.status = 'FAILED';
        analysis.error = data.toString();
    });
    
    res.status(201).json(analysis);
});

app.get('/api/analyze/:id', (req, res) => {
    const id = parseInt(req.params.id);
    const analysis = fileAnalyses.find(a => a.id === id);
    if (!analysis) {
        return res.status(404).json({ error: 'Analysis not found' });
    }
    res.json(analysis);
});

// ML Training route
app.post('/api/train', (req, res) => {
    const { algorithm = 'ensemble', datasetSize = 50000 } = req.body;
    
    res.json({ message: 'Training started with large dataset', status: 'TRAINING' });
    
    // Call Python training script with larger dataset
    const pythonProcess = spawn('python3', ['ml_service/train_model.py', algorithm, datasetSize.toString()]);
    
    pythonProcess.stdout.on('data', (data) => {
        try {
            const result = JSON.parse(data.toString());
            const newModel = {
                id: nextId++,
                modelName: `${algorithm}_large_dataset_${Date.now()}`,
                algorithm,
                accuracy: result.accuracy,
                precision: result.precision,
                recall: result.recall,
                f1Score: result.f1_score,
                trainingDataSize: datasetSize,
                features: result.features,
                trainedAt: new Date(),
                isActive: true
            };
            
            // Deactivate old models
            mlModels.forEach(m => m.isActive = false);
            mlModels.push(newModel);
            
        } catch (error) {
            console.error('Training result parsing error:', error);
        }
    });
    
    pythonProcess.stderr.on('data', (data) => {
        console.error(`Training error: ${data}`);
    });
});

// Serve static files
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../client/index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on http://0.0.0.0:${PORT}`);
});