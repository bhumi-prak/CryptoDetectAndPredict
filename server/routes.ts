import express from 'express';
import { storage } from './storage';
import { insertUserSchema, insertThreatDetectionSchema, insertMlModelSchema, insertFileAnalysisSchema } from '../shared/schema';

const router = express.Router();

// Authentication routes
router.post('/auth/signup', async (req, res) => {
  try {
    const userData = insertUserSchema.parse(req.body);
    
    // Check if user already exists
    const existingUser = await storage.getUserByEmail(userData.email);
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists with this email' });
    }
    
    // Create new user
    const user = await storage.createUser(userData);
    
    // Don't send password back
    const { password, ...userWithoutPassword } = user;
    res.status(201).json({ user: userWithoutPassword });
  } catch (error) {
    res.status(400).json({ error: 'Invalid user data' });
  }
});

router.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const user = await storage.getUserByEmail(email);
    if (!user || user.password !== password) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    
    // Don't send password back
    const { password: _, ...userWithoutPassword } = user;
    res.json({ user: userWithoutPassword });
  } catch (error) {
    res.status(500).json({ error: 'Login failed' });
  }
});

// Threat detection routes
router.get('/threats', async (req, res) => {
  try {
    const threats = await storage.getAllThreatDetections();
    res.json(threats);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch threats' });
  }
});

router.get('/threats/user/:userId', async (req, res) => {
  try {
    const userId = parseInt(req.params.userId);
    const threats = await storage.getThreatDetectionsByUser(userId);
    res.json(threats);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch user threats' });
  }
});

router.post('/threats', async (req, res) => {
  try {
    const threatData = insertThreatDetectionSchema.parse(req.body);
    const threat = await storage.createThreatDetection(threatData);
    res.status(201).json(threat);
  } catch (error) {
    res.status(400).json({ error: 'Invalid threat data' });
  }
});

router.patch('/threats/:id', async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const threat = await storage.updateThreatDetection(id, req.body);
    res.json(threat);
  } catch (error) {
    res.status(404).json({ error: 'Threat not found' });
  }
});

// ML Model routes
router.get('/models', async (req, res) => {
  try {
    const models = await storage.getAllMlModels();
    res.json(models);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch models' });
  }
});

router.get('/models/active', async (req, res) => {
  try {
    const model = await storage.getActiveMlModel();
    res.json(model);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch active model' });
  }
});

router.post('/models', async (req, res) => {
  try {
    const modelData = insertMlModelSchema.parse(req.body);
    const model = await storage.createMlModel(modelData);
    res.status(201).json(model);
  } catch (error) {
    res.status(400).json({ error: 'Invalid model data' });
  }
});

// File analysis routes
router.post('/analyze', async (req, res) => {
  try {
    const analysisData = insertFileAnalysisSchema.parse(req.body);
    const analysis = await storage.createFileAnalysis(analysisData);
    
    // Simulate ML analysis (in real app, this would call Python ML service)
    setTimeout(async () => {
      const mockResult = {
        threatLevel: Math.random() > 0.7 ? 'HIGH' : Math.random() > 0.4 ? 'MEDIUM' : 'LOW',
        confidence: Math.random() * 0.4 + 0.6, // 0.6-1.0
        features: {
          entropy: Math.random() * 8,
          fileSize: analysisData.fileName ? analysisData.fileName.length * 1000 : 1000,
          suspiciousPatterns: Math.floor(Math.random() * 5),
        }
      };
      
      await storage.updateFileAnalysis(analysis.id, {
        status: 'COMPLETED',
        analysisResult: mockResult,
        completedAt: new Date(),
      });
    }, 2000);
    
    res.status(201).json(analysis);
  } catch (error) {
    res.status(400).json({ error: 'Invalid analysis data' });
  }
});

router.get('/analyze/user/:userId', async (req, res) => {
  try {
    const userId = parseInt(req.params.userId);
    const analyses = await storage.getFileAnalysisByUser(userId);
    res.json(analyses);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch analyses' });
  }
});

router.get('/analyze/:id', async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const analysis = await storage.getFileAnalysisById(id);
    if (!analysis) {
      return res.status(404).json({ error: 'Analysis not found' });
    }
    res.json(analysis);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch analysis' });
  }
});

// ML Training simulation endpoint
router.post('/train', async (req, res) => {
  try {
    const { algorithm = 'RANDOM_FOREST', datasetSize = 10000 } = req.body;
    
    // Simulate training process
    res.json({ message: 'Training started', status: 'TRAINING' });
    
    // Simulate training completion after 5 seconds
    setTimeout(async () => {
      const mockAccuracy = 0.85 + Math.random() * 0.12; // 85-97%
      const mockPrecision = 0.80 + Math.random() * 0.15; // 80-95%
      const mockRecall = 0.78 + Math.random() * 0.17; // 78-95%
      const f1Score = 2 * (mockPrecision * mockRecall) / (mockPrecision + mockRecall);
      
      await storage.createMlModel({
        modelName: `${algorithm}_${Date.now()}`,
        algorithm,
        accuracy: mockAccuracy,
        precision: mockPrecision,
        recall: mockRecall,
        f1Score,
        trainingDataSize: datasetSize,
        features: ['entropy', 'fileSize', 'extensionRisk', 'behaviorPatterns'],
        modelPath: `/models/${algorithm}_${Date.now()}.pkl`,
        isActive: true,
      });
    }, 5000);
    
  } catch (error) {
    res.status(500).json({ error: 'Training failed' });
  }
});

export default router;