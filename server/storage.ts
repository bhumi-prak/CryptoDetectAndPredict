import type { User, InsertUser, ThreatDetection, InsertThreatDetection, MlModel, InsertMlModel, FileAnalysis, InsertFileAnalysis } from '../shared/schema';

export interface IStorage {
  // User management
  createUser(user: InsertUser): Promise<User>;
  getUserByEmail(email: string): Promise<User | null>;
  getUserById(id: number): Promise<User | null>;
  
  // Threat detection
  createThreatDetection(detection: InsertThreatDetection): Promise<ThreatDetection>;
  getThreatDetectionsByUser(userId: number): Promise<ThreatDetection[]>;
  getAllThreatDetections(): Promise<ThreatDetection[]>;
  updateThreatDetection(id: number, updates: Partial<ThreatDetection>): Promise<ThreatDetection>;
  
  // ML Models
  createMlModel(model: InsertMlModel): Promise<MlModel>;
  getActiveMlModel(): Promise<MlModel | null>;
  getAllMlModels(): Promise<MlModel[]>;
  updateMlModel(id: number, updates: Partial<MlModel>): Promise<MlModel>;
  
  // File analysis
  createFileAnalysis(analysis: InsertFileAnalysis): Promise<FileAnalysis>;
  getFileAnalysisByUser(userId: number): Promise<FileAnalysis[]>;
  updateFileAnalysis(id: number, updates: Partial<FileAnalysis>): Promise<FileAnalysis>;
  getFileAnalysisById(id: number): Promise<FileAnalysis | null>;
}

class MemStorage implements IStorage {
  private users: User[] = [];
  private threatDetections: ThreatDetection[] = [];
  private mlModels: MlModel[] = [];
  private fileAnalyses: FileAnalysis[] = [];
  private nextId = 1;

  async createUser(user: InsertUser): Promise<User> {
    const newUser: User = {
      id: this.nextId++,
      ...user,
      createdAt: new Date(),
    };
    this.users.push(newUser);
    return newUser;
  }

  async getUserByEmail(email: string): Promise<User | null> {
    return this.users.find(u => u.email === email) || null;
  }

  async getUserById(id: number): Promise<User | null> {
    return this.users.find(u => u.id === id) || null;
  }

  async createThreatDetection(detection: InsertThreatDetection): Promise<ThreatDetection> {
    const newDetection: ThreatDetection = {
      id: this.nextId++,
      userId: detection.userId || null,
      fileName: detection.fileName,
      filePath: detection.filePath,
      threatLevel: detection.threatLevel,
      threatType: detection.threatType,
      confidence: detection.confidence,
      mlPrediction: detection.mlPrediction,
      fileSize: detection.fileSize || null,
      entropy: detection.entropy || null,
      features: detection.features || null,
      isQuarantined: detection.isQuarantined || false,
      detectedAt: new Date(),
    };
    this.threatDetections.push(newDetection);
    return newDetection;
  }

  async getThreatDetectionsByUser(userId: number): Promise<ThreatDetection[]> {
    return this.threatDetections.filter(t => t.userId === userId);
  }

  async getAllThreatDetections(): Promise<ThreatDetection[]> {
    return this.threatDetections;
  }

  async updateThreatDetection(id: number, updates: Partial<ThreatDetection>): Promise<ThreatDetection> {
    const index = this.threatDetections.findIndex(t => t.id === id);
    if (index === -1) throw new Error('Threat detection not found');
    
    this.threatDetections[index] = { ...this.threatDetections[index], ...updates };
    return this.threatDetections[index];
  }

  async createMlModel(model: InsertMlModel): Promise<MlModel> {
    const newModel: MlModel = {
      id: this.nextId++,
      modelName: model.modelName,
      algorithm: model.algorithm,
      accuracy: model.accuracy,
      precision: model.precision,
      recall: model.recall,
      f1Score: model.f1Score,
      trainingDataSize: model.trainingDataSize || null,
      features: model.features || null,
      modelPath: model.modelPath || null,
      isActive: model.isActive || false,
      trainedAt: new Date(),
    };
    this.mlModels.push(newModel);
    return newModel;
  }

  async getActiveMlModel(): Promise<MlModel | null> {
    return this.mlModels.find(m => m.isActive) || null;
  }

  async getAllMlModels(): Promise<MlModel[]> {
    return this.mlModels;
  }

  async updateMlModel(id: number, updates: Partial<MlModel>): Promise<MlModel> {
    const index = this.mlModels.findIndex(m => m.id === id);
    if (index === -1) throw new Error('ML model not found');
    
    this.mlModels[index] = { ...this.mlModels[index], ...updates };
    return this.mlModels[index];
  }

  async createFileAnalysis(analysis: InsertFileAnalysis): Promise<FileAnalysis> {
    const newAnalysis: FileAnalysis = {
      id: this.nextId++,
      userId: analysis.userId || null,
      fileName: analysis.fileName,
      filePath: analysis.filePath,
      status: analysis.status,
      analysisResult: analysis.analysisResult || null,
      uploadedAt: new Date(),
      completedAt: null,
    };
    this.fileAnalyses.push(newAnalysis);
    return newAnalysis;
  }

  async getFileAnalysisByUser(userId: number): Promise<FileAnalysis[]> {
    return this.fileAnalyses.filter(f => f.userId === userId);
  }

  async updateFileAnalysis(id: number, updates: Partial<FileAnalysis>): Promise<FileAnalysis> {
    const index = this.fileAnalyses.findIndex(f => f.id === id);
    if (index === -1) throw new Error('File analysis not found');
    
    this.fileAnalyses[index] = { ...this.fileAnalyses[index], ...updates };
    return this.fileAnalyses[index];
  }

  async getFileAnalysisById(id: number): Promise<FileAnalysis | null> {
    return this.fileAnalyses.find(f => f.id === id) || null;
  }
}

export const storage = new MemStorage();