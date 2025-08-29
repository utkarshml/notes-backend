import express, { Application, Request, Response } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';

import { connectDatabase } from './utils/database';
import { authRoutes } from './routes/auth';
import { notesRoutes } from './routes/notes';
import { errorHandler, notFound } from './middleware/errorHandler';
import { generalLimiter } from './middleware/rateLimiter';
import { cleanupExpiredOTPs } from './utils/otp';
import { ApiResponse } from './types';

// Load environment variables
dotenv.config();

class App {
  public app: Application;
  private readonly PORT = process.env.PORT || 5000;

  constructor() {
    this.app = express();
    this.initializeMiddlewares();
    this.initializeRoutes();
    this.initializeErrorHandling();
    this.setupPeriodicTasks();
  }

  private initializeMiddlewares(): void {
    // Security middleware
    this.app.use(helmet({
      crossOriginEmbedderPolicy: false,
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          scriptSrc: ["'self'"],
          imgSrc: ["'self'", "data:", "https:"],
        },
      },
    }));

    // CORS configuration
    this.app.use(cors({
      origin: process.env.FRONTEND_URL || 'http://localhost:3000',
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
      allowedHeaders: ['Content-Type', 'Authorization'],
    }));

    // Rate limiting
    this.app.use(generalLimiter);

    // Body parsing middleware
    this.app.use(express.json({ limit: '10mb' }));
    this.app.use(express.urlencoded({ extended: true, limit: '10mb' }));
    this.app.use(cookieParser());

    // Trust proxy for rate limiting behind reverse proxy
    this.app.set('trust proxy', 1);

    // Request logging in development
    if (process.env.NODE_ENV === 'development') {
      this.app.use((req, res, next) => {
        console.log(`${req.method} ${req.path} - ${new Date().toISOString()}`);
        next();
      });
    }
  }

  private initializeRoutes(): void {
    // Health check route
    this.app.get('/health', (req: Request, res: Response<ApiResponse>) => {
      res.status(200).json({
        success: true,
        message: 'Server is healthy',
        data: {
          timestamp: new Date().toISOString(),
          uptime: process.uptime(),
          memory: process.memoryUsage(),
          environment: process.env.NODE_ENV || 'development'
        }
      });
    });

    // API routes
    this.app.use('/api/auth', authRoutes);
    this.app.use('/api/notes', notesRoutes);

    // API info route
    this.app.get('/api', (req: Request, res: Response<ApiResponse>) => {
      res.status(200).json({
        success: true,
        message: 'Notes API v1.0.0',
        data: {
          version: '1.0.0',
          endpoints: {
            auth: '/api/auth',
            notes: '/api/notes',
            health: '/health'
          }
        }
      });
    });
  }

  private initializeErrorHandling(): void {
    // 404 handler
    this.app.use(notFound);

    // Global error handler
    this.app.use(errorHandler);
  }

  private setupPeriodicTasks(): void {
    // Clean up expired OTPs every 10 minutes
    setInterval(() => {
      cleanupExpiredOTPs().catch(console.error);
    }, 10 * 60 * 1000);
  }

  public async start(): Promise<void> {
    try {
      // Connect to database
      await connectDatabase();

      // Start server
      this.app.listen(this.PORT, () => {
        console.log(`
🚀 Server is running!
📍 Port: ${this.PORT}
🌍 Environment: ${process.env.NODE_ENV || 'development'}
📚 API Documentation: http://localhost:${this.PORT}/api
💚 Health Check: http://localhost:${this.PORT}/health
        `);
      });

      // Graceful shutdown
      process.on('SIGTERM', this.gracefulShutdown);
      process.on('SIGINT', this.gracefulShutdown);

    } catch (error) {
      console.error('❌ Failed to start server:', error);
      process.exit(1);
    }
  }

  private gracefulShutdown = (signal: string): void => {
    console.log(`\n🛑 Received ${signal}. Starting graceful shutdown...`);
    
    // Close server
    process.exit(0);
  };
}

// Start the application
const app = new App();
app.start().catch(console.error);

export default app.app;
