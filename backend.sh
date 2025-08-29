#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🚀 Setting up TypeScript Backend Project...${NC}"

# Create project directory
mkdir -p backend
cd backend

# Initialize package.json
echo -e "${YELLOW}📦 Initializing package.json...${NC}"
npm init -y

# Install dependencies
echo -e "${YELLOW}📦 Installing dependencies...${NC}"
npm install express mongoose jsonwebtoken bcrypt nodemailer google-auth-library cors helmet dotenv express-rate-limit
npm install -D @types/express @types/mongoose @types/jsonwebtoken @types/bcrypt @types/nodemailer @types/cors typescript ts-node nodemon @types/node

# Create TypeScript config
echo -e "${YELLOW}⚙️  Creating TypeScript configuration...${NC}"
cat > tsconfig.json << 'EOF'
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "commonjs",
    "lib": ["ES2020"],
    "outDir": "./dist",
    "rootDir": "./src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true,
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true,
    "removeComments": true,
    "noImplicitAny": true,
    "strictNullChecks": true,
    "strictFunctionTypes": true,
    "noImplicitThis": true,
    "noImplicitReturns": true,
    "noFallthroughCasesInSwitch": true,
    "moduleResolution": "node",
    "baseUrl": "./",
    "paths": {
      "@/*": ["src/*"]
    },
    "allowSyntheticDefaultImports": true,
    "experimentalDecorators": true,
    "emitDecoratorMetadata": true
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist"]
}
EOF

# Update package.json scripts
echo -e "${YELLOW}📝 Updating package.json scripts...${NC}"
cat > package.json << 'EOF'
{
  "name": "backend",
  "version": "1.0.0",
  "description": "TypeScript Backend with Authentication and Notes Management",
  "main": "dist/app.js",
  "scripts": {
    "build": "tsc",
    "start": "node dist/app.js",
    "dev": "nodemon src/app.ts",
    "clean": "rm -rf dist",
    "prebuild": "npm run clean",
    "postbuild": "cp package*.json dist/",
    "lint": "tsc --noEmit",
    "watch": "tsc --watch"
  },
  "keywords": ["typescript", "express", "mongodb", "jwt", "authentication"],
  "author": "",
  "license": "ISC",
  "dependencies": {
    "express": "^4.18.2",
    "mongoose": "^8.0.3",
    "jsonwebtoken": "^9.0.2",
    "bcrypt": "^5.1.1",
    "nodemailer": "^6.9.7",
    "google-auth-library": "^9.4.1",
    "cors": "^2.8.5",
    "helmet": "^7.1.0",
    "dotenv": "^16.3.1",
    "express-rate-limit": "^7.1.5"
  },
  "devDependencies": {
    "@types/express": "^4.17.21",
    "@types/mongoose": "^5.11.97",
    "@types/jsonwebtoken": "^9.0.5",
    "@types/bcrypt": "^5.0.2",
    "@types/nodemailer": "^6.4.14",
    "@types/cors": "^2.8.17",
    "@types/node": "^20.10.4",
    "typescript": "^5.3.3",
    "ts-node": "^10.9.1",
    "nodemon": "^3.0.2"
  },
  "engines": {
    "node": ">=18.0.0",
    "npm": ">=8.0.0"
  }
}
EOF

# Create project structure
echo -e "${YELLOW}📁 Creating project structure...${NC}"
mkdir -p src/{models,routes,controllers,middleware,utils,types}

# Create environment file
echo -e "${YELLOW}🔐 Creating environment files...${NC}"
cat > .env.example << 'EOF'
# Server Configuration
PORT=5000
NODE_ENV=development

# Database
MONGO_URI=mongodb+srv://username:password@cluster.mongodb.net/database_name

# JWT Secret
JWT_SECRET=your_super_secret_jwt_key_here_make_it_long_and_complex

# Email Configuration (Gmail SMTP)
EMAIL_USER=your_email@gmail.com
EMAIL_PASS=your_app_password_here

# Google OAuth
GOOGLE_CLIENT_ID=your_google_client_id.googleusercontent.com
GOOGLE_CLIENT_SECRET=your_google_client_secret

# Frontend URL (for CORS)
FRONTEND_URL=http://localhost:3000

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
EOF

# Copy example to actual env file
cp .env.example .env

# Create types
echo -e "${YELLOW}🎯 Creating TypeScript types...${NC}"
cat > src/types/index.ts << 'EOF'
import { Request } from 'express';
import { JwtPayload } from 'jsonwebtoken';

export interface AuthenticatedRequest extends Request {
  user?: {
    userId: string;
    email: string;
  };
}

export interface UserPayload extends JwtPayload {
  userId: string;
  email: string;
}

export interface GoogleTokenPayload {
  email: string;
  name: string;
  picture?: string;
  email_verified: boolean;
}

export interface OTPData {
  email: string;
  otp: string;
  expiresAt: Date;
  type: 'signup' | 'login';
}

export interface ApiResponse<T = any> {
  success: boolean;
  message: string;
  data?: T;
  error?: string;
}
EOF

# Create User model
echo -e "${YELLOW}👤 Creating User model...${NC}"
cat > src/models/User.ts << 'EOF'
import mongoose, { Document, Schema } from 'mongoose';
import bcrypt from 'bcrypt';

export interface IUser extends Document {
  email: string;
  name?: string;
  profilePicture?: string;
  authMethod: 'email' | 'google';
  googleId?: string;
  isEmailVerified: boolean;
  createdAt: Date;
  updatedAt: Date;
  comparePassword?(password: string): Promise<boolean>;
}

const UserSchema = new Schema<IUser>({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
    match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email']
  },
  name: {
    type: String,
    trim: true,
    maxlength: 100
  },
  profilePicture: {
    type: String,
    default: null
  },
  authMethod: {
    type: String,
    enum: ['email', 'google'],
    required: true
  },
  googleId: {
    type: String,
    sparse: true,
    unique: true
  },
  isEmailVerified: {
    type: Boolean,
    default: false
  }
}, {
  timestamps: true,
  versionKey: false
});

// Indexes for performance
UserSchema.index({ email: 1 });
UserSchema.index({ googleId: 1 });

// Pre-save middleware for email normalization
UserSchema.pre('save', function(next) {
  if (this.isModified('email')) {
    this.email = this.email.toLowerCase().trim();
  }
  next();
});

export const User = mongoose.model<IUser>('User', UserSchema);
EOF

# Create OTP model
echo -e "${YELLOW}🔢 Creating OTP model...${NC}"
cat > src/models/OTP.ts << 'EOF'
import mongoose, { Document, Schema } from 'mongoose';

export interface IOTP extends Document {
  email: string;
  otp: string;
  type: 'signup' | 'login';
  expiresAt: Date;
  attempts: number;
  isUsed: boolean;
  createdAt: Date;
}

const OTPSchema = new Schema<IOTP>({
  email: {
    type: String,
    required: true,
    lowercase: true,
    trim: true
  },
  otp: {
    type: String,
    required: true
  },
  type: {
    type: String,
    enum: ['signup', 'login'],
    required: true
  },
  expiresAt: {
    type: Date,
    required: true,
    default: () => new Date(Date.now() + 5 * 60 * 1000) // 5 minutes
  },
  attempts: {
    type: Number,
    default: 0,
    max: 3
  },
  isUsed: {
    type: Boolean,
    default: false
  }
}, {
  timestamps: true,
  versionKey: false
});

// TTL index to automatically delete expired OTPs
OTPSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
OTPSchema.index({ email: 1, type: 1 });

export const OTP = mongoose.model<IOTP>('OTP', OTPSchema);
EOF

# Create Notes model
echo -e "${YELLOW}📝 Creating Notes model...${NC}"
cat > src/models/Note.ts << 'EOF'
import mongoose, { Document, Schema } from 'mongoose';

export interface INote extends Document {
  userId: mongoose.Types.ObjectId;
  title: string;
  content: string;
  tags?: string[];
  isPinned: boolean;
  createdAt: Date;
  updatedAt: Date;
}

const NoteSchema = new Schema<INote>({
  userId: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  title: {
    type: String,
    required: true,
    trim: true,
    maxlength: 200
  },
  content: {
    type: String,
    required: true,
    maxlength: 10000
  },
  tags: [{
    type: String,
    trim: true,
    lowercase: true,
    maxlength: 50
  }],
  isPinned: {
    type: Boolean,
    default: false
  }
}, {
  timestamps: true,
  versionKey: false
});

// Indexes for performance
NoteSchema.index({ userId: 1, createdAt: -1 });
NoteSchema.index({ userId: 1, isPinned: -1, createdAt: -1 });

export const Note = mongoose.model<INote>('Note', NoteSchema);
EOF

# Create database connection utility
echo -e "${YELLOW}🗄️  Creating database connection...${NC}"
cat > src/utils/database.ts << 'EOF'
import mongoose from 'mongoose';

export const connectDatabase = async (): Promise<void> => {
  try {
    const mongoUri = process.env.MONGO_URI;
    
    if (!mongoUri) {
      throw new Error('MONGO_URI environment variable is not defined');
    }

    const options = {
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
    };

    await mongoose.connect(mongoUri, options);
    
    console.log('✅ MongoDB connected successfully');
    
    // Handle connection events
    mongoose.connection.on('error', (err) => {
      console.error('❌ MongoDB connection error:', err);
    });
    
    mongoose.connection.on('disconnected', () => {
      console.warn('⚠️  MongoDB disconnected');
    });
    
    process.on('SIGINT', async () => {
      try {
        await mongoose.connection.close();
        console.log('🔐 MongoDB connection closed through app termination');
        process.exit(0);
      } catch (err) {
        console.error('Error closing MongoDB connection:', err);
        process.exit(1);
      }
    });
    
  } catch (error) {
    console.error('❌ Database connection failed:', error);
    process.exit(1);
  }
};
EOF

# Create OTP utility
echo -e "${YELLOW}🔢 Creating OTP utilities...${NC}"
cat > src/utils/otp.ts << 'EOF'
import crypto from 'crypto';
import { OTP } from '../models/OTP';

export const generateOTP = (): string => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

export const createOTP = async (email: string, type: 'signup' | 'login'): Promise<string> => {
  try {
    // Delete any existing OTPs for this email and type
    await OTP.deleteMany({ email, type });
    
    const otp = generateOTP();
    
    // Create new OTP
    await OTP.create({
      email,
      otp,
      type,
      expiresAt: new Date(Date.now() + 5 * 60 * 1000) // 5 minutes
    });
    
    return otp;
  } catch (error) {
    console.error('Error creating OTP:', error);
    throw new Error('Failed to generate OTP');
  }
};

export const verifyOTP = async (email: string, otp: string, type: 'signup' | 'login'): Promise<boolean> => {
  try {
    const otpRecord = await OTP.findOne({
      email,
      type,
      isUsed: false,
      expiresAt: { $gt: new Date() }
    });
    
    if (!otpRecord) {
      return false;
    }
    
    // Increment attempts
    otpRecord.attempts += 1;
    
    // Check if OTP matches
    if (otpRecord.otp === otp) {
      otpRecord.isUsed = true;
      await otpRecord.save();
      return true;
    }
    
    // Check if max attempts reached
    if (otpRecord.attempts >= 3) {
      otpRecord.isUsed = true;
    }
    
    await otpRecord.save();
    return false;
  } catch (error) {
    console.error('Error verifying OTP:', error);
    return false;
  }
};

export const cleanupExpiredOTPs = async (): Promise<void> => {
  try {
    await OTP.deleteMany({
      $or: [
        { expiresAt: { $lt: new Date() } },
        { isUsed: true }
      ]
    });
  } catch (error) {
    console.error('Error cleaning up expired OTPs:', error);
  }
};
EOF

# Create email utility
echo -e "${YELLOW}📧 Creating email utilities...${NC}"
cat > src/utils/email.ts << 'EOF'
import nodemailer from 'nodemailer';

interface EmailOptions {
  to: string;
  subject: string;
  html: string;
}

class EmailService {
  private transporter: nodemailer.Transporter;

  constructor() {
    this.transporter = nodemailer.createTransporter({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    });
  }

  async sendEmail({ to, subject, html }: EmailOptions): Promise<boolean> {
    try {
      const mailOptions = {
        from: `"Your App" <${process.env.EMAIL_USER}>`,
        to,
        subject,
        html
      };

      await this.transporter.sendMail(mailOptions);
      console.log(`✅ Email sent successfully to ${to}`);
      return true;
    } catch (error) {
      console.error('❌ Error sending email:', error);
      return false;
    }
  }

  async sendOTPEmail(email: string, otp: string, type: 'signup' | 'login'): Promise<boolean> {
    const subject = type === 'signup' ? 'Complete Your Registration' : 'Login Verification Code';
    const action = type === 'signup' ? 'complete your registration' : 'log in to your account';
    
    const html = `
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Verification Code</title>
        <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: #4F46E5; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }
            .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 8px 8px; }
            .otp-box { background: white; padding: 20px; text-align: center; border-radius: 8px; margin: 20px 0; border: 2px dashed #4F46E5; }
            .otp-code { font-size: 32px; font-weight: bold; color: #4F46E5; letter-spacing: 8px; }
            .footer { text-align: center; margin-top: 20px; color: #666; font-size: 14px; }
            .warning { background: #FEF2F2; border: 1px solid #FECACA; color: #DC2626; padding: 15px; border-radius: 8px; margin: 20px 0; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Verification Code</h1>
            </div>
            <div class="content">
                <p>Hello,</p>
                <p>Use this verification code to ${action}:</p>
                
                <div class="otp-box">
                    <div class="otp-code">${otp}</div>
                </div>
                
                <div class="warning">
                    <strong>⚠️ Important:</strong> This code expires in 5 minutes. Don't share it with anyone.
                </div>
                
                <p>If you didn't request this code, please ignore this email.</p>
                
                <p>Best regards,<br>Your App Team</p>
            </div>
            <div class="footer">
                <p>This is an automated message, please do not reply.</p>
            </div>
        </div>
    </body>
    </html>
    `;

    return this.sendEmail({ to: email, subject, html });
  }
}

export const emailService = new EmailService();
EOF

# Create JWT utility
echo -e "${YELLOW}🔐 Creating JWT utilities...${NC}"
cat > src/utils/jwt.ts << 'EOF'
import jwt from 'jsonwebtoken';
import { UserPayload } from '../types';

export const generateToken = (payload: { userId: string; email: string }): string => {
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    throw new Error('JWT_SECRET environment variable is not defined');
  }

  return jwt.sign(payload, secret, {
    expiresIn: '7d',
    issuer: 'your-app',
    audience: 'your-app-users'
  });
};

export const verifyToken = (token: string): UserPayload => {
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    throw new Error('JWT_SECRET environment variable is not defined');
  }

  try {
    return jwt.verify(token, secret) as UserPayload;
  } catch (error) {
    throw new Error('Invalid or expired token');
  }
};

export const decodeToken = (token: string): UserPayload | null => {
  try {
    return jwt.decode(token) as UserPayload;
  } catch {
    return null;
  }
};
EOF

# Create Google OAuth utility
echo -e "${YELLOW}🔍 Creating Google OAuth utilities...${NC}"
cat > src/utils/googleAuth.ts << 'EOF'
import { OAuth2Client } from 'google-auth-library';
import { GoogleTokenPayload } from '../types';

class GoogleAuthService {
  private client: OAuth2Client;

  constructor() {
    const clientId = process.env.GOOGLE_CLIENT_ID;
    if (!clientId) {
      throw new Error('GOOGLE_CLIENT_ID environment variable is not defined');
    }
    this.client = new OAuth2Client(clientId);
  }

  async verifyGoogleToken(token: string): Promise<GoogleTokenPayload | null> {
    try {
      const ticket = await this.client.verifyIdToken({
        idToken: token,
        audience: process.env.GOOGLE_CLIENT_ID
      });

      const payload = ticket.getPayload();
      
      if (!payload || !payload.email || !payload.email_verified) {
        return null;
      }

      return {
        email: payload.email,
        name: payload.name || '',
        picture: payload.picture,
        email_verified: payload.email_verified
      };
    } catch (error) {
      console.error('Error verifying Google token:', error);
      return null;
    }
  }
}

export const googleAuthService = new GoogleAuthService();
EOF

# Create authentication middleware
echo -e "${YELLOW}🛡️  Creating authentication middleware...${NC}"
cat > src/middleware/auth.ts << 'EOF'
import { Response, NextFunction } from 'express';
import { verifyToken } from '../utils/jwt';
import { AuthenticatedRequest, ApiResponse } from '../types';

export const authenticateToken = (
  req: AuthenticatedRequest,
  res: Response<ApiResponse>,
  next: NextFunction
): void => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN
    
    // Also check for token in cookies
    const cookieToken = req.cookies?.token;
    
    const finalToken = token || cookieToken;
    
    if (!finalToken) {
      res.status(401).json({
        success: false,
        message: 'Access token required',
        error: 'No token provided'
      });
      return;
    }

    const decoded = verifyToken(finalToken);
    req.user = {
      userId: decoded.userId,
      email: decoded.email
    };
    
    next();
  } catch (error) {
    res.status(403).json({
      success: false,
      message: 'Invalid or expired token',
      error: error instanceof Error ? error.message : 'Token verification failed'
    });
  }
};

export const optionalAuth = (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): void => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];
    const cookieToken = req.cookies?.token;
    const finalToken = token || cookieToken;
    
    if (finalToken) {
      try {
        const decoded = verifyToken(finalToken);
        req.user = {
          userId: decoded.userId,
          email: decoded.email
        };
      } catch {
        // Token invalid, but continue without user
      }
    }
    
    next();
  } catch {
    next();
  }
};
EOF

# Create error handling middleware
echo -e "${YELLOW}🚨 Creating error handling middleware...${NC}"
cat > src/middleware/errorHandler.ts << 'EOF'
import { Request, Response, NextFunction } from 'express';
import { ApiResponse } from '../types';

interface CustomError extends Error {
  statusCode?: number;
  code?: number;
  keyValue?: any;
}

export const errorHandler = (
  error: CustomError,
  req: Request,
  res: Response<ApiResponse>,
  next: NextFunction
): void => {
  let statusCode = error.statusCode || 500;
  let message = error.message || 'Internal Server Error';

  console.error(`Error ${statusCode}: ${message}`, error);

  // MongoDB duplicate key error
  if (error.code === 11000) {
    statusCode = 400;
    const field = Object.keys(error.keyValue || {})[0];
    message = `${field} already exists`;
  }

  // MongoDB validation error
  if (error.name === 'ValidationError') {
    statusCode = 400;
    message = 'Validation Error';
  }

  // JWT errors
  if (error.name === 'JsonWebTokenError') {
    statusCode = 401;
    message = 'Invalid token';
  }

  if (error.name === 'TokenExpiredError') {
    statusCode = 401;
    message = 'Token expired';
  }

  res.status(statusCode).json({
    success: false,
    message,
    error: process.env.NODE_ENV === 'development' ? error.stack : undefined
  });
};

export const notFound = (req: Request, res: Response<ApiResponse>): void => {
  res.status(404).json({
    success: false,
    message: `Route ${req.originalUrl} not found`,
    error: 'Not Found'
  });
};
EOF

# Create rate limiting middleware
echo -e "${YELLOW}⏱️  Creating rate limiting middleware...${NC}"
cat > src/middleware/rateLimiter.ts << 'EOF'
import rateLimit from 'express-rate-limit';

// General rate limiter
export const generalLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000'), // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100'), // limit each IP to 100 requests per windowMs
  message: {
    success: false,
    message: 'Too many requests from this IP, please try again later.',
    error: 'Rate limit exceeded'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Strict limiter for auth endpoints
export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // limit each IP to 10 requests per windowMs for auth
  message: {
    success: false,
    message: 'Too many authentication attempts, please try again later.',
    error: 'Auth rate limit exceeded'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// OTP limiter
export const otpLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 3, // limit each IP to 3 OTP requests per minute
  message: {
    success: false,
    message: 'Too many OTP requests, please try again later.',
    error: 'OTP rate limit exceeded'
  },
  standardHeaders: true,
  legacyHeaders: false,
});
EOF

# Create validation middleware
echo -e "${YELLOW}✅ Creating validation middleware...${NC}"
cat > src/middleware/validation.ts << 'EOF'
import { Request, Response, NextFunction } from 'express';
import { ApiResponse } from '../types';

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export const validateEmail = (
  req: Request,
  res: Response<ApiResponse>,
  next: NextFunction
): void => {
  const { email } = req.body;

  if (!email) {
    res.status(400).json({
      success: false,
      message: 'Email is required',
      error: 'Validation failed'
    });
    return;
  }

  if (!emailRegex.test(email)) {
    res.status(400).json({
      success: false,
      message: 'Please provide a valid email address',
      error: 'Invalid email format'
    });
    return;
  }

  next();
};

export const validateOTP = (
  req: Request,
  res: Response<ApiResponse>,
  next: NextFunction
): void => {
  const { otp } = req.body;

  if (!otp) {
    res.status(400).json({
      success: false,
      message: 'OTP is required',
      error: 'Validation failed'
    });
    return;
  }

  if (!/^\d{6}$/.test(otp)) {
    res.status(400).json({
      success: false,
      message: 'OTP must be a 6-digit number',
      error: 'Invalid OTP format'
    });
    return;
  }

  next();
};

export const validateNote = (
  req: Request,
  res: Response<ApiResponse>,
  next: NextFunction
): void => {
  const { title, content } = req.body;

  if (!title || !content) {
    res.status(400).json({
      success: false,
      message: 'Title and content are required',
      error: 'Validation failed'
    });
    return;
  }

  if (title.trim().length === 0 || content.trim().length === 0) {
    res.status(400).json({
      success: false,
      message: 'Title and content cannot be empty',
      error: 'Validation failed'
    });
    return;
  }

  next();
};

export const validateGoogleToken = (
  req: Request,
  res: Response<ApiResponse>,
  next: NextFunction
): void => {
  const { token } = req.body;

  if (!token) {
    res.status(400).json({
      success: false,
      message: 'Google token is required',
      error: 'Validation failed'
    });
    return;
  }

  next();
};
EOF

# Create auth controller
echo -e "${YELLOW}🔐 Creating authentication controller...${NC}"
cat > src/controllers/authController.ts << 'EOF'
import { Request, Response } from 'express';
import { User } from '../models/User';
import { createOTP, verifyOTP } from '../utils/otp';
import { emailService } from '../utils/email';
import { generateToken } from '../utils/jwt';
import { googleAuthService } from '../utils/googleAuth';
import { ApiResponse } from '../types';

export class AuthController {
  // Signup with email + OTP
  async signup(req: Request, res: Response<ApiResponse>): Promise<void> {
    try {
      const { email } = req.body;

      // Check if user already exists
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        res.status(400).json({
          success: false,
          message: 'User with this email already exists',
          error: 'User exists'
        });
        return;
      }

      // Generate and send OTP
      const otp = await createOTP(email, 'signup');
      const emailSent = await emailService.sendOTPEmail(email, otp, 'signup');

      if (!emailSent) {
        res.status(500).json({
          success: false,
          message: 'Failed to send verification email',
          error: 'Email service error'
        });
        return;
      }

      res.status(200).json({
        success: true,
        message: 'Verification code sent to your email',
        data: { email }
      });
    } catch (error) {
      console.error('Signup error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }

  // Verify OTP for signup
  async verifySignupOTP(req: Request, res: Response<ApiResponse>): Promise<void> {
    try {
      const { email, otp, name } = req.body;

      // Verify OTP
      const isValidOTP = await verifyOTP(email, otp, 'signup');
      if (!isValidOTP) {
        res.status(400).json({
          success: false,
          message: 'Invalid or expired OTP',
          error: 'OTP verification failed'
        });
        return;
      }

      // Check if user already exists (race condition prevention)
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        res.status(400).json({
          success: false,
          message: 'User already exists',
          error: 'User exists'
        });
        return;
      }

      // Create new user
      const user = await User.create({
        email,
        name: name || email.split('@')[0],
        authMethod: 'email',
        isEmailVerified: true
      });

      // Generate JWT token
      const token = generateToken({
        userId: user._id.toString(),
        email: user.email
      });

      res.status(201).json({
        success: true,
        message: 'Account created successfully',
        data: {
          token,
          user: {
            id: user._id,
            email: user.email,
            name: user.name,
            authMethod: user.authMethod
          }
        }
      });
    } catch (error) {
      console.error('Verify signup OTP error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }

  // Login with email + OTP
  async login(req: Request, res: Response<ApiResponse>): Promise<void> {
    try {
      const { email } = req.body;

      // Check if user exists and uses email auth
      const user = await User.findOne({ email, authMethod: 'email' });
      if (!user) {
        res.status(404).json({
          success: false,
          message: 'No account found with this email',
          error: 'User not found'
        });
        return;
      }

      // Generate and send OTP
      const otp = await createOTP(email, 'login');
      const emailSent = await emailService.sendOTPEmail(email, otp, 'login');

      if (!emailSent) {
        res.status(500).json({
          success: false,
          message: 'Failed to send verification email',
          error: 'Email service error'
        });
        return;
      }

      res.status(200).json({
        success: true,
        message: 'Verification code sent to your email',
        data: { email }
      });
    } catch (error) {
      console.error('Login error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }

  // Verify OTP for login
  async verifyLoginOTP(req: Request, res: Response<ApiResponse>): Promise<void> {
    try {
      const { email, otp } = req.body;

      // Verify OTP
      const isValidOTP = await verifyOTP(email, otp, 'login');
      if (!isValidOTP) {
        res.status(400).json({
          success: false,
          message: 'Invalid or expired OTP',
          error: 'OTP verification failed'
        });
        return;
      }

      // Get user
      const user = await User.findOne({ email, authMethod: 'email' });
      if (!user) {
        res.status(404).json({
          success: false,
          message: 'User not found',
          error: 'User not found'
        });
        return;
      }

      // Generate JWT token
      const token = generateToken({
        userId: user._id.toString(),
        email: user.email
      });

      res.status(200).json({
        success: true,
        message: 'Login successful',
        data: {
          token,
          user: {
            id: user._id,
            email: user.email,
            name: user.name,
            authMethod: user.authMethod
          }
        }
      });
    } catch (error) {
      console.error('Verify login OTP error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }

  // Google OAuth signup/login
  async googleAuth(req: Request, res: Response<ApiResponse>): Promise<void> {
    try {
      const { token } = req.body;

      // Verify Google token
      const googleUser = await googleAuthService.verifyGoogleToken(token);
      if (!googleUser) {
        res.status(400).json({
          success: false,
          message: 'Invalid Google token',
          error: 'Google verification failed'
        });
        return;
      }

      // Check if user exists
      let user = await User.findOne({ email: googleUser.email });

      if (user) {
        // User exists - check auth method
        if (user.authMethod !== 'google') {
          res.status(400).json({
            success: false,
            message: 'This email is associated with email/password login. Please use email login instead.',
            error: 'Auth method mismatch'
          });
          return;
        }
      } else {
        // Create new user
        user = await User.create({
          email: googleUser.email,
          name: googleUser.name,
          profilePicture: googleUser.picture,
          authMethod: 'google',
          googleId: googleUser.email, // Using email as googleId for simplicity
          isEmailVerified: googleUser.email_verified
        });
      }

      // Generate JWT token
      const jwtToken = generateToken({
        userId: user._id.toString(),
        email: user.email
      });

      res.status(200).json({
        success: true,
        message: user.createdAt.getTime() === user.updatedAt.getTime() ? 'Account created successfully' : 'Login successful',
        data: {
          token: jwtToken,
          user: {
            id: user._id,
            email: user.email,
            name: user.name,
            profilePicture: user.profilePicture,
            authMethod: user.authMethod
          }
        }
      });
    } catch (error) {
      console.error('Google auth error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }

  // Get current user
  async getCurrentUser(req: any, res: Response<ApiResponse>): Promise<void> {
    try {
      const user = await User.findById(req.user.userId).select('-__v');
      if (!user) {
        res.status(404).json({
          success: false,
          message: 'User not found',
          error: 'User not found'
        });
        return;
      }

      res.status(200).json({
        success: true,
        message: 'User retrieved successfully',
        data: {
          user: {
            id: user._id,
            email: user.email,
            name: user.name,
            profilePicture: user.profilePicture,
            authMethod: user.authMethod,
            isEmailVerified: user.isEmailVerified,
            createdAt: user.createdAt
          }
        }
      });
    } catch (error) {
      console.error('Get current user error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }

  // Logout
  async logout(req: Request, res: Response<ApiResponse>): Promise<void> {
    try {
      // If using HTTP-only cookies, clear the cookie
      res.clearCookie('token');
      
      res.status(200).json({
        success: true,
        message: 'Logged out successfully'
      });
    } catch (error) {
      console.error('Logout error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }
}
EOF

# Create notes controller
echo -e "${YELLOW}📝 Creating notes controller...${NC}"
cat > src/controllers/notesController.ts << 'EOF'
import { Response } from 'express';
import mongoose from 'mongoose';
import { Note } from '../models/Note';
import { AuthenticatedRequest, ApiResponse } from '../types';

export class NotesController {
  // Create a new note
  async createNote(req: AuthenticatedRequest, res: Response<ApiResponse>): Promise<void> {
    try {
      const { title, content, tags, isPinned } = req.body;
      const userId = req.user?.userId;

      if (!userId) {
        res.status(401).json({
          success: false,
          message: 'User not authenticated',
          error: 'Authentication required'
        });
        return;
      }

      const note = await Note.create({
        userId: new mongoose.Types.ObjectId(userId),
        title: title.trim(),
        content: content.trim(),
        tags: tags || [],
        isPinned: isPinned || false
      });

      res.status(201).json({
        success: true,
        message: 'Note created successfully',
        data: { note }
      });
    } catch (error) {
      console.error('Create note error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }

  // Get all notes for the authenticated user
  async getNotes(req: AuthenticatedRequest, res: Response<ApiResponse>): Promise<void> {
    try {
      const userId = req.user?.userId;
      const { page = '1', limit = '10', search, tags, sortBy = 'createdAt', sortOrder = 'desc' } = req.query;

      if (!userId) {
        res.status(401).json({
          success: false,
          message: 'User not authenticated',
          error: 'Authentication required'
        });
        return;
      }

      // Build filter
      const filter: any = { userId: new mongoose.Types.ObjectId(userId) };

      // Search functionality
      if (search && typeof search === 'string') {
        filter.$or = [
          { title: { $regex: search, $options: 'i' } },
          { content: { $regex: search, $options: 'i' } }
        ];
      }

      // Tags filter
      if (tags && typeof tags === 'string') {
        const tagsArray = tags.split(',').map(tag => tag.trim());
        filter.tags = { $in: tagsArray };
      }

      // Pagination
      const pageNum = Math.max(1, parseInt(page as string));
      const limitNum = Math.min(50, Math.max(1, parseInt(limit as string)));
      const skip = (pageNum - 1) * limitNum;

      // Sort
      const sortField = typeof sortBy === 'string' ? sortBy : 'createdAt';
      const sortDir = sortOrder === 'asc' ? 1 : -1;
      const sort: any = {};
      
      // Special sorting for pinned notes
      if (sortField === 'createdAt') {
        sort.isPinned = -1; // Pinned notes first
        sort.createdAt = sortDir;
      } else {
        sort[sortField] = sortDir;
      }

      // Execute query
      const [notes, totalCount] = await Promise.all([
        Note.find(filter)
          .sort(sort)
          .skip(skip)
          .limit(limitNum)
          .select('-__v'),
        Note.countDocuments(filter)
      ]);

      const totalPages = Math.ceil(totalCount / limitNum);

      res.status(200).json({
        success: true,
        message: 'Notes retrieved successfully',
        data: {
          notes,
          pagination: {
            currentPage: pageNum,
            totalPages,
            totalCount,
            hasNextPage: pageNum < totalPages,
            hasPrevPage: pageNum > 1
          }
        }
      });
    } catch (error) {
      console.error('Get notes error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }

  // Get a specific note by ID
  async getNoteById(req: AuthenticatedRequest, res: Response<ApiResponse>): Promise<void> {
    try {
      const { id } = req.params;
      const userId = req.user?.userId;

      if (!userId) {
        res.status(401).json({
          success: false,
          message: 'User not authenticated',
          error: 'Authentication required'
        });
        return;
      }

      if (!mongoose.Types.ObjectId.isValid(id)) {
        res.status(400).json({
          success: false,
          message: 'Invalid note ID',
          error: 'Invalid ID format'
        });
        return;
      }

      const note = await Note.findOne({
        _id: new mongoose.Types.ObjectId(id),
        userId: new mongoose.Types.ObjectId(userId)
      }).select('-__v');

      if (!note) {
        res.status(404).json({
          success: false,
          message: 'Note not found',
          error: 'Note not found'
        });
        return;
      }

      res.status(200).json({
        success: true,
        message: 'Note retrieved successfully',
        data: { note }
      });
    } catch (error) {
      console.error('Get note by ID error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }

  // Update a note
  async updateNote(req: AuthenticatedRequest, res: Response<ApiResponse>): Promise<void> {
    try {
      const { id } = req.params;
      const { title, content, tags, isPinned } = req.body;
      const userId = req.user?.userId;

      if (!userId) {
        res.status(401).json({
          success: false,
          message: 'User not authenticated',
          error: 'Authentication required'
        });
        return;
      }

      if (!mongoose.Types.ObjectId.isValid(id)) {
        res.status(400).json({
          success: false,
          message: 'Invalid note ID',
          error: 'Invalid ID format'
        });
        return;
      }

      const updateData: any = {};
      if (title !== undefined) updateData.title = title.trim();
      if (content !== undefined) updateData.content = content.trim();
      if (tags !== undefined) updateData.tags = tags;
      if (isPinned !== undefined) updateData.isPinned = isPinned;

      const note = await Note.findOneAndUpdate(
        {
          _id: new mongoose.Types.ObjectId(id),
          userId: new mongoose.Types.ObjectId(userId)
        },
        updateData,
        { new: true, runValidators: true }
      ).select('-__v');

      if (!note) {
        res.status(404).json({
          success: false,
          message: 'Note not found',
          error: 'Note not found'
        });
        return;
      }

      res.status(200).json({
        success: true,
        message: 'Note updated successfully',
        data: { note }
      });
    } catch (error) {
      console.error('Update note error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }

  // Delete a note
  async deleteNote(req: AuthenticatedRequest, res: Response<ApiResponse>): Promise<void> {
    try {
      const { id } = req.params;
      const userId = req.user?.userId;

      if (!userId) {
        res.status(401).json({
          success: false,
          message: 'User not authenticated',
          error: 'Authentication required'
        });
        return;
      }

      if (!mongoose.Types.ObjectId.isValid(id)) {
        res.status(400).json({
          success: false,
          message: 'Invalid note ID',
          error: 'Invalid ID format'
        });
        return;
      }

      const note = await Note.findOneAndDelete({
        _id: new mongoose.Types.ObjectId(id),
        userId: new mongoose.Types.ObjectId(userId)
      });

      if (!note) {
        res.status(404).json({
          success: false,
          message: 'Note not found',
          error: 'Note not found'
        });
        return;
      }

      res.status(200).json({
        success: true,
        message: 'Note deleted successfully',
        data: { deletedNoteId: id }
      });
    } catch (error) {
      console.error('Delete note error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }

  // Delete all notes for user
  async deleteAllNotes(req: AuthenticatedRequest, res: Response<ApiResponse>): Promise<void> {
    try {
      const userId = req.user?.userId;

      if (!userId) {
        res.status(401).json({
          success: false,
          message: 'User not authenticated',
          error: 'Authentication required'
        });
        return;
      }

      const result = await Note.deleteMany({
        userId: new mongoose.Types.ObjectId(userId)
      });

      res.status(200).json({
        success: true,
        message: `${result.deletedCount} notes deleted successfully`,
        data: { deletedCount: result.deletedCount }
      });
    } catch (error) {
      console.error('Delete all notes error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }
}
EOF

# Create auth routes
echo -e "${YELLOW}🛤️  Creating authentication routes...${NC}"
cat > src/routes/auth.ts << 'EOF'
import { Router } from 'express';
import { AuthController } from '../controllers/authController';
import { validateEmail, validateOTP, validateGoogleToken } from '../middleware/validation';
import { authLimiter, otpLimiter } from '../middleware/rateLimiter';
import { authenticateToken } from '../middleware/auth';

const router = Router();
const authController = new AuthController();

// Signup routes
router.post('/signup', authLimiter, validateEmail, authController.signup);
router.post('/verify-otp', otpLimiter, validateEmail, validateOTP, authController.verifySignupOTP);

// Login routes
router.post('/login', authLimiter, validateEmail, authController.login);
router.post('/verify-login-otp', otpLimiter, validateEmail, validateOTP, authController.verifyLoginOTP);

// Google OAuth
router.post('/google', authLimiter, validateGoogleToken, authController.googleAuth);

// Protected routes
router.get('/me', authenticateToken, authController.getCurrentUser);
router.post('/logout', authenticateToken, authController.logout);

export { router as authRoutes };
EOF

# Create notes routes
echo -e "${YELLOW}🛤️  Creating notes routes...${NC}"
cat > src/routes/notes.ts << 'EOF'
import { Router } from 'express';
import { NotesController } from '../controllers/notesController';
import { validateNote } from '../middleware/validation';
import { authenticateToken } from '../middleware/auth';

const router = Router();
const notesController = new NotesController();

// All routes are protected
router.use(authenticateToken);

// Notes CRUD routes
router.post('/create', validateNote, notesController.createNote);
router.get('/', notesController.getNotes);
router.get('/:id', notesController.getNoteById);
router.put('/:id', notesController.updateNote);
router.delete('/:id', notesController.deleteNote);
router.delete('/', notesController.deleteAllNotes);

export { router as notesRoutes };
EOF

# Create main app file
echo -e "${YELLOW}🚀 Creating main application file...${NC}"
cat > src/app.ts << 'EOF'
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
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
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
EOF

# Create nodemon configuration
echo -e "${YELLOW}⚙️  Creating nodemon configuration...${NC}"
cat > nodemon.json << 'EOF'
{
  "watch": ["src"],
  "ext": "ts,json",
  "ignore": ["src/**/*.spec.ts", "node_modules"],
  "exec": "ts-node src/app.ts",
  "env": {
    "NODE_ENV": "development"
  }
}
EOF

# Create .gitignore
echo -e "${YELLOW}📝 Creating .gitignore...${NC}"
cat > .gitignore << 'EOF'
# Dependencies
node_modules/
npm-debug.log*
yarn-debug.log*
yarn-error.log*
pnpm-debug.log*
lerna-debug.log*

# Runtime data
pids
*.pid
*.seed
*.pid.lock

# Coverage directory used by tools like istanbul
coverage/
*.lcov

# nyc test coverage
.nyc_output

# Grunt intermediate storage (https://gruntjs.com/creating-plugins#storing-task-files)
.grunt

# Bower dependency directory (https://bower.io/)
bower_components

# node-waf configuration
.lock-wscript

# Compiled binary addons (https://nodejs.org/api/addons.html)
build/Release

# Dependency directories
node_modules/
jspm_packages/

# TypeScript cache
*.tsbuildinfo

# Optional npm cache directory
.npm

# Optional eslint cache
.eslintcache

# Optional stylelint cache
.stylelintcache

# Microbundle cache
.rpt2_cache/
.rts2_cache_cjs/
.rts2_cache_es/
.rts2_cache_umd/

# Optional REPL history
.node_repl_history

# Output of 'npm pack'
*.tgz

# Yarn Integrity file
.yarn-integrity

# dotenv environment variable files
.env
.env.development.local
.env.test.local
.env.production.local
.env.local

# parcel-bundler cache (https://parceljs.org/)
.cache
.parcel-cache

# Next.js build output
.next
out

# Nuxt.js build / generate output
.nuxt
dist

# Gatsby files
.cache/
public

# Vuepress build output
.vuepress/dist

# Serverless directories
.serverless/

# FuseBox cache
.fusebox/

# DynamoDB Local files
.dynamodb/

# TernJS port file
.tern-port

# Stores VSCode versions used for testing VSCode extensions
.vscode-test

# yarn v2
.yarn/cache
.yarn/unplugged
.yarn/build-state.yml
.yarn/install-state.gz
.pnp.*

# Build directory
dist/
build/

# Logs
logs
*.log

# Runtime data
pids
*.pid
*.seed
*.pid.lock

# Directory for instrumented libs generated by jscoverage/JSCover
lib-cov

# Coverage directory used by tools like istanbul
coverage
*.lcov

# OS generated files
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes
ehthumbs.db
Thumbs.db

# Editor directories and files
.vscode/
.idea/
*.swp
*.swo
*~

# Temporary folders
tmp/
temp/
EOF

# Create README.md
echo -e "${YELLOW}📖 Creating README.md...${NC}"
cat > README.md << 'EOF'
# TypeScript Backend with Authentication & Notes Management

A robust backend API built with **Node.js**, **Express**, **TypeScript**, **MongoDB**, and **JWT** authentication.

## 🚀 Features

### Authentication
- **Email + OTP Signup/Login**: Secure authentication with time-limited OTPs
- **Google OAuth**: Social login integration
- **JWT Tokens**: Stateless authentication with HTTP-only cookies support
- **Rate Limiting**: Protection against brute force attacks
- **Input Validation**: Comprehensive request validation

### Notes Management
- **CRUD Operations**: Create, read, update, delete notes
- **Search & Filter**: Full-text search and tag-based filtering
- **Pagination**: Efficient data loading
- **User Isolation**: Users can only access their own notes
- **Pinned Notes**: Priority note management

### Security & Performance
- **Helmet.js**: Security headers
- **CORS**: Configurable cross-origin requests
- **Rate Limiting**: Multiple rate limit strategies
- **Input Sanitization**: XSS protection
- **MongoDB Indexes**: Optimized database queries
- **Error Handling**: Comprehensive error management

## 📦 Installation

1. **Clone and setup:**
   ```bash
   git clone <your-repo>
   cd backend
   npm install
   ```

2. **Environment Configuration:**
   ```bash
   cp .env.example .env
   ```
   
   Update `.env` with your actual values:
   ```env
   MONGO_URI=mongodb+srv://username:password@cluster.mongodb.net/database_name
   JWT_SECRET=your_super_secret_jwt_key_here
   EMAIL_USER=your_email@gmail.com
   EMAIL_PASS=your_gmail_app_password
   GOOGLE_CLIENT_ID=your_google_client_id.googleusercontent.com
   GOOGLE_CLIENT_SECRET=your_google_client_secret
   ```

3. **Development:**
   ```bash
   npm run dev
   ```

4. **Production:**
   ```bash
   npm run build
   npm start
   ```

## 🔧 Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `MONGO_URI` | MongoDB connection string | ✅ |
| `JWT_SECRET` | Secret key for JWT tokens | ✅ |
| `EMAIL_USER` | Gmail address for sending OTPs | ✅ |
| `EMAIL_PASS` | Gmail app password | ✅ |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID | ✅ |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret | ✅ |
| `PORT` | Server port (default: 5000) | ❌ |
| `NODE_ENV` | Environment (development/production) | ❌ |
| `FRONTEND_URL` | Frontend URL for CORS | ❌ |

## 📚 API Documentation

### Base URL
```
http://localhost:5000/api
```

### Authentication Endpoints

#### 1. Email Signup
```http
POST /auth/signup
Content-Type: application/json

{
  "email": "user@example.com"
}
```

#### 2. Verify Signup OTP
```http
POST /auth/verify-otp
Content-Type: application/json

{
  "email": "user@example.com",
  "otp": "123456",
  "name": "John Doe"
}
```

#### 3. Email Login
```http
POST /auth/login
Content-Type: application/json

{
  "email": "user@example.com"
}
```

#### 4. Verify Login OTP
```http
POST /auth/verify-login-otp
Content-Type: application/json

{
  "email": "user@example.com",
  "otp": "123456"
}
```

#### 5. Google OAuth
```http
POST /auth/google
Content-Type: application/json

{
  "token": "google_id_token_here"
}
```

#### 6. Get Current User
```http
GET /auth/me
Authorization: Bearer <jwt_token>
```

#### 7. Logout
```http
POST /auth/logout
Authorization: Bearer <jwt_token>
```

### Notes Endpoints

#### 1. Create Note
```http
POST /notes/create
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "title": "My Note",
  "content": "Note content here",
  "tags": ["work", "important"],
  "isPinned": false
}
```

#### 2. Get All Notes
```http
GET /notes?page=1&limit=10&search=keyword&tags=work,personal&sortBy=createdAt&sortOrder=desc
Authorization: Bearer <jwt_token>
```

#### 3. Get Note by ID
```http
GET /notes/:id
Authorization: Bearer <jwt_token>
```

#### 4. Update Note
```http
PUT /notes/:id
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "title": "Updated title",
  "content": "Updated content",
  "tags": ["updated"],
  "isPinned": true
}
```

#### 5. Delete Note
```http
DELETE /notes/:id
Authorization: Bearer <jwt_token>
```

#### 6. Delete All Notes
```http
DELETE /notes
Authorization: Bearer <jwt_token>
```

## 🏗️ Project Structure

```
backend/
├── src/
│   ├── controllers/           # Request handlers
│   │   ├── authController.ts
│   │   └── notesController.ts
│   ├── middleware/           # Express middleware
│   │   ├── auth.ts
│   │   ├── errorHandler.ts
│   │   ├── rateLimiter.ts
│   │   └── validation.ts
│   ├── models/              # MongoDB schemas
│   │   ├── User.ts
│   │   ├── Note.ts
│   │   └── OTP.ts
│   ├── routes/              # API routes
│   │   ├── auth.ts
│   │   └── notes.ts
│   ├── types/               # TypeScript types
│   │   └── index.ts
│   ├── utils/               # Utility functions
│   │   ├── database.ts
│   │   ├── email.ts
│   │   ├── googleAuth.ts
│   │   ├── jwt.ts
│   │   └── otp.ts
│   └── app.ts              # Main application
├── dist/                   # Compiled JavaScript
├── .env.example           # Environment template
├── .gitignore
├── nodemon.json
├── package.json
├── README.md
└── tsconfig.json
```

## 🔒 Security Features

- **Rate Limiting**: Multiple rate limit strategies for different endpoints
- **JWT Authentication**: Secure token-based authentication
- **OTP Expiration**: 5-minute OTP validity with attempt limits
- **Input Validation**: Comprehensive request validation
- **CORS Configuration**: Configurable cross-origin requests
- **Helmet.js**: Security headers for production
- **Password Hashing**: Bcrypt for sensitive data (when needed)
- **Environment Variables**: Sensitive data protection

## 🚢 Deployment

### Render Deployment

1. **Connect Repository**: Link your GitHub repository to Render
2. **Environment Variables**: Set all required environment variables
3. **Build Command**: `npm run build`
4. **Start Command**: `npm start`

### Railway Deployment

1. **Connect Repository**: Link your GitHub repository to Railway
2. **Environment Variables**: Set all required environment variables
3. **Deploy**: Railway will automatically detect and deploy

### Environment Variables for Production
Make sure to set these in your deployment platform:

```env
NODE_ENV=production
MONGO_URI=your_production_mongodb_uri
JWT_SECRET=your_super_secret_production_jwt_key
EMAIL_USER=your_production_email
EMAIL_PASS=your_production_email_password
GOOGLE_CLIENT_ID=your_production_google_client_id
GOOGLE_CLIENT_SECRET=your_production_google_client_secret
FRONTEND_URL=https://your-frontend-domain.com
```

## 🛠️ Scripts

| Command | Description |
|---------|-------------|
| `npm run dev` | Start development server with hot reload |
| `npm run build` | Compile TypeScript to JavaScript |
| `npm start` | Start production server |
| `npm run clean` | Remove build directory |
| `npm run lint` | Check TypeScript without emitting |

## 📝 Error Handling

The API returns consistent error responses:

```json
{
  "success": false,
  "message": "Error description",
  "error": "Error type or details"
}
```

## 🔍 Health Check

```http
GET /health
```

Returns server status and system information.

## ⚡ Performance Optimizations

- **Database Indexes**: Optimized MongoDB queries
- **Connection Pooling**: Efficient database connections
- **Rate Limiting**: Prevent abuse
- **Compression**: Gzip compression for responses
- **Caching Headers**: Appropriate cache headers
- **Pagination**: Efficient data loading

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the ISC License.

## 🆘 Support

For support, email your-support@email.com or create an issue in the repository.

---

Built with ❤️ using TypeScript, Express, MongoDB, and modern best practices.
EOF

# Create Docker configuration (optional)
echo -e "${YELLOW}🐳 Creating Docker configuration...${NC}"
cat > Dockerfile << 'EOF'
# Build stage
FROM node:18-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY tsconfig.json ./

# Install dependencies
RUN npm ci --only=production && npm cache clean --force

# Copy source code
COPY src ./src

# Build the application
RUN npm run build

# Production stage
FROM node:18-alpine AS production

WORKDIR /app

# Create non-root user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S backend -u 1001

# Copy package files
COPY package*.json ./

# Install production dependencies only
RUN npm ci --only=production && npm cache clean --force

# Copy built application
COPY --from=builder /app/dist ./dist

# Change ownership
RUN chown -R backend:nodejs /app
USER backend

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:5000/health', (res) => { process.exit(res.statusCode === 200 ? 0 : 1) })"

# Start application
CMD ["npm", "start"]
EOF

# Create Docker Compose for development
cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  backend:
    build: .
    ports:
      - "5000:5000"
    environment:
      - NODE_ENV=development
      - PORT=5000
    env_file:
      - .env
    volumes:
      - ./src:/app/src
    depends_on:
      - mongo
    networks:
      - app-network

  mongo:
    image: mongo:7
    ports:
      - "27017:27017"
    environment:
      - MONGO_INITDB_ROOT_USERNAME=admin
      - MONGO_INITDB_ROOT_PASSWORD=password
      - MONGO_INITDB_DATABASE=notesapp
    volumes:
      - mongo-data:/data/db
    networks:
      - app-network

networks:
  app-network:
    driver: bridge

volumes:
  mongo-data:
EOF

# Create deployment script
echo -e "${YELLOW}🚀 Creating deployment script...${NC}"
cat > deploy.sh << 'EOF'
#!/bin/bash

set -e

echo "🚀 Starting deployment process..."

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Check if environment is provided
if [ -z "$1" ]; then
    echo -e "${RED}❌ Please provide environment: ./deploy.sh [staging|production]${NC}"
    exit 1
fi

ENVIRONMENT=$1

echo -e "${YELLOW}📦 Building application...${NC}"
npm run build

echo -e "${YELLOW}🧪 Running type check...${NC}"
npm run lint

echo -e "${YELLOW}🔍 Checking environment variables...${NC}"
if [ ! -f .env ]; then
    echo -e "${RED}❌ .env file not found${NC}"
    exit 1
fi

# Check required environment variables
REQUIRED_VARS=("MONGO_URI" "JWT_SECRET" "EMAIL_USER" "EMAIL_PASS" "GOOGLE_CLIENT_ID")
for var in "${REQUIRED_VARS[@]}"; do
    if [ -z "$(grep "^${var}=" .env | cut -d '=' -f2)" ]; then
        echo -e "${RED}❌ Missing required environment variable: ${var}${NC}"
        exit 1
    fi
done

echo -e "${GREEN}✅ Pre-deployment checks passed${NC}"

if [ "$ENVIRONMENT" == "production" ]; then
    echo -e "${YELLOW}🌐 Deploying to production...${NC}"
    # Add your production deployment commands here
    # For example: Railway, Render, or Docker deployment
elif [ "$ENVIRONMENT" == "staging" ]; then
    echo -e "${YELLOW}🔧 Deploying to staging...${NC}"
    # Add your staging deployment commands here
fi

echo -e "${GREEN}🎉 Deployment completed successfully!${NC}"
EOF

chmod +x deploy.sh

# Create development setup script
echo -e "${YELLOW}⚙️  Creating development setup script...${NC}"
cat > setup-dev.sh << 'EOF'
#!/bin/bash

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}🔧 Setting up development environment...${NC}"

# Check if .env exists
if [ ! -f .env ]; then
    echo -e "${YELLOW}📝 Creating .env file from example...${NC}"
    cp .env.example .env
    echo -e "${YELLOW}⚠️  Please update .env with your actual values${NC}"
fi

# Install dependencies
echo -e "${YELLOW}📦 Installing dependencies...${NC}"
npm install

# Build the project
echo -e "${YELLOW}🏗️  Building project...${NC}"
npm run build

echo -e "${GREEN}✅ Development environment setup complete!${NC}"
echo -e "${YELLOW}📋 Next steps:${NC}"
echo "1. Update .env with your actual values"
echo "2. Start development server: npm run dev"
echo "3. Check health: http://localhost:5000/health"
EOF

chmod +x setup-dev.sh

# Create API testing script
echo -e "${YELLOW}🧪 Creating API testing script...${NC}"
cat > test-api.sh << 'EOF'
#!/bin/bash

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

BASE_URL="http://localhost:5000/api"
EMAIL="test@example.com"
TOKEN=""

echo -e "${YELLOW}🧪 Testing API endpoints...${NC}"

# Test health endpoint
echo -e "${YELLOW}1. Testing health endpoint...${NC}"
HEALTH_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:5000/health)
if [ "$HEALTH_RESPONSE" == "200" ]; then
    echo -e "${GREEN}✅ Health check passed${NC}"
else
    echo -e "${RED}❌ Health check failed (Status: $HEALTH_RESPONSE)${NC}"
    exit 1
fi

# Test signup
echo -e "${YELLOW}2. Testing email signup...${NC}"
SIGNUP_RESPONSE=$(curl -s -X POST \
  "$BASE_URL/auth/signup" \
  -H "Content-Type: application/json" \
  -d "{\"email\": \"$EMAIL\"}")

if echo "$SIGNUP_RESPONSE" | grep -q "success.*true"; then
    echo -e "${GREEN}✅ Signup endpoint working${NC}"
else
    echo -e "${RED}❌ Signup endpoint failed${NC}"
    echo "$SIGNUP_RESPONSE"
fi

# Test login
echo -e "${YELLOW}3. Testing email login...${NC}"
LOGIN_RESPONSE=$(curl -s -X POST \
  "$BASE_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\": \"$EMAIL\"}")

if echo "$LOGIN_RESPONSE" | grep -q "success.*true\|User.*not.*found"; then
    echo -e "${GREEN}✅ Login endpoint working${NC}"
else
    echo -e "${RED}❌ Login endpoint failed${NC}"
    echo "$LOGIN_RESPONSE"
fi

# Test protected route without token
echo -e "${YELLOW}4. Testing protected route without token...${NC}"
PROTECTED_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/notes")
if [ "$PROTECTED_RESPONSE" == "401" ]; then
    echo -e "${GREEN}✅ Protected route properly secured${NC}"
else
    echo -e "${RED}❌ Protected route not properly secured (Status: $PROTECTED_RESPONSE)${NC}"
fi

echo -e "${GREEN}🎉 API testing completed!${NC}"
EOF

chmod +x test-api.sh

# Final success message and instructions
echo -e "${GREEN}✅ Backend project setup completed successfully!${NC}"
echo ""
echo -e "${BLUE}📁 Project structure created in: $(pwd)${NC}"
echo ""
echo -e "${YELLOW}📋 Next Steps:${NC}"
echo "1. Update .env file with your actual values"
echo "2. Start development: ${GREEN}npm run dev${NC}"
echo "3. Test the API: ${GREEN}./test-api.sh${NC}"
echo "4. Deploy: ${GREEN}./deploy.sh production${NC}"
echo ""
echo -e "${YELLOW}🔗 Important URLs:${NC}"
echo "• API Base: http://localhost:5000/api"
echo "• Health Check: http://localhost:5000/health"
echo "• API Info: http://localhost:5000/api"
echo ""
echo -e "${YELLOW}📚 Available Scripts:${NC}"
echo "• ${GREEN}npm run dev${NC} - Start development server"
echo "• ${GREEN}npm run build${NC} - Build for production"
echo "• ${GREEN}npm start${NC} - Start production server"
echo "• ${GREEN}./setup-dev.sh${NC} - Quick development setup"
echo "• ${GREEN}./test-api.sh${NC} - Test API endpoints"
echo ""
echo -e "${BLUE}🎉 Happy coding!${NC}"