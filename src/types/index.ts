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
