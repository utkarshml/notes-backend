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
