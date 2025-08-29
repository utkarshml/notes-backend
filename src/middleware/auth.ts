import { Response, NextFunction } from 'express';
import { verifyToken } from '../utils/jwt';
import { AuthenticatedRequest, ApiResponse } from '../types';

export const authenticateToken = (
  req: AuthenticatedRequest,
  res: Response<ApiResponse>,
  next: NextFunction
): void => {
  try {
    // Also check for token in cookies
    const cookieToken = req.cookies?.token;
    
    const finalToken = cookieToken;
    
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
