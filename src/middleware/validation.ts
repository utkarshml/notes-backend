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
