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
