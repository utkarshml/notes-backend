import { Router } from 'express';
import { AuthController, googleCallback, googleLogin } from '../controllers/authController';
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
// router.post('/google', authLimiter, validateGoogleToken, authController.googleAuth);
router.get("/google",   googleLogin);
router.get("/google/callback",googleCallback);
// Protected routes
router.get('/me', authenticateToken, authController.getCurrentUser);
router.post('/logout', authenticateToken, authController.logout);

// Resend OTP
router.post('/resend-otp', authLimiter, validateEmail, authController.resendOTP);
export { router as authRoutes };
