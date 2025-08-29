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
      const { email, name, dateOfBirth } = req.body;

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

  


      // Store user data in database
      const user = await User.create({
        email,
        name,
        dateOfBirth,
        authMethod: 'email'
      });

      res.status(200).json({
        success: true,
        message: 'Verification code sent to your email',
        data: { email, _id: user._id }
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

  async resendOTP(req: Request, res: Response<ApiResponse>): Promise<void>  {
    try {
      const { email } = req.body;
  
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
      console.error('Resend OTP error:', error);
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
      const { user_id, otp,email } = req.body;

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

      // Create new user
      const user = await User.findOneAndUpdate(
        { email : email },
        { $set: { isEmailVerified: true } },
        { new: true, runValidators: true }
      ).select('-__v');

      // Generate JWT token
      const token = generateToken({
        userId: (user?.id as string).toString(),
        email: user?.email as string
      });
      res.cookie('token', token, {
        expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        httpOnly: true,
        secure : false,
        sameSite : 'none',
        path : '/'
      })

      res.status(201).json({
        success: true,
        message: 'Account created successfully',
        data: {
          token,
          user: {
            id: user?.id,
            email: user?.email,
            name: user?.name,
            authMethod: user?.authMethod
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
        userId: (user._id as string).toString(),
        email: user.email
      });
      res.cookie('token', token, {
        expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        httpOnly: true,
        secure : false,
        sameSite : "lax",
      })

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
        userId: (user._id as string).toString(),
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

// Step 1: Redirect user to Google OAuth
export const googleLogin = async (req: Request, res: Response<ApiResponse>): Promise<void> => {
  const redirect_uri = `${req.protocol}://${req.get("host")}/api/auth/google/callback`;
  const client_id = process.env.GOOGLE_CLIENT_ID;

  const scope = [
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
  ].join(" ");

  const authUrl = `https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id=${client_id}&redirect_uri=${redirect_uri}&scope=${scope}`;

  res.redirect(authUrl);
};

// Step 2: Google Callback
export const googleCallback = async (req: Request, res: Response<ApiResponse>) => {
  const code = typeof req.query.code === 'string' ? req.query.code : '';
  const client_id = process.env.GOOGLE_CLIENT_ID || '';
  const client_secret = process.env.GOOGLE_CLIENT_SECRET || '';
  const redirect_uri = `${req.protocol}://${req.get("host")}/api/auth/google/callback`;

  try {
    // Exchange code for tokens
    const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        code,
        client_id,
        client_secret,
        redirect_uri,
        grant_type: "authorization_code",
      }),
    });

    const tokenData = await tokenRes.json() as { access_token: string };
    const { access_token } = tokenData;

    // Get user info from Google
    const userRes = await fetch("https://www.googleapis.com/oauth2/v3/userinfo", {
      headers: { Authorization: `Bearer ${access_token}` },
    });
    
    const googleUser = await userRes.json() as { sub: string; email: string; [key: string]: any };
    // console.log("Google User:", googleUser);
    if(!googleUser) {
      res.status(500).json({
        success: false,
        message: "Google OAuth Failed",
        error: "Google OAuth Failed"
      });
      return;
    }
    const user = await User.findOne({ email: googleUser.email });
    if (user) {
      const token = generateToken({
        userId: (user._id as string).toString(),
        email: user.email
      });
      res.cookie('token', token, {
        expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        httpOnly: true,
        secure: false, // change to true in production with https
        sameSite: "lax",
      });
      res.redirect(process.env.FRONTEND_URL +  "/dashboard");
      return;
    }
    const newUser = new User({
      email: googleUser.email,
      name: googleUser.name,
      profilePicture: googleUser.picture,
      authMethod: "google",
      isEmailVerified: true,
    });
    await newUser.save();
    const myToken = generateToken(
      { userId: (newUser._id as string).toString(), email: googleUser.email },
    );

    // Set cookie
    res.cookie("token", myToken, {
      httpOnly: true,
      secure: false, // change to true in production with https
      sameSite: "lax",
    });

    // Redirect to React app
    res.redirect(process.env.FRONTEND_URL +  "/dashboard");
  } catch (err) {
    if (typeof err === 'object' && err !== null && 'response' in err && typeof (err as any).response === 'object') {
      console.error((err as any).response?.data || (err as any).message);
    } else {
      console.error((err as any).message || err);
    }
    res.status(500).json({
      success: false,
      message: "Google OAuth Failed",
      error: typeof (err as any)?.message === 'string' ? (err as any).message : 'Unknown error'
    });
  }
};
