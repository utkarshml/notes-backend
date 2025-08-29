import { OAuth2Client } from 'google-auth-library';
import { GoogleTokenPayload } from '../types';
import dotenv from 'dotenv';

dotenv.config();
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
