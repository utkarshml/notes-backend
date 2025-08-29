import nodemailer from 'nodemailer';
import dotenv from 'dotenv';

dotenv.config();
interface EmailOptions {
  to: string;
  subject: string;
  html: string;
}

class EmailService {
  private transporter: nodemailer.Transporter;

  constructor() {
    this.transporter = nodemailer.createTransport({
      service: 'gmail',
      host : process.env.EMAIL_HOST,
      secure : false,
      auth: {
        user: process.env.EMAIL_USERNAME,
        pass: process.env.EMAIL_PASS,
      },
      port : 587
    });
  }

  async sendEmail({ to, subject, html }: EmailOptions): Promise<boolean> {
    try {
      const mailOptions = {
        from: ` Notes App ${process.env.EMAIL_USERNAME}`,
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
