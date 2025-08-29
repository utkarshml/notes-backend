import mongoose, { Document, Schema } from 'mongoose';
import bcrypt from 'bcrypt';

export interface IUser extends Document {
  email: string;
  name?: string;
  dateOfBirth?: Date;
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
  dateOfBirth: {
    type: Date,
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
