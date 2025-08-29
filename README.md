# TypeScript Backend with Authentication & Notes Management

A robust backend API built with **Node.js**, **Express**, **TypeScript**, **MongoDB**, and **JWT** authentication.

## 🚀 Features

### Authentication
- **Email + OTP Signup/Login**: Secure authentication with time-limited OTPs
- **Google OAuth**: Social login integration
- **JWT Tokens**: Stateless authentication with HTTP-only cookies support
- **Rate Limiting**: Protection against brute force attacks
- **Input Validation**: Comprehensive request validation

### Notes Management
- **CRUD Operations**: Create, read, update, delete notes
- **Search & Filter**: Full-text search and tag-based filtering
- **Pagination**: Efficient data loading
- **User Isolation**: Users can only access their own notes
- **Pinned Notes**: Priority note management

### Security & Performance
- **Helmet.js**: Security headers
- **CORS**: Configurable cross-origin requests
- **Rate Limiting**: Multiple rate limit strategies
- **Input Sanitization**: XSS protection
- **MongoDB Indexes**: Optimized database queries
- **Error Handling**: Comprehensive error management

## 📦 Installation

1. **Clone and setup:**
   ```bash
   git clone <your-repo>
   cd backend
   npm install
   ```

2. **Environment Configuration:**
   ```bash
   cp .env.example .env
   ```
   
   Update `.env` with your actual values:
   ```env
   MONGO_URI=mongodb+srv://username:password@cluster.mongodb.net/database_name
   JWT_SECRET=your_super_secret_jwt_key_here
   EMAIL_USER=your_email@gmail.com
   EMAIL_PASS=your_gmail_app_password
   GOOGLE_CLIENT_ID=your_google_client_id.googleusercontent.com
   GOOGLE_CLIENT_SECRET=your_google_client_secret
   ```

3. **Development:**
   ```bash
   npm run dev
   ```

4. **Production:**
   ```bash
   npm run build
   npm start
   ```

## 🔧 Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `MONGO_URI` | MongoDB connection string | ✅ |
| `JWT_SECRET` | Secret key for JWT tokens | ✅ |
| `EMAIL_USER` | Gmail address for sending OTPs | ✅ |
| `EMAIL_PASS` | Gmail app password | ✅ |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID | ✅ |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret | ✅ |
| `PORT` | Server port (default: 5000) | ❌ |
| `NODE_ENV` | Environment (development/production) | ❌ |
| `FRONTEND_URL` | Frontend URL for CORS | ❌ |

## 📚 API Documentation

### Base URL
```
http://localhost:5000/api
```

### Authentication Endpoints

#### 1. Email Signup
```http
POST /auth/signup
Content-Type: application/json

{
  "email": "user@example.com"
}
```

#### 2. Verify Signup OTP
```http
POST /auth/verify-otp
Content-Type: application/json

{
  "email": "user@example.com",
  "otp": "123456",
  "name": "John Doe"
}
```

#### 3. Email Login
```http
POST /auth/login
Content-Type: application/json

{
  "email": "user@example.com"
}
```

#### 4. Verify Login OTP
```http
POST /auth/verify-login-otp
Content-Type: application/json

{
  "email": "user@example.com",
  "otp": "123456"
}
```

#### 5. Google OAuth
```http
POST /auth/google
Content-Type: application/json

{
  "token": "google_id_token_here"
}
```

#### 6. Get Current User
```http
GET /auth/me
Authorization: Bearer <jwt_token>
```

#### 7. Logout
```http
POST /auth/logout
Authorization: Bearer <jwt_token>
```

### Notes Endpoints

#### 1. Create Note
```http
POST /notes/create
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "title": "My Note",
  "content": "Note content here",
  "tags": ["work", "important"],
  "isPinned": false
}
```

#### 2. Get All Notes
```http
GET /notes?page=1&limit=10&search=keyword&tags=work,personal&sortBy=createdAt&sortOrder=desc
Authorization: Bearer <jwt_token>
```

#### 3. Get Note by ID
```http
GET /notes/:id
Authorization: Bearer <jwt_token>
```

#### 4. Update Note
```http
PUT /notes/:id
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "title": "Updated title",
  "content": "Updated content",
  "tags": ["updated"],
  "isPinned": true
}
```

#### 5. Delete Note
```http
DELETE /notes/:id
Authorization: Bearer <jwt_token>
```

#### 6. Delete All Notes
```http
DELETE /notes
Authorization: Bearer <jwt_token>
```

## 🏗️ Project Structure

```
backend/
├── src/
│   ├── controllers/           # Request handlers
│   │   ├── authController.ts
│   │   └── notesController.ts
│   ├── middleware/           # Express middleware
│   │   ├── auth.ts
│   │   ├── errorHandler.ts
│   │   ├── rateLimiter.ts
│   │   └── validation.ts
│   ├── models/              # MongoDB schemas
│   │   ├── User.ts
│   │   ├── Note.ts
│   │   └── OTP.ts
│   ├── routes/              # API routes
│   │   ├── auth.ts
│   │   └── notes.ts
│   ├── types/               # TypeScript types
│   │   └── index.ts
│   ├── utils/               # Utility functions
│   │   ├── database.ts
│   │   ├── email.ts
│   │   ├── googleAuth.ts
│   │   ├── jwt.ts
│   │   └── otp.ts
│   └── app.ts              # Main application
├── dist/                   # Compiled JavaScript
├── .env.example           # Environment template
├── .gitignore
├── nodemon.json
├── package.json
├── README.md
└── tsconfig.json
```

## 🔒 Security Features

- **Rate Limiting**: Multiple rate limit strategies for different endpoints
- **JWT Authentication**: Secure token-based authentication
- **OTP Expiration**: 5-minute OTP validity with attempt limits
- **Input Validation**: Comprehensive request validation
- **CORS Configuration**: Configurable cross-origin requests
- **Helmet.js**: Security headers for production
- **Password Hashing**: Bcrypt for sensitive data (when needed)
- **Environment Variables**: Sensitive data protection

## 🚢 Deployment

### Render Deployment

1. **Connect Repository**: Link your GitHub repository to Render
2. **Environment Variables**: Set all required environment variables
3. **Build Command**: `npm run build`
4. **Start Command**: `npm start`

### Railway Deployment

1. **Connect Repository**: Link your GitHub repository to Railway
2. **Environment Variables**: Set all required environment variables
3. **Deploy**: Railway will automatically detect and deploy

### Environment Variables for Production
Make sure to set these in your deployment platform:

```env
NODE_ENV=production
MONGO_URI=your_production_mongodb_uri
JWT_SECRET=your_super_secret_production_jwt_key
EMAIL_USER=your_production_email
EMAIL_PASS=your_production_email_password
GOOGLE_CLIENT_ID=your_production_google_client_id
GOOGLE_CLIENT_SECRET=your_production_google_client_secret
FRONTEND_URL=https://your-frontend-domain.com
```

## 🛠️ Scripts

| Command | Description |
|---------|-------------|
| `npm run dev` | Start development server with hot reload |
| `npm run build` | Compile TypeScript to JavaScript |
| `npm start` | Start production server |
| `npm run clean` | Remove build directory |
| `npm run lint` | Check TypeScript without emitting |

## 📝 Error Handling

The API returns consistent error responses:

```json
{
  "success": false,
  "message": "Error description",
  "error": "Error type or details"
}
```

## 🔍 Health Check

```http
GET /health
```

Returns server status and system information.

## ⚡ Performance Optimizations

- **Database Indexes**: Optimized MongoDB queries
- **Connection Pooling**: Efficient database connections
- **Rate Limiting**: Prevent abuse
- **Compression**: Gzip compression for responses
- **Caching Headers**: Appropriate cache headers
- **Pagination**: Efficient data loading

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the ISC License.

## 🆘 Support

For support, email your-support@email.com or create an issue in the repository.

---

Built with ❤️ using TypeScript, Express, MongoDB, and modern best practices.
