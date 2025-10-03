# 🔒 Secure Authentication System

A production-ready full-stack authentication system built with React, Node.js, Express, and PostgreSQL, implementing industry-standard security practices and OWASP Top 10 protections.

[![Live Demo](https://img.shields.io/badge/demo-live-success)](https://auth-frontend-three-beryl.vercel.app)
[![Backend](https://img.shields.io/badge/backend-deployed-blue)](https://secure-auth-api-production.up.railway.app)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

## 🌟 Live Demo

- **Frontend:** [https://auth-frontend-three-beryl.vercel.app](https://auth-frontend-three-beryl.vercel.app)
- **Backend API:** [https://secure-auth-api-production.up.railway.app](https://secure-auth-api-production.up.railway.app)
- **API Health Check:** [https://secure-auth-api-production.up.railway.app/health](https://secure-auth-api-production.up.railway.app/health)

## 📸 Demo Credentials

Try the live demo with:
- **Email:** `test@example.com`
- **Password:** `SecurePass123!`

## 🎯 Features

### Authentication & Authorization
- JWT-based authentication with access and refresh tokens
- Refresh token rotation (7-day expiry)
- Short-lived access tokens (15-minute expiry)
- Secure session management
- Protected routes with middleware authentication

### Security Features (OWASP Top 10 Compliant)
- **Password Security:** Bcrypt hashing with 12 salt rounds
- **SQL Injection Prevention:** Parameterized queries with PostgreSQL
- **NoSQL Injection Prevention:** Custom input sanitization
- **XSS Protection:** HTML character escaping
- **Rate Limiting:** 5 login attempts per 15 minutes
- **Account Lockout:** Progressive lockout after failed attempts
- **Brute Force Prevention:** IP-based rate limiting (100 requests/15min)
- **Security Headers:** Helmet.js with CSP, HSTS, X-Frame-Options
- **CORS Protection:** Configurable allowed origins
- **Input Validation:** Express-validator with strict rules
- **Request Size Limits:** 10kb max payload (DoS prevention)
- **HTTP Parameter Pollution Prevention**
- **Comprehensive Logging:** Winston for security audit trails
- **Password Policy:** Minimum 8 characters, uppercase, lowercase, number, special character

### Frontend Features
- Real-time validation and error handling
- Responsive, modern UI with Tailwind CSS
- Token refresh mechanism
- Mobile-friendly design
- Loading states and user feedback
- Secure token storage in localStorage

## 🛠️ Tech Stack

### Backend
- **Runtime:** Node.js (v18+)
- **Framework:** Express.js
- **Database:** PostgreSQL (with connection pooling)
- **Authentication:** JWT (jsonwebtoken)
- **Password Hashing:** bcrypt
- **Security:** Helmet.js, express-rate-limit, hpp
- **Validation:** express-validator
- **Logging:** Winston

### Frontend
- **Framework:** React.js
- **Styling:** Tailwind CSS
- **Icons:** Lucide React
- **HTTP Client:** Fetch API
- **State Management:** React Hooks (useState, useEffect)

### DevOps
- **Backend Deployment:** Railway
- **Frontend Deployment:** Vercel
- **Database Hosting:** Railway PostgreSQL
- **CI/CD:** Automatic deployment on push

## 🚀 Quick Start

### Prerequisites
- Node.js (v18 or higher)
- PostgreSQL (v15 or higher)
- npm or yarn

### Backend Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/yesanisha/secure-auth-api.git
   cd secure-auth-api
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Set up environment variables**
   ```bash
   cp .env.example .env
   ```
   
   Edit `.env` with your configuration:
   ```env
   NODE_ENV=development
   PORT=3000
   
   DATABASE_URL=postgresql://user:password@localhost:5432/secure_auth_db
   
   JWT_SECRET=your_jwt_secret_here
   JWT_REFRESH_SECRET=your_refresh_secret_here
   
   ALLOWED_ORIGINS=http://localhost:3000,http://localhost:3001
   LOG_LEVEL=info
   ```

4. **Generate JWT secrets**
   ```bash
   node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
   ```
   Run twice and copy the outputs to your `.env` file

5. **Set up PostgreSQL database**
   ```bash
   # Using Docker (recommended)
   docker run --name postgres-auth \
     -e POSTGRES_PASSWORD=postgres \
     -e POSTGRES_DB=secure_auth_db \
     -p 5432:5432 \
     -d postgres:15-alpine
   ```

6. **Start the server**
   ```bash
   npm run dev
   ```
   
   Server will start at `http://localhost:3000`

### Frontend Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/yesanisha/auth-frontend.git
   cd auth-frontend
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Update API URL** (if needed)
   
   In `src/App.js`, update the API_URL:
   ```javascript
   const API_URL = 'http://localhost:3000/api/auth';
   ```

4. **Start the development server**
   ```bash
   npm start
   ```
   
   Frontend will open at `http://localhost:3001`

## 📡 API Endpoints

### Public Endpoints

#### Register User
```http
POST /api/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePass123!"
}
```

**Response:**
```json
{
  "success": true,
  "message": "User registered successfully",
  "data": {
    "user": {
      "id": 1,
      "email": "user@example.com",
      "createdAt": "2025-10-03T13:39:59.822Z"
    },
    "tokens": {
      "accessToken": "eyJhbGciOiJIUzI1NiIs...",
      "refreshToken": "eyJhbGciOiJIUzI1NiIs...",
      "expiresIn": 900
    }
  }
}
```

#### Login
```http
POST /api/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePass123!"
}
```

#### Refresh Token
```http
POST /api/auth/refresh
Content-Type: application/json

{
  "refreshToken": "eyJhbGciOiJIUzI1NiIs..."
}
```

### Protected Endpoints

#### Get User Profile
```http
GET /api/auth/me
Authorization: Bearer {accessToken}
```

#### Logout
```http
POST /api/auth/logout
Authorization: Bearer {accessToken}
```

## 🧪 Testing

### Test with cURL

```bash
# Health check
curl https://secure-auth-api-production.up.railway.app/health

# Register user
curl -X POST https://secure-auth-api-production.up.railway.app/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"SecurePass123!"}'

# Login
curl -X POST https://secure-auth-api-production.up.railway.app/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"SecurePass123!"}'

# Access protected route
curl -X GET https://secure-auth-api-production.up.railway.app/api/auth/me \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### Security Testing

**SQL Injection Test:**
```bash
curl -X POST https://secure-auth-api-production.up.railway.app/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com OR 1=1--","password":"anything"}'
# Returns validation error, not database error ✓
```

**XSS Test:**
```bash
curl -X POST https://secure-auth-api-production.up.railway.app/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"<script>alert(1)</script>@test.com","password":"SecurePass123!"}'
# HTML characters are escaped ✓
```

**Rate Limiting Test:**
```bash
# Make 6 rapid login attempts - 6th should be blocked
for i in {1..6}; do
  curl -X POST https://secure-auth-api-production.up.railway.app/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"test@example.com","password":"wrong"}';
done
```

## 📊 Project Structure

```
secure-auth-api/
├── src/
│   ├── config/
│   │   └── database.js          # PostgreSQL configuration
│   ├── controllers/
│   │   └── authController.js    # Authentication logic
│   ├── middleware/
│   │   ├── auth.js              # JWT verification
│   │   ├── validator.js         # Input validation
│   │   └── errorHandler.js      # Global error handling
│   ├── routes/
│   │   └── auth.js              # API routes
│   └── utils/
│       ├── tokenManager.js      # JWT token management
│       └── logger.js            # Winston logger
├── logs/                        # Application logs
├── .env                         # Environment variables
├── .gitignore
├── package.json
├── README.md
└── server.js                    # Entry point

auth-frontend/
├── public/
├── src/
│   ├── App.js                   # Main React component
│   ├── index.js
│   └── index.css                # Tailwind styles
├── package.json
└── README.md
```

## 🔐 Security Best Practices Implemented

1. **Authentication:** JWT with refresh token rotation, short-lived access tokens
2. **Password Security:** Bcrypt with 12 salt rounds, strong password policy
3. **Input Validation:** Strict validation, sanitization for injection attacks
4. **Rate Limiting:** Global and endpoint-specific limits, account lockout
5. **Headers & CORS:** CSP, HSTS, X-Frame-Options, configured CORS
6. **Database Security:** Parameterized queries, connection pooling, SSL/TLS
7. **Logging & Monitoring:** Comprehensive audit logs, security event tracking

## 🌐 Deployment

### Backend (Railway)
- Connected to GitHub repository
- Automatic deployment on push
- PostgreSQL database provisioned
- Environment variables configured

### Frontend (Vercel)
- Connected to GitHub repository
- Automatic deployment on push
- Custom domain support
- Edge network CDN

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📝 License

This project is licensed under the MIT License.

## 👤 Author

**Anisha Kumari**

- GitHub: [@yesanisha](https://github.com/yesanisha)
- Email: anishakumari6145@gmail.com
- LinkedIn:[yesanisha](https://www.linkedin.com/in/yesanisha/)

## 🙏 Acknowledgments

- OWASP for security best practices
- Express.js and React communities
- Railway and Vercel for hosting

## 📈 Future Enhancements

- [ ] Email verification
- [ ] Password reset functionality
- [ ] Two-factor authentication (2FA)
- [ ] OAuth integration (Google, GitHub)
- [ ] Role-based access control (RBAC)
- [ ] Session management dashboard
- [ ] API documentation with Swagger

---

Built with security in mind by Anisha Kumariion API

A production-ready authentication system built with Node.js, Express, PostgreSQL, and React, implementing industry-standard security practices and OWASP Top 10 protections.

[![Live Demo](https://img.shields.io/badge/demo-live-success)](https://secure-auth-api-production.up.railway.app)
[![Backend](https://img.shields.io/badge/backend-deployed-blue)](https://secure-auth-api-production.up.railway.app)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

## 🌟 Live Demo

- **Frontend:** [https://auth-frontend-6jowap9um-anishas-projects-738a86ea.vercel.app/](https://auth-frontend-6jowap9um-anishas-projects-738a86ea.vercel.app/)
- **Backend API:** [https://secure-auth-api-production.up.railway.app](https://secure-auth-api-production.up.railway.app)
- **API Health Check:** [https://secure-auth-api-production.up.railway.app/health](https://secure-auth-api-production.up.railway.app/health)

## 📸 Screenshots
<img width="699" height="812" alt="Screenshot 2025-10-03 at 21 37 32" src="https://github.com/user-attachments/assets/0ddaf324-52f6-44df-b751-afbe35b31c6f" />


## 🎯 Features

### Authentication & Authorization
- ✅ JWT-based authentication with access and refresh tokens
- ✅ Refresh token rotation (7-day expiry)
- ✅ Short-lived access tokens (15-minute expiry)
- ✅ Secure session management
- ✅ Protected routes with middleware

### Security Features (OWASP Top 10 Compliant)
- ✅ **Password Security:** Bcrypt hashing with 12 salt rounds
- ✅ **SQL Injection Prevention:** Parameterized queries with PostgreSQL
- ✅ **NoSQL Injection Prevention:** Custom input sanitization
- ✅ **XSS Protection:** HTML character escaping
- ✅ **Rate Limiting:** 5 login attempts per 15 minutes
- ✅ **Account Lockout:** Progressive lockout after failed attempts
- ✅ **Brute Force Prevention:** IP-based rate limiting (100 requests/15min)
- ✅ **Security Headers:** Helmet.js with CSP, HSTS, X-Frame-Options
- ✅ **CORS Protection:** Configurable allowed origins
- ✅ **Input Validation:** Express-validator with strict rules
- ✅ **Request Size Limits:** 10kb max payload (DoS prevention)
- ✅ **HTTP Parameter Pollution Prevention**
- ✅ **Comprehensive Logging:** Winston for security audit trails
- ✅ **Password Policy:** Minimum 8 characters, uppercase, lowercase, number, special character

### Additional Features
- 📊 Real-time validation and error handling
- 🎨 Responsive, modern UI with Tailwind CSS
- 🔄 Token refresh mechanism
- 📱 Mobile-friendly design
- 🐳 Docker support
- 📝 Comprehensive API documentation

## 🛠️ Tech Stack

### Backend
- **Runtime:** Node.js (v18+)
- **Framework:** Express.js
- **Database:** PostgreSQL (with connection pooling)
- **Authentication:** JWT (jsonwebtoken)
- **Password Hashing:** bcrypt
- **Security:** Helmet.js, express-rate-limit, hpp
- **Validation:** express-validator
- **Logging:** Winston

### Frontend
- **Framework:** React.js
- **Styling:** Tailwind CSS
- **Icons:** Lucide React
- **HTTP Client:** Fetch API
- **State Management:** React Hooks

### DevOps
- **Deployment:** Railway (Backend), Vercel (Frontend)
- **Containerization:** Docker
- **Version Control:** Git/GitHub
- **CI/CD:** Automatic deployment on push

## 🚀 Quick Start

### Prerequisites
- Node.js (v18 or higher)
- PostgreSQL (v15 or higher)
- npm or yarn

### Backend Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/yesanisha/secure-auth-api.git
   cd secure-auth-api
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Set up environment variables**
   ```bash
   cp .env.example .env
   ```
   
   Edit `.env` with your configuration:
   ```env
   NODE_ENV=development
   PORT=3000
   
   DB_HOST=localhost
   DB_PORT=5432
   DB_NAME=secure_auth_db
   DB_USER=your_db_user
   DB_PASSWORD=your_db_password
   
   JWT_SECRET=your_jwt_secret_here
   JWT_REFRESH_SECRET=your_refresh_secret_here
   
   ALLOWED_ORIGINS=http://localhost:3000,http://localhost:3001
   LOG_LEVEL=info
   ```

4. **Generate JWT secrets**
   ```bash
   node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
   ```
   Copy the output to your `.env` file (run twice for both secrets)

5. **Set up PostgreSQL database**
   ```bash
   # Using Docker (recommended)
   docker run --name postgres-auth \
     -e POSTGRES_PASSWORD=postgres \
     -e POSTGRES_DB=secure_auth_db \
     -p 5432:5432 \
     -d postgres:15-alpine
   
   # Or install PostgreSQL locally and create database
   ```

6. **Start the server**
   ```bash
   npm run dev
   ```
   
   Server will start at `http://localhost:3000`

### Frontend Setup

1. **Navigate to frontend directory**
   ```bash
   cd auth-frontend
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Update API URL** (if needed)
   
   In `src/App.js`, update the API_URL:
   ```javascript
   const API_URL = 'http://localhost:3000/api/auth';
   ```

4. **Start the development server**
   ```bash
   npm start
   ```
   
   Frontend will open at `http://localhost:3001`

## 📡 API Endpoints

### Public Endpoints

#### Register User
```http
POST /api/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePass123!"
}
```

**Response:**
```json
{
  "success": true,
  "message": "User registered successfully",
  "data": {
    "user": {
      "id": 1,
      "email": "user@example.com",
      "createdAt": "2025-10-03T13:39:59.822Z"
    },
    "tokens": {
      "accessToken": "eyJhbGciOiJIUzI1NiIs...",
      "refreshToken": "eyJhbGciOiJIUzI1NiIs...",
      "expiresIn": 900
    }
  }
}
```

#### Login
```http
POST /api/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePass123!"
}
```

#### Refresh Token
```http
POST /api/auth/refresh
Content-Type: application/json

{
  "refreshToken": "eyJhbGciOiJIUzI1NiIs..."
}
```

### Protected Endpoints

#### Get User Profile
```http
GET /api/auth/me
Authorization: Bearer {accessToken}
```

#### Logout
```http
POST /api/auth/logout
Authorization: Bearer {accessToken}
```

## 🧪 Testing

### Manual Testing with cURL

```bash
# Health check
curl http://localhost:3000/health

# Register user
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"SecurePass123!"}'

# Login
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"SecurePass123!"}'

# Access protected route
curl -X GET http://localhost:3000/api/auth/me \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"

# Test rate limiting (run 6 times quickly)
for i in {1..6}; do
  curl -X POST http://localhost:3000/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"test@example.com","password":"wrong"}'
done
```

### Security Testing

**SQL Injection Test:**
```bash
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com OR 1=1--","password":"anything"}'
# Should return validation error, not database error
```

**XSS Test:**
```bash
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"<script>alert(1)</script>@test.com","password":"SecurePass123!"}'
# Should sanitize/reject the input
```

## 🐳 Docker Deployment

### Using Docker Compose

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### Build Docker Image

```bash
# Build image
docker build -t secure-auth-api .

# Run container
docker run -p 3000:3000 --env-file .env secure-auth-api
```

## 🌐 Deployment

### Backend Deployment (Railway)

1. Push code to GitHub
2. Connect Railway to your repository
3. Add environment variables in Railway dashboard
4. Deploy automatically on push

### Frontend Deployment (Vercel)

```bash
# Install Vercel CLI
npm install -g vercel

# Login
vercel login

# Deploy
vercel

# Production deployment
vercel --prod
```

## 📊 Project Structure

```
secure-auth-api/
├── src/
│   ├── config/
│   │   └── database.js          # PostgreSQL configuration
│   ├── controllers/
│   │   └── authController.js    # Authentication logic
│   ├── middleware/
│   │   ├── auth.js              # JWT verification
│   │   ├── validator.js         # Input validation
│   │   └── errorHandler.js      # Global error handling
│   ├── routes/
│   │   └── auth.js              # API routes
│   └── utils/
│       ├── tokenManager.js      # JWT token management
│       └── logger.js            # Winston logger
├── logs/                        # Application logs
├── .env                         # Environment variables
├── .gitignore
├── docker-compose.yml
├── Dockerfile
├── package.json
├── README.md
└── server.js                    # Entry point
```

## 🔐 Security Best Practices Implemented

1. **Authentication:**
   - JWT with refresh token rotation
   - Short-lived access tokens (15 minutes)
   - Secure token storage and transmission

2. **Password Security:**
   - Bcrypt with 12 salt rounds
   - Strong password policy enforcement
   - No password hints or recovery questions

3. **Input Validation:**
   - Strict validation on all inputs
   - Sanitization to prevent injection attacks
   - Type checking and length limits

4. **Rate Limiting:**
   - Global rate limit: 100 requests per 15 minutes
   - Auth endpoints: 5 attempts per 15 minutes
   - Account lockout after failed attempts

5. **Headers & CORS:**
   - Content Security Policy (CSP)
   - HTTP Strict Transport Security (HSTS)
   - X-Frame-Options (clickjacking protection)
   - X-Content-Type-Options
   - Configured CORS with allowed origins

6. **Database Security:**
   - Parameterized queries (SQL injection prevention)
   - Connection pooling
   - Encrypted credentials
   - SSL/TLS in production

7. **Logging & Monitoring:**
   - Comprehensive audit logs
   - Error tracking
   - Security event logging

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the project
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👤 Author

**Anisha Kumari**

- GitHub: [@yesanisha](https://github.com/yesanisha)
- Email: anishakumari6145@gmail.com


## 🙏 Acknowledgments

- OWASP for security best practices
- Express.js community
- All contributors and testers

## 📈 Future Enhancements

- [ ] Email verification
- [ ] Password reset functionality
- [ ] Two-factor authentication (2FA)
- [ ] OAuth integration (Google, GitHub)
- [ ] Role-based access control (RBAC)
- [ ] Session management dashboard
- [ ] API rate limit dashboard
- [ ] Automated security testing
- [ ] Performance monitoring
- [ ] API documentation with Swagger

## 📞 Support

If you have any questions or need help, please:
- Open an issue on GitHub
- Email: anishakumari6145@gmail.com

---

⭐ If you find this project helpful, please consider giving it a star on GitHub!

**Built with ❤️ by Anisha Kumari**
