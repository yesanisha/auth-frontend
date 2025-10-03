import React, { useState, useEffect } from 'react';
import { Lock, Mail, User, Shield, LogOut, CheckCircle, XCircle } from 'lucide-react';

const API_URL = 'https://secure-auth-api-production.up.railway.app/api/auth';

const authService = {
  register: async (email, password) => {
    const response = await fetch(`${API_URL}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    return response.json();
  },

  login: async (email, password) => {
    const response = await fetch(`${API_URL}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    return response.json();
  },

  getProfile: async (token) => {
    const response = await fetch(`${API_URL}/me`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    return response.json();
  },

  refreshToken: async (refreshToken) => {
    const response = await fetch(`${API_URL}/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refreshToken })
    });
    return response.json();
  }
};

export default function SecureAuthApp() {
  const [view, setView] = useState('landing');
  const [user, setUser] = useState(null);
  const [tokens, setTokens] = useState(null);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState({ type: '', text: '' });
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  useEffect(() => {
    const storedTokens = localStorage.getItem('authTokens');
    if (storedTokens) {
      const parsed = JSON.parse(storedTokens);
      setTokens(parsed);
      loadProfile(parsed.accessToken);
    }
  }, []);

  const loadProfile = async (token) => {
    try {
      const result = await authService.getProfile(token);
      if (result.success) {
        setUser(result.data.user);
        setView('dashboard');
      }
    } catch (error) {
      console.error('Profile load failed');
    }
  };

  const handleAuth = async (isRegister) => {
    setLoading(true);
    setMessage({ type: '', text: '' });

    try {
      const result = isRegister
        ? await authService.register(email, password)
        : await authService.login(email, password);

      if (result.success) {
        setMessage({ type: 'success', text: `${isRegister ? 'Registration' : 'Login'} successful!` });
        setTokens(result.data.tokens);
        setUser(result.data.user);
        localStorage.setItem('authTokens', JSON.stringify(result.data.tokens));
        setTimeout(() => setView('dashboard'), 1000);
      } else {
        setMessage({ type: 'error', text: result.message || 'Authentication failed' });
      }
    } catch (error) {
      setMessage({ type: 'error', text: 'Network error. Is the server running?' });
    }

    setLoading(false);
  };

  const handleLogout = () => {
    localStorage.removeItem('authTokens');
    setTokens(null);
    setUser(null);
    setView('landing');
    setEmail('');
    setPassword('');
    setMessage({ type: 'success', text: 'Logged out successfully' });
  };

  const handleRefresh = async () => {
    if (!tokens?.refreshToken) return;
    setLoading(true);
    try {
      const result = await authService.refreshToken(tokens.refreshToken);
      if (result.success) {
        setTokens(result.data.tokens);
        localStorage.setItem('authTokens', JSON.stringify(result.data.tokens));
        setMessage({ type: 'success', text: 'Token refreshed!' });
      }
    } catch (error) {
      setMessage({ type: 'error', text: 'Refresh failed' });
    }
    setLoading(false);
  };

  const MessageAlert = () => message.text ? (
    <div className={`mb-6 p-4 rounded-lg flex items-center gap-3 ${message.type === 'success' ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
      }`}>
      {message.type === 'success' ? <CheckCircle className="w-5 h-5" /> : <XCircle className="w-5 h-5" />}
      {message.text}
    </div>
  ) : null;

  if (view === 'landing') {
    return (
      <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center p-4">
        <div className="max-w-4xl w-full">
          <div className="text-center mb-12">
            <Shield className="w-20 h-20 text-indigo-600 mx-auto mb-4" />
            <h1 className="text-5xl font-bold text-gray-900 mb-4">Secure Auth API</h1>
            <p className="text-xl text-gray-600">Production-ready authentication with 15+ security features</p>
          </div>

          <MessageAlert />

          <div className="grid md:grid-cols-2 gap-6">
            <div className="bg-white rounded-2xl shadow-xl p-8 hover:shadow-2xl transition-shadow cursor-pointer"
              onClick={() => setView('login')}>
              <Lock className="w-12 h-12 text-indigo-600 mb-4" />
              <h2 className="text-2xl font-bold mb-4">Login</h2>
              <p className="text-gray-600 mb-6">Access your secure account with JWT authentication</p>
              <div className="w-full bg-indigo-600 text-white py-3 rounded-lg font-semibold text-center">
                Sign In
              </div>
            </div>

            <div className="bg-white rounded-2xl shadow-xl p-8 hover:shadow-2xl transition-shadow cursor-pointer"
              onClick={() => setView('register')}>
              <User className="w-12 h-12 text-green-600 mb-4" />
              <h2 className="text-2xl font-bold mb-4">Register</h2>
              <p className="text-gray-600 mb-6">Create a new account with encrypted credentials</p>
              <div className="w-full bg-green-600 text-white py-3 rounded-lg font-semibold text-center">
                Sign Up
              </div>
            </div>
          </div>

          <div className="mt-12 bg-white rounded-2xl shadow-xl p-8">
            <h3 className="text-xl font-bold mb-4 flex items-center gap-2">
              <Shield className="w-6 h-6 text-indigo-600" />
              Security Features
            </h3>
            <div className="grid md:grid-cols-3 gap-4">
              {['JWT Tokens', 'Rate Limiting', 'Password Hashing', 'SQL Prevention', 'XSS Protection',
                'Account Lockout', 'OWASP Headers', 'CORS Protection', 'Input Validation'].map((f, i) => (
                  <div key={i} className="flex items-center gap-2 text-sm text-gray-700">
                    <CheckCircle className="w-4 h-4 text-green-600 flex-shrink-0" />
                    {f}
                  </div>
                ))}
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (view === 'login' || view === 'register') {
    const isLogin = view === 'login';
    return (
      <div className={`min-h-screen bg-gradient-to-br ${isLogin ? 'from-blue-50 to-indigo-100' : 'from-green-50 to-emerald-100'} flex items-center justify-center p-4`}>
        <div className="max-w-md w-full">
          <div className="bg-white rounded-2xl shadow-xl p-8">
            <div className="text-center mb-8">
              {isLogin ? <Lock className="w-16 h-16 text-indigo-600 mx-auto mb-4" /> :
                <User className="w-16 h-16 text-green-600 mx-auto mb-4" />}
              <h2 className="text-3xl font-bold">{isLogin ? 'Welcome Back' : 'Create Account'}</h2>
              <p className="text-gray-600 mt-2">{isLogin ? 'Sign in to your account' : 'Join our platform'}</p>
            </div>

            <MessageAlert />

            <div className="space-y-6">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Email</label>
                <div className="relative">
                  <Mail className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="w-full pl-10 pr-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500"
                    placeholder="you@example.com"
                  />
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Password</label>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
                  <input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="w-full pl-10 pr-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500"
                    placeholder={isLogin ? "Enter password" : "Min 8 chars, uppercase, number, special"}
                  />
                </div>
                {!isLogin && (
                  <p className="mt-2 text-xs text-gray-500">
                    Must contain: uppercase, lowercase, number, special character
                  </p>
                )}
              </div>

              <button
                onClick={() => handleAuth(!isLogin)}
                disabled={loading}
                className={`w-full ${isLogin ? 'bg-indigo-600 hover:bg-indigo-700' : 'bg-green-600 hover:bg-green-700'} text-white py-3 rounded-lg font-semibold transition-colors disabled:opacity-50`}
              >
                {loading ? 'Processing...' : isLogin ? 'Sign In' : 'Create Account'}
              </button>
            </div>

            <div className="mt-6 text-center">
              <button
                onClick={() => { setView('landing'); setMessage({ type: '', text: '' }); }}
                className={`${isLogin ? 'text-indigo-600' : 'text-green-600'} font-medium`}
              >
                ← Back to Home
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (view === 'dashboard' && user && tokens) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-purple-50 to-pink-100">
        <nav className="bg-white shadow-md">
          <div className="max-w-6xl mx-auto px-4 py-4 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Shield className="w-8 h-8 text-indigo-600" />
              <span className="text-xl font-bold">Secure Dashboard</span>
            </div>
            <button
              onClick={handleLogout}
              className="flex items-center gap-2 bg-red-600 text-white px-4 py-2 rounded-lg hover:bg-red-700"
            >
              <LogOut className="w-4 h-4" />
              Logout
            </button>
          </div>
        </nav>

        <div className="max-w-6xl mx-auto px-4 py-8">
          <MessageAlert />

          <div className="grid md:grid-cols-2 gap-6">
            <div className="bg-white rounded-2xl shadow-xl p-6">
              <h3 className="text-xl font-bold mb-4 flex items-center gap-2">
                <User className="w-6 h-6 text-indigo-600" />
                User Profile
              </h3>
              <div className="space-y-3">
                <div>
                  <span className="text-sm text-gray-500">User ID</span>
                  <p className="text-lg font-semibold">{user.id}</p>
                </div>
                <div>
                  <span className="text-sm text-gray-500">Email</span>
                  <p className="text-lg font-semibold">{user.email}</p>
                </div>
                <div>
                  <span className="text-sm text-gray-500">Created</span>
                  <p className="text-lg font-semibold">{new Date(user.createdAt).toLocaleDateString()}</p>
                </div>
              </div>
            </div>

            <div className="bg-white rounded-2xl shadow-xl p-6">
              <h3 className="text-xl font-bold mb-4 flex items-center gap-2">
                <Lock className="w-6 h-6 text-green-600" />
                Security Status
              </h3>
              <div className="space-y-3">
                {['Authentication', 'JWT Active', 'Session Encrypted'].map((s, i) => (
                  <div key={i} className="flex items-center justify-between p-3 bg-green-50 rounded-lg">
                    <span className="text-sm font-medium">{s}</span>
                    <CheckCircle className="w-5 h-5 text-green-600" />
                  </div>
                ))}
              </div>
              <button
                onClick={handleRefresh}
                disabled={loading}
                className="w-full mt-4 bg-indigo-600 text-white py-2 rounded-lg hover:bg-indigo-700 disabled:opacity-50"
              >
                {loading ? 'Refreshing...' : 'Refresh Token'}
              </button>
            </div>
          </div>

          <div className="mt-6 bg-white rounded-2xl shadow-xl p-6">
            <h3 className="text-xl font-bold mb-4">Token Information</h3>
            <div className="space-y-4">
              <div>
                <span className="text-sm text-gray-500 font-medium">Access Token (15 min)</span>
                <div className="mt-2 p-3 bg-gray-100 rounded-lg break-all text-sm font-mono">
                  {tokens.accessToken.substring(0, 100)}...
                </div>
              </div>
              <div>
                <span className="text-sm text-gray-500 font-medium">Refresh Token (7 days)</span>
                <div className="mt-2 p-3 bg-gray-100 rounded-lg break-all text-sm font-mono">
                  {tokens.refreshToken.substring(0, 100)}...
                </div>
              </div>
            </div>
          </div>

          <div className="mt-6 bg-gradient-to-r from-indigo-500 to-purple-600 rounded-2xl shadow-xl p-6 text-white">
            <h3 className="text-xl font-bold mb-2">🎉 Success!</h3>
            <p className="text-indigo-100">
              You're authenticated with JWT tokens, bcrypt hashing, rate limiting, and OWASP security practices!
            </p>
          </div>
        </div>
      </div>
    );
  }

  return null;
}