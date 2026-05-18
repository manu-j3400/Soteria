import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { Component, ReactNode } from 'react';
import Layout from './components/Layout';
import DesktopHome from './pages/DesktopHome';
import Scanner from './pages/Scanner';
import About from './pages/About';
import NeuralEngine from './pages/NeuralEngine';
import KnowledgeGraph from './pages/KnowledgeGraph';
import BatchScanner from './pages/BatchScanner';
import Login from './pages/Login';
import Signup from './pages/Signup';
import LandingPage from './pages/LandingPage';
import FeaturesPage from './pages/FeaturesPage';
import HowItWorks from './pages/HowItWorks';
import ForgotPassword from './pages/ForgotPassword';
import GithubCallback from './pages/GithubCallback';
import { AuthProvider } from './context/AuthContext';
import { GameProvider } from './context/GameContext';
import { ThemeProvider } from './context/ThemeContext';
import ProtectedRoute from './components/ProtectedRoute';
import AdminLogin from './pages/AdminLogin';
import AdminDashboard from './pages/AdminDashboard';
import AdminProtectedRoute from './components/AdminProtectedRoute';
import PublicRoute from './components/PublicRoute';

import { Analytics } from '@vercel/analytics/react';

class RouteErrorBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state = { error: null };
  static getDerivedStateFromError(error: Error) { return { error }; }
  render() {
    if (this.state.error) {
      return (
        <div className="min-h-screen bg-black flex items-center justify-center p-8">
          <div className="max-w-lg text-center space-y-4">
            <p className="text-xs font-mono text-red-400 uppercase tracking-widest">Page Error</p>
            <p className="text-neutral-400 text-sm font-mono">{(this.state.error as Error).message}</p>
            <button onClick={() => window.location.reload()} className="text-xs text-blue-400 underline">Reload</button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

function AuthenticatedLayout({ children }: { children: React.ReactNode }) {
  return (
    <Layout>
      {children}
    </Layout>
  );
}

function App() {
  return (
    <>
      <ThemeProvider>
      <AuthProvider>
          <GameProvider>
            <Router>
              <RouteErrorBoundary>
              <Routes>
                {/* PUBLIC ROUTES */}
                <Route path="/" element={<Navigate to="/home" replace />} />
                <Route path="/home" element={<PublicRoute><LandingPage /></PublicRoute>} />
                <Route path="/features" element={<FeaturesPage />} />
                <Route path="/how-it-works" element={<HowItWorks />} />
                <Route path="/login" element={<PublicRoute><Login /></PublicRoute>} />
                <Route path="/signup" element={<PublicRoute><Signup /></PublicRoute>} />
                <Route path="/forgot-password" element={<ForgotPassword />} />

                {/* PROTECTED ROUTES */}
                <Route path="/dashboard" element={
                  <ProtectedRoute>
                    <DesktopHome />
                  </ProtectedRoute>
                } />


                <Route path="/scanner" element={
                  <ProtectedRoute>
                    <AuthenticatedLayout>
                      <Scanner />
                    </AuthenticatedLayout>
                  </ProtectedRoute>
                } />

                <Route path="/engine" element={
                  <ProtectedRoute>
                    <AuthenticatedLayout>
                      <NeuralEngine />
                    </AuthenticatedLayout>
                  </ProtectedRoute>
                } />

                <Route path="/graph" element={
                  <ProtectedRoute>
                    <AuthenticatedLayout>
                      <KnowledgeGraph />
                    </AuthenticatedLayout>
                  </ProtectedRoute>
                } />

                <Route path="/about" element={<About />} />

                <Route path="/batch" element={
                  <ProtectedRoute>
                    <AuthenticatedLayout>
                      <BatchScanner />
                    </AuthenticatedLayout>
                  </ProtectedRoute>
                } />

                <Route path="/auth/github/callback" element={<GithubCallback />} />

                {/* ADMIN ROUTES */}
                <Route path="/admin/login" element={<AdminLogin />} />
                <Route path="/admin" element={
                  <AdminProtectedRoute>
                    <AdminDashboard />
                  </AdminProtectedRoute>
                } />

                {/* FALLBACK */}
                <Route path="*" element={<Navigate to="/home" replace />} />

              </Routes>
              </RouteErrorBoundary>
            </Router>
          </GameProvider>
      </AuthProvider>
      </ThemeProvider>
      <Analytics />
    </>
  );
}

export default App;
