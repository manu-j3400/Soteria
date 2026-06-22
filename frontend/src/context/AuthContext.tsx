import React, { createContext, useContext, useState, useEffect } from 'react';
import { supabase } from '../lib/supabase';

interface User {
    id: string;
    name: string;
    email: string;
}

interface AuthContextType {
    user: User | null;
    token: string | null;
    login: (email: string, password: string) => Promise<void>;
    signup: (name: string, email: string, password: string) => Promise<void>;
    signInWithGoogle: () => Promise<void>;
    logout: () => void;
    isAuthenticated: boolean;
    isLoading: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
    const [user, setUser] = useState<User | null>(null);
    const [token, setToken] = useState<string | null>(null);
    const [isLoading, setIsLoading] = useState(true);

    useEffect(() => {
        // Timeout guard: if Supabase doesn't respond in 3s (missing env vars,
        // placeholder URL, or network issue) treat as logged out and unblock UI.
        const loadingTimeout = setTimeout(() => setIsLoading(false), 3000);

        // Get initial session
        supabase.auth.getSession().then(({ data: { session } }) => {
            clearTimeout(loadingTimeout);
            if (session) {
                const t = session.access_token;
                setToken(t);
                localStorage.setItem('soteria_token', t);
                setUser({
                    id: session.user.id,
                    email: session.user.email || '',
                    name: session.user.user_metadata?.name || 'User'
                });
            }
            setIsLoading(false);
        }).catch(() => {
            clearTimeout(loadingTimeout);
            // Supabase unreachable (no env vars set) — treat as logged out
            setIsLoading(false);
        });

        // Listen for auth changes
        const { data: { subscription } } = supabase.auth.onAuthStateChange((_event, session) => {
            if (session) {
                const t = session.access_token;
                setToken(t);
                localStorage.setItem('soteria_token', t);
                setUser({
                    id: session.user.id,
                    email: session.user.email || '',
                    name: session.user.user_metadata?.name || 'User'
                });
            } else {
                setToken(null);
                setUser(null);
                localStorage.removeItem('soteria_token');
            }
            setIsLoading(false);
        });

        // If Supabase is unreachable (paused project, bad env vars), kill the
        // subscription after 5 seconds to stop the token-refresh retry spam.
        const subKillTimer = setTimeout(() => {
            subscription.unsubscribe();
        }, 5000);

        return () => {
            clearTimeout(subKillTimer);
            subscription.unsubscribe();
        };
    }, []);

    const login = async (email: string, password: string) => {
        const { error, data } = await supabase.auth.signInWithPassword({ email, password });
        if (error) throw new Error(error.message);
        if (data.session) {
            setToken(data.session.access_token);
            setUser({
                id: data.session.user.id,
                email: data.session.user.email || '',
                name: data.session.user.user_metadata?.name || 'User'
            });
        }
    };

    const signInWithGoogle = async () => {
        const siteUrl = import.meta.env.VITE_SITE_URL || window.location.origin;
        const { error } = await supabase.auth.signInWithOAuth({
            provider: 'google',
            options: { redirectTo: `${siteUrl}/dashboard` }
        });
        if (error) throw new Error(error.message);
    };

    const signup = async (name: string, email: string, password: string) => {
        const { error, data } = await supabase.auth.signUp({
            email,
            password,
            options: {
                data: { name }
            }
        });
        if (error) throw new Error(error.message);
        if (data.session) {
            setToken(data.session.access_token);
            setUser({
                id: data.session.user.id,
                email: data.session.user.email || '',
                name: data.session.user.user_metadata?.name || 'User'
            });
        }
    };

    const logout = async () => {
        await supabase.auth.signOut();
        setUser(null);
        setToken(null);
    };

    return (
        <AuthContext.Provider value={{
            user,
            token,
            login,
            signup,
            signInWithGoogle,
            logout,
            isAuthenticated: !!user,
            isLoading
        }}>
            {children}
        </AuthContext.Provider>
    );
}

export function useAuth() {
    const context = useContext(AuthContext);
    if (context === undefined) {
        throw new Error('useAuth must be used within an AuthProvider');
    }
    return context;
}
