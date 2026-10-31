'use client';

import React, { createContext, useContext, useEffect, useState } from 'react';
import { UserDto, login as apiLogin, register as apiRegister, logout as apiLogout } from '@/lib/api';

interface AuthContextType {
  user: UserDto | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (email: string, pass: string) => Promise<void>;
  register: (email: string, pass: string, name: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<UserDto | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    try {
      const storedToken = localStorage.getItem('syscan_token');
      const storedUser = localStorage.getItem('syscan_user');
      if (storedToken && storedUser) {
        setToken(storedToken);
        setUser(JSON.parse(storedUser));
      }
    } catch {
      // In case of parsing error
    } finally {
      setIsLoading(false);
    }
  }, []);

  const login = async (email: string, pass: string) => {
    const res = await apiLogin(email, pass);
    setUser(res.user);
    setToken(res.token);
  };

  const register = async (email: string, pass: string, name: string) => {
    const res = await apiRegister(email, pass, name);
    setUser(res.user);
    setToken(res.token);
  };

  const logout = () => {
    apiLogout();
    setUser(null);
    setToken(null);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        isAuthenticated: !!token,
        isLoading,
        login,
        register,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

