import { createContext, useCallback, useContext, useEffect, useState } from "react";
import { api, tokenStore } from "@/lib/api";

const AuthContext = createContext(null);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used within AuthProvider");
  return context;
};

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  const logout = useCallback(() => {
    tokenStore.clear();
    setUser(null);
  }, []);

  useEffect(() => {
    if (!tokenStore.get()) {
      setLoading(false);
      return;
    }
    api
      .get("/users/me")
      .then((res) => setUser(res.data))
      .catch(logout)
      .finally(() => setLoading(false));
  }, [logout]);

  useEffect(() => {
    window.addEventListener("sw:logout", logout);
    return () => window.removeEventListener("sw:logout", logout);
  }, [logout]);

  const authenticate = async (path, email, password) => {
    const res = await api.post(path, { email, password });
    tokenStore.set(res.data.access_token);
    setUser(res.data.user);
    return res.data.user;
  };

  const value = {
    user,
    loading,
    isAuthenticated: !!user,
    login: (email, password) => authenticate("/auth/login", email, password),
    register: (email, password) => authenticate("/auth/register", email, password),
    logout,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
