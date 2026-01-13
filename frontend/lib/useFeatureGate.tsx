"use client";

import { createContext, useContext, useEffect, useState, ReactNode } from "react";

interface FeatureInfo {
  name: string;
  description: string;
  available: boolean;
  is_paid: boolean;
}

interface ModeConfig {
  mode: "OSS" | "SAAS";
  is_saas: boolean;
  is_oss: boolean;
  features: Record<string, FeatureInfo>;
}

interface FeatureGateContextType {
  config: ModeConfig | null;
  loading: boolean;
  isPaidFeature: (featureName: string) => boolean;
  isFeatureAvailable: (featureName: string) => boolean;
  isSaasMode: () => boolean;
  isOssMode: () => boolean;
  user: any; // Expose user for debugging and UI logic
  refetchUser: () => Promise<void>; // Allow re-fetching user after login
}

const defaultConfig: ModeConfig = {
  mode: "OSS",
  is_saas: false,
  is_oss: true,
  features: {},
};

const FeatureGateContext = createContext<FeatureGateContextType>({
  config: null,
  loading: true,
  isPaidFeature: () => true,
  isFeatureAvailable: () => false,
  isSaasMode: () => false,
  isOssMode: () => true,
  user: null,
  refetchUser: async () => {},
});

export function FeatureGateProvider({ children }: { children: ReactNode }) {
  const [config, setConfig] = useState<ModeConfig | null>(null);
  const [user, setUser] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const init = async () => {
        await Promise.all([fetchConfig(), fetchUser()]);
        setLoading(false);
    };
    init();
  }, []);

  const fetchConfig = async () => {
    try {
      const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:9001/api";
      const response = await fetch(`${API_URL}/config/`);
      if (response.ok) {
        const data = await response.json();
        setConfig(data);
      } else {
        setConfig(defaultConfig);
      }
    } catch (error) {
      console.warn("Failed to fetch config, defaulting to OSS mode");
      setConfig(defaultConfig);
    }
  };

  const fetchUser = async () => {
      try {
          const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:9001/api";
          const res = await fetch(`${API_URL}/auth/me/`, { credentials: "include" });
          if (res.ok) {
              const userData = await res.json();
              // Check if we got actual user data (has username) vs empty object
              if (userData && userData.username) {
                  console.log("FeatureGate: User loaded", userData.username, "Is Staff:", userData.is_staff);
                  setUser(userData);
              } else {
                  console.log("FeatureGate: Not authenticated (empty response)");
                  setUser(null);
              }
          } else {
              console.warn("FeatureGate: Failed to fetch user", res.status);
              setUser(null);
          }
      } catch (e) {
          console.error("FeatureGate: Error fetching user", e);
          setUser(null);
      }
  };

  const isPaidFeature = (featureName: string): boolean => {
    if (!config) return true;
    const feature = config.features[featureName];
    return feature?.is_paid ?? false;
  };

  const isFeatureAvailable = (featureName: string): boolean => {
    if (!config) return false;
    
    // 1. Check if user is admin/staff (Always allow)
    if (user && (user.is_staff || user.is_superuser)) {
        return true;
    }

    const feature = config.features[featureName];
    
    // 2. Check global availability (OSS mode might disable it)
    if (!feature?.available) {
        return false;
    }

    // 3. If SAAS mode and Paid Feature, allow everyone for now (Free for all)
    if (config.is_saas && feature.is_paid) {
         return true;
    }

    return true;
  };

  const isSaasMode = (): boolean => {
    return config?.is_saas ?? false;
  };

  const isOssMode = (): boolean => {
    return config?.is_oss ?? true;
  };

  return (
    <FeatureGateContext.Provider
      value={{
        config,
        loading,
        isPaidFeature,
        isFeatureAvailable,
        isSaasMode,
        isOssMode,
        user, // Exposed
        refetchUser: fetchUser, // Allow external trigger
      }}
    >
      {children}
    </FeatureGateContext.Provider>
  );
}

export function useFeatureGate() {
  const context = useContext(FeatureGateContext);
  if (!context) {
    throw new Error("useFeatureGate must be used within a FeatureGateProvider");
  }
  return context;
}

/**
 * Hook to check if a specific feature is available.
 * Returns { available, loading, featureInfo }
 */
export function useFeature(featureName: string) {
  const { config, loading, isFeatureAvailable, isPaidFeature } = useFeatureGate();

  return {
    available: isFeatureAvailable(featureName),
    loading,
    isPaid: isPaidFeature(featureName),
    featureInfo: config?.features[featureName] ?? null,
  };
}
