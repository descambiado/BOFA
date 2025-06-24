
import { createContext, useContext, useState, ReactNode } from 'react';

interface AppContextType {
  favoriteScripts: string[];
  addFavoriteScript: (scriptName: string) => void;
  removeFavoriteScript: (scriptName: string) => void;
  isFavorite: (scriptName: string) => boolean;
  executionHistory: ExecutionRecord[];
  addExecutionRecord: (record: ExecutionRecord) => void;
  clearExecutionHistory: () => void;
}

interface ExecutionRecord {
  id: string;
  script: string;
  module: string;
  timestamp: string;
  status: 'success' | 'error' | 'warning';
  executionTime: string;
  parameters?: Record<string, any>;
}

const AppContext = createContext<AppContextType | undefined>(undefined);

export const useApp = () => {
  const context = useContext(AppContext);
  if (context === undefined) {
    throw new Error('useApp must be used within an AppProvider');
  }
  return context;
};

interface AppProviderProps {
  children: ReactNode;
}

export const AppProvider = ({ children }: AppProviderProps) => {
  const [favoriteScripts, setFavoriteScripts] = useState<string[]>([]);
  const [executionHistory, setExecutionHistory] = useState<ExecutionRecord[]>([]);

  const addFavoriteScript = (scriptName: string) => {
    setFavoriteScripts(prev => {
      if (!prev.includes(scriptName)) {
        return [...prev, scriptName];
      }
      return prev;
    });
  };

  const removeFavoriteScript = (scriptName: string) => {
    setFavoriteScripts(prev => prev.filter(name => name !== scriptName));
  };

  const isFavorite = (scriptName: string) => {
    return favoriteScripts.includes(scriptName);
  };

  const addExecutionRecord = (record: ExecutionRecord) => {
    setExecutionHistory(prev => [record, ...prev.slice(0, 99)]); // Keep last 100 records
  };

  const clearExecutionHistory = () => {
    setExecutionHistory([]);
  };

  const value: AppContextType = {
    favoriteScripts,
    addFavoriteScript,
    removeFavoriteScript,
    isFavorite,
    executionHistory,
    addExecutionRecord,
    clearExecutionHistory
  };

  return <AppContext.Provider value={value}>{children}</AppContext.Provider>;
};
