/**
 * BOFA v2.5.1 - Neural Security Edge
 * Configuración centralizada de la aplicación
 */

export const APP_CONFIG = {
  // Información de la aplicación
  name: "BOFA",
  fullName: "Best Of All Cybersecurity Suite",
  version: "2.5.1",
  codename: "Neural Security Edge",
  releaseDate: "2025-01-08",
  
  // Información del desarrollador
  developer: {
    name: "@descambiado",
    fullName: "David Hernández Jiménez",
    email: "david@descambiado.com",
    github: "https://github.com/descambiado",
    website: "https://descambiado.com"
  },
  
  // URLs y endpoints - Funcional sin backend externo
  api: {
    baseUrl: "/api", // Usando rutas relativas para demo
    timeout: 5000,
    retryAttempts: 1,
    mockMode: 'auto' // Auto: usa API real si está disponible, demo si no
  },
  
  // Características de la versión
  features: {
    neuralThreatPrediction: true,
    quantumResistantCrypto: true,
    dnaCryptography: true,
    behavioralBiometrics: true,
    autonomousPentesting: true,
    realTimeThreatCorrelation: true,
    edgeAiSecurity: true,
    neuralSiemIntegration: true,
    dockerLabsManagement: true,
    realTimeScriptExecution: true
  },
  
  // Límites y configuraciones
  limits: {
    maxConcurrentScripts: 5,
    maxLabsRunning: 3,
    scriptTimeoutSeconds: 300,
    apiTimeoutMs: 30000
  },
  
  // Configuración de UI
  ui: {
    theme: "dark",
    animationDuration: 300,
    toastDuration: 4000,
    refreshInterval: 30000
  }
} as const;

export type AppConfig = typeof APP_CONFIG;