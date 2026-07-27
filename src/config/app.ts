/**
 * BOFA v2.9.1
 * Central application configuration for the local-first runtime and UI.
 */

export const APP_CONFIG = {
  name: "BOFA",
  fullName: "Local-first security runtime",
  version: "2.9.1",
  codename: "Duplicate-aware web/API hunting",
  releaseDate: "2026-04-29",

  developer: {
    name: "@descambiado",
    fullName: "David Hernandez Jimenez",
    email: "david@descambiado.com",
    github: "https://github.com/descambiado",
    website: "https://descambiado.com",
  },

  api: {
    baseUrl: "/api",
    timeout: 5000,
    retryAttempts: 1,
    mockMode: "auto" as "auto" | boolean,
  },

  features: {
    localFirstRuntime: true,
    duplicateAwareBounty: true,
    evidenceExports: true,
    aiCopilots: true,
    dockerLabsManagement: true,
    realTimeScriptExecution: true,
    runHistory: true,
    controlPlane: true,
  },

  limits: {
    maxConcurrentScripts: 5,
    maxLabsRunning: 3,
    scriptTimeoutSeconds: 300,
    apiTimeoutMs: 30000,
  },

  ui: {
    theme: "dark",
    animationDuration: 300,
    toastDuration: 4000,
    refreshInterval: 30000,
  },
} as const;

export type AppConfig = typeof APP_CONFIG;
