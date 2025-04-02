// frontend/src/types/settings.ts

export type SettingsType = {
  allowedSymbols: string;
  botEnabled: boolean;
  enableTrailingStop: boolean;
  maxDailyLoss: number;
  maxTradesPerDay: number;
  minimumRRR: number;
  riskType: "FIXED" | "PERCENTAGE";
  riskValue: number;
  tradingHoursEnd: string;
  tradingHoursStart: string;
  
};

export type SettingsStateType = {
  settings: SettingsType;
  isLoading: boolean;
  error: string | null;
};

export type SettingsAction = {
  getSettings: () => Promise<void>;
  updateSettings: (settings: Partial<SettingsType>) => Promise<void>;
 
};