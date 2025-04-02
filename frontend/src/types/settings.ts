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
  // Telegram settings
  apiId: number; // API_ID as an integer
  apiHash: number; // API_HASH as an integer
  phoneNumber: number; // PHONE_NUMBER as an integer
};

export type SettingsStateType = {
  settings: SettingsType;
  isLoading: boolean;
  error: string | null;
};

export type SettingsAction = {
  getSettings: () => Promise<void>;
  updateSettings: (settings: Partial<SettingsType>) => Promise<void>;
  getTelegramSettings: () => Promise<void>;
  updateTelegramSettings: (settings: Partial<Pick<SettingsType, 'apiId' | 'apiHash' | 'phoneNumber'>>) => Promise<void>;
};