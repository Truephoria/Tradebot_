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
  getSettings: () => void;
  updateSettings: (settings: any) => void;
};
