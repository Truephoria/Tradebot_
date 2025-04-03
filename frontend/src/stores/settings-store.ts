// frontend/src/stores/settings-store.ts
import { create } from 'zustand';
import axios from '@/utils/axios';
import { SettingsStateType, SettingsAction } from '@/types/settings';

export type SettingStoreType = SettingsStateType & SettingsAction;

// Initial state for the settings store
export const initSettingState: SettingsStateType = {
  settings: {
    riskType: 'PERCENTAGE',
    riskValue: 1.5,
    maxDailyLoss: 3,
    minimumRRR: 1.5,
    enableTrailingStop: true,
    tradingHoursStart: '08:00',
    tradingHoursEnd: '16:00',
    maxTradesPerDay: 10,
    allowedSymbols: 'EURUSD,GBPUSD,XAUUSD,USDJPY,US30',
    botEnabled: true,
    apiId: '',
    apiHash: '',
    phoneNumber: '',
  },
  isLoading: false,
  error: null,
};

interface SettingState {
  settings: SettingsStateType['settings'];
  isLoading: boolean;
  error: string | null;
  getSettings: () => Promise<void>;
  updateSettings: (newSettings: Partial<SettingsStateType['settings']>) => Promise<void>;
}

export const useSettingStore = create<SettingState>((set) => ({
  settings: initSettingState.settings,
  isLoading: false,
  error: null,
  // Fetch all settings (risk/trading + Telegram)
  getSettings: async () => {
    set({ isLoading: true });
    try {
      // Fetch risk/trading settings
      const settingsResponse = await axios.get("/api/settings");
      // Fetch Telegram settings
      const telegramResponse = await axios.get("/api/telegram/auth_settings");
      const credentials = telegramResponse.data.credentials || {};

      set((state) => ({
        settings: {
          ...state.settings,
          ...settingsResponse.data.settings,
          apiId: credentials.apiId || '',
          apiHash: credentials.apiHash || '',
          phoneNumber: credentials.phoneNumber || '',
        },
        error: null,
      }));
      console.log("Settings fetched:", settingsResponse.data.status);
      console.log("Telegram settings fetched:", telegramResponse.data.status);
    } catch (error) {
      console.error("Error fetching settings:", error);
      set({ error: "Failed to fetch settings" });
      throw error;
    } finally {
      set({ isLoading: false });
    }
  },
  // Update all settings (risk/trading + Telegram)
  updateSettings: async (newSettings) => {
    set({ isLoading: true });
    try {
      // Check if Telegram settings are being updated
      const hasTelegramSettings = 'apiId' in newSettings || 'apiHash' in newSettings || 'phoneNumber' in newSettings;
      const telegramSettings: Partial<Pick<SettingsStateType['settings'], 'apiId' | 'apiHash' | 'phoneNumber'>> = {};

      if (hasTelegramSettings) {
        if (newSettings.apiId !== undefined) telegramSettings.apiId = newSettings.apiId;
        if (newSettings.apiHash !== undefined) telegramSettings.apiHash = newSettings.apiHash;
        if (newSettings.phoneNumber !== undefined) telegramSettings.phoneNumber = newSettings.phoneNumber;
      }

      // Update risk/trading settings if present
      const riskTradingSettings: Partial<SettingsStateType['settings']> = { ...newSettings };
      delete riskTradingSettings.apiId;
      delete riskTradingSettings.apiHash;
      delete riskTradingSettings.phoneNumber;

      // Send requests to the appropriate endpoints
      const promises: Promise<any>[] = [];
      if (Object.keys(riskTradingSettings).length > 0) {
        promises.push(axios.post("/api/settings", riskTradingSettings));
      }
      if (Object.keys(telegramSettings).length > 0) {
        promises.push(axios.post("/api/telegram/auth_settings", telegramSettings));
      }

      const responses = await Promise.all(promises);

      // Update the store with the new settings
      set((state) => ({
        settings: {
          ...state.settings,
          ...newSettings,
        },
        error: null,
      }));

      responses.forEach((response) => {
        console.log("Settings updated:", response.data.status);
      });
    } catch (error) {
      console.error("Error updating settings:", error);
      set({ error: "Failed to update settings" });
      throw error;
    } finally {
      set({ isLoading: false });
    }
  },
}));