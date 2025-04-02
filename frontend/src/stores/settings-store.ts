// frontend/src/stores/settings-store.ts
import { create } from 'zustand';
import axios from '@/utils/axios'; // Your configured axios instance
import { SettingsStateType, SettingsAction } from '@/types/settings';

export type SettingStoreType = SettingsStateType & SettingsAction;

interface Settings {
  // Existing risk/trading settings
  riskType: 'FIXED' | 'PERCENTAGE';
  riskValue: number;
  maxDailyLoss: number;
  minimumRRR: number;
  enableTrailingStop: boolean;
  tradingHoursStart: string;
  tradingHoursEnd: string;
  maxTradesPerDay: number;
  allowedSymbols: string;
  botEnabled: boolean;
  // New Telegram settings
  apiId: number;
  apiHash: string;
  phoneNumber: string;
}

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
  settings: Record<string, any>;
  isLoading: boolean;
  getSettings: () => Promise<void>;
  updateSettings: (newSettings: Record<string, any>) => Promise<void>;
  getTelegramSettings: () => Promise<void>;
  updateTelegramSettings: (newSettings: Record<string, any>) => Promise<void>;
}

export const useSettingStore = create<SettingState>((set) => ({
  settings: {},
  isLoading: false,
  // Fetch risk/trading settings
  getSettings: async () => {
    set({ isLoading: true });
    try {
      const response = await axios.get("/api/settings");
      set((state) => ({
        settings: { ...state.settings, ...response.data.settings },
      }));
      console.log("Settings fetched:", response.data.status);
    } catch (error) {
      console.error("Error fetching settings:", error);
      throw error;
    } finally {
      set({ isLoading: false });
    }
  },
  // Update risk/trading settings
  updateSettings: async (newSettings) => {
    set({ isLoading: true });
    try {
      const response = await axios.post("/api/settings", newSettings);
      set((state) => ({
        settings: { ...state.settings, ...response.data.settings },
      }));
      console.log("Settings updated:", response.data.status);
    } catch (error) {
      console.error("Error updating settings:", error);
      throw error;
    } finally {
      set({ isLoading: false });
    }
  },
  // Fetch Telegram settings
  getTelegramSettings: async () => {
    set({ isLoading: true });
    try {
      const response = await axios.get("/api/telegram/auth_settings");
      const credentials = response.data.credentials || {};
      set((state) => ({
        settings: {
          ...state.settings,
          apiId: credentials.apiId ? Number(credentials.apiId) : 0,
          apiHash: credentials.apiHash || '',
          phoneNumber: credentials.phoneNumber || '',
        },
      }));
      console.log("Telegram settings fetched:", response.data.status);
    } catch (error) {
      console.error("Error fetching Telegram settings:", error);
      throw error;
    } finally {
      set({ isLoading: false });
    }
  },
  // Update Telegram settings
  updateTelegramSettings: async (newSettings) => {
    set({ isLoading: true });
    try {
      const response = await axios.post("/api/telegram/auth_settings", newSettings);
      set((state) => ({
        settings: {
          ...state.settings,
          apiId: newSettings.apiId ? Number(newSettings.apiId) : 0,
          apiHash: newSettings.apiHash || '',
          phoneNumber: newSettings.phoneNumber || '',
        },
      }));
      console.log("Telegram settings updated:", response.data.status);
    } catch (error) {
      console.error("Error updating Telegram settings:", error);
      throw error;
    } finally {
      set({ isLoading: false });
    }
  },
}));