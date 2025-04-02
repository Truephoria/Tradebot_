// frontend/src/stores/settings-store.ts
import { create } from 'zustand';
import axios from '@/utils/axios'; // Import your configured axios instance
import { SettingsStateType, SettingsAction } from '@/types/settings';

export type SettingStoreType = SettingsStateType & SettingsAction;

interface Settings {
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
  },
  isLoading: false,
  error: null,
};

interface SettingState {
  settings: Record<string, any>;
  isLoading: boolean;
  getSettings: () => Promise<void>;
  updateSettings: (newSettings: Record<string, any>) => Promise<void>;
}

export const useSettingStore = create<SettingState>((set) => ({
  settings: {},
  isLoading: false,
  getSettings: async () => {
    set({ isLoading: true });
    try {
      const response = await axios.get("/api/settings");
      set({ settings: response.data.settings });
      console.log("Settings fetched:", response.data.status);
    } catch (error) {
      console.error("Error fetching settings:", error);
      throw error;
    } finally {
      set({ isLoading: false });
    }
  },
  updateSettings: async (newSettings) => {
    set({ isLoading: true });
    try {
      const response = await axios.post("/api/settings", newSettings);
      set({ settings: response.data.settings || newSettings });
      console.log("Settings updated:", response.data.status);
    } catch (error) {
      console.error("Error updating settings:", error);
      throw error;
    } finally {
      set({ isLoading: false });
    }
  },
}));