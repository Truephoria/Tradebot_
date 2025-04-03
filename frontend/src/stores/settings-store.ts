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
    //apiId: '', // Now a string
    //apiHash: '', // Now a string
    //phoneNumber: '', // Now a string
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
  //getTelegramSettings: () => Promise<void>;
 // updateTelegramSettings: (newSettings: Partial<Pick<SettingsStateType['settings'], 'apiId' | 'apiHash' | 'phoneNumber'>>) => Promise<void>;
}

export const useSettingStore = create<SettingState>((set) => ({
  settings: initSettingState.settings,
  isLoading: false,
  error: null,
  // Fetch risk/trading settings
  getSettings: async () => {
    set({ isLoading: true });
const token = localStorage.getItem('token');
    if (!token) {
      console.warn("No token, skipping settings request");
      return;
    }

try {
  const payload = JSON.parse(atob(token.split('.')[1]));
  if (payload.exp < Math.floor(Date.now() / 1000)) {
    console.warn("Token expired, skipping settings request");
    return;
  }
} catch (err) {
  console.error("Token check failed", err);
  return;
}
      const response = await axios.get("/api/settings");
      set((state) => ({
        settings: { ...state.settings, ...response.data.settings },
        error: null,
      }));
      console.log("Settings fetched:", response.data.status);
   
      set({ isLoading: false });
    
  },
  // Update risk/trading settings
  updateSettings: async (newSettings) => {
    set({ isLoading: true });
    const token = localStorage.getItem('token');
    if (!token) {
      console.warn("No token, skipping settings request");
      return;
    }

try {
  const payload = JSON.parse(atob(token.split('.')[1]));
  if (payload.exp < Math.floor(Date.now() / 1000)) {
    console.warn("Token expired, skipping settings request");
    return;
  }
} catch (err) {
  console.error("Token check failed", err);
  return;
}
      const response = await axios.post("/api/settings", newSettings);
      set((state) => ({
        settings: { ...state.settings, ...response.data.settings },
        error: null,
      }));
      console.log("Settings updated:", response.data.status);
    
      set({ isLoading: false });
    
  },
 

 /*
  // Fetch Telegram settings
  getTelegramSettings: async () => {
    set({ isLoading: true });
    try {
      const response = await axios.get("/api/telegram/auth_settings");
      const credentials = response.data.credentials || {};
      set((state) => ({
        settings: {
          ...state.settings,
          apiId: credentials.apiId || '',
          apiHash: credentials.apiHash || '',
          phoneNumber: credentials.phoneNumber || '',
        },
        error: null,
      }));
      console.log("Telegram settings fetched:", response.data.status);
    } catch (error) {
      console.error("Error fetching Telegram settings:", error);
      set({ error: "Failed to fetch Telegram settings" });
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
          apiId: newSettings.apiId !== undefined ? newSettings.apiId : state.settings.apiId,
          apiHash: newSettings.apiHash !== undefined ? newSettings.apiHash : state.settings.apiHash,
          phoneNumber: newSettings.phoneNumber !== undefined ? newSettings.phoneNumber : state.settings.phoneNumber,
        },
        error: null,
      }));
      console.log("Telegram settings updated:", response.data.status);
    } catch (error) {
      console.error("Error updating Telegram settings:", error);
      set({ error: "Failed to update Telegram settings" });
      throw error;
    } finally {
      set({ isLoading: false });
    }
  }, 
  */
}));