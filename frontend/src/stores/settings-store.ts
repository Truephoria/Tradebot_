// frontend/src/stores/settings-store.ts
import { create } from 'zustand';
import axios from '@/utils/axios'; // Your pre-configured Axios instance
// If you store your user JWT in localStorage or some global store, import or read it here.

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

interface SettingState {
  settings: Settings;
  isLoading: boolean;
  error: string | null;
  getSettings: () => Promise<void>;
  updateSettings: (newSettings: Partial<Settings>) => Promise<void>;
}

/**
 * By default, we keep a "clean" set of initial settings
 * or an empty object until we fetch from Python.
 */
const defaultSettings: Settings = {
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
};

export const useSettingStore = create<SettingState>((set) => ({
  settings: defaultSettings,
  isLoading: false,
  error: null,

  // Fetch settings from our Next.js route -> Python
  getSettings: async () => {
    set({ isLoading: true, error: null });
    try {
      // If you need a token for the Python route (which is behind @token_required),
      // grab it from localStorage or however your login is done
      const token = localStorage.getItem('token') || '';
      const response = await axios.get('/api/settings', {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });
      set({
        settings: response.data.settings,
        error: null,
      });
      console.log('Settings fetched successfully');
    } catch (err: any) {
      console.error('Error fetching settings:', err?.message || err);
      set({ error: err?.message || 'Failed to fetch settings' });
      throw err;
    } finally {
      set({ isLoading: false });
    }
  },

  // Update settings via Next.js route -> Python
  updateSettings: async (newSettings) => {
    set({ isLoading: true, error: null });
    try {
      const token = localStorage.getItem('token') || '';
      const response = await axios.post('/api/settings', newSettings, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });
      set({
        settings: response.data.settings || newSettings,
        error: null,
      });
      console.log('Settings updated successfully');
    } catch (err: any) {
      console.error('Error updating settings:', err?.message || err);
      set({ error: err?.message || 'Failed to update settings' });
      throw err;
    } finally {
      set({ isLoading: false });
    }
  },
}));