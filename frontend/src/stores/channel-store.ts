// frontend/src/stores/channel-store.ts
import { create } from 'zustand';
import { ChannelListType, ChannelListAction } from '@/types/channels';
import { useAuthStore } from '@/stores/auth-store';
import { io } from 'socket.io-client';

export type ChannelStoreType = ChannelListType & ChannelListAction;

export const initChannelListState: ChannelListType = {
  selectedChannel: [],
  channelList: [],
  isLoading: false,
  error: null,
};

// Initialize SocketIO client
const socket = io('https://pkbk36mqmi.us-east-2.awsapprunner.com', { // Update to your ngrok URL later
  reconnection: true,
  transports: ['websocket'],
});

export const useChannelStore = create<ChannelStoreType>((set) => ({
  ...initChannelListState,
  getChannelList: async () => {
    set({ isLoading: true });
    try {
      const token = useAuthStore.getState().token;
      if (!token) throw new Error("No authentication token available");
      const response = await fetch('https://pkbk36mqmi.us-east-2.awsapprunner.com/api/channels/all', { // Update to ngrok URL later
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(`HTTP error! status: ${response.status}, message: ${errorData.message || 'Unknown error'}`);
      }
      const data = await response.json();
      set({
        selectedChannel: data.active_channels,
        channelList: data.channels,
        isLoading: false,
        error: null,
      });
      console.log('Channel count:', data.count);
    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
      set({ isLoading: false, error: errorMessage });
      console.error('Error fetching channel list:', error);
    }
  },
  fetchChannelList: async () => {
    set({ isLoading: true, error: null });
    try {
      const token = useAuthStore.getState().token;
      if (!token) throw new Error("No authentication token available");
      const response = await fetch('https://pkbk36mqmi.us-east-2.awsapprunner.com/api/channels', { // Update to ngrok URL later
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(`HTTP error! status: ${response.status}, message: ${errorData.message || 'Unknown error'}`);
      }
      const data = await response.json();
      const allChannelsResponse = await fetch('https://pkbk36mqmi.us-east-2.awsapprunner.com/api/channels/all', {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });
      if (!allChannelsResponse.ok) {
        const errorData = await allChannelsResponse.json();
        throw new Error(`HTTP error! status: ${allChannelsResponse.status}, message: ${errorData.message || 'Unknown error'}`);
      }
      const allChannelsData = await allChannelsResponse.json();
      set({
        selectedChannel: allChannelsData.active_channels || [],
        channelList: allChannelsData.channels,
        isLoading: false,
        error: null,
      });
      console.log('Channels fetched from Telegram and synced:', allChannelsData.channels);
    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
      set({ isLoading: false, error: errorMessage });
      console.error('Error fetching channels:', error);
      throw error;
    }
  },
  addChannel: async (channelId: string) => {
    set((state) => ({
      selectedChannel: state.selectedChannel.includes(channelId)
        ? state.selectedChannel
        : [...state.selectedChannel, channelId],
    }));
    try {
      const token = useAuthStore.getState().token;
      if (!token) throw new Error("No authentication token available");
      const response = await fetch(`https://pkbk36mqmi.us-east-2.awsapprunner.com/api/channels/${channelId}/status`, { // Update to ngrok URL
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({ is_active: true }),
      });
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(`HTTP error! status: ${response.status}, message: ${errorData.message || 'Unknown error'}`);
      }
      const data = await response.json();
      console.log('Channel added:', data.message, data.is_active);
    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
      console.error('Error adding channel:', errorMessage);
    }
  },
  removeChannel: async (channelId: string) => {
    set((state) => ({
      selectedChannel: state.selectedChannel.filter((c) => c !== channelId),
    }));
    try {
      const token = useAuthStore.getState().token;
      if (!token) throw new Error("No authentication token available");
      const response = await fetch(`https://pkbk36mqmi.us-east-2.awsapprunner.com/${channelId}/status`, { // Update to ngrok URL
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({ is_active: false }),
      });
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(`HTTP error! status: ${response.status}, message: ${errorData.message || 'Unknown error'}`);
      }
      const data = await response.json();
      console.log('Channel removed:', data.message, data.is_active);
    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
      console.error('Error removing channel:', errorMessage);
    }
  },
}));

// Listen for new signals from SocketIO
socket.on('connect', () => {
  console.log('Connected to SocketIO server');
});

socket.on('new_signal', (data) => {
  console.log('New Telegram message received:', {
    channel_id: data.channel_id,
    raw_message: data.message,
    parsed_signal: data.parsed_signal,
    error: data.error || null,
  });
});

socket.on('disconnect', () => {
  console.log('Disconnected from SocketIO server');
});