// frontend/src/types/channels.ts
export type ChannelType = {
  channel_id: string;
  channel_name: string;
  is_active: boolean;
};

export type ChannelListType = {
  selectedChannel: string[]; // Array of channel_ids
  channelList: ChannelType[]; // Array of channel objects
  isLoading: boolean;
  error: string | null;
};

export type ChannelListAction = {
  getChannelList: () => Promise<void>;
  fetchChannelList: () => Promise<void>;
  addChannel: (channelId: string) => Promise<void>;
  removeChannel: (channelId: string) => Promise<void>;
};