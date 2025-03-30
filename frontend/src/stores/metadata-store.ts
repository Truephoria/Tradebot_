// frontend/src/stores/metadata-store.ts
import { create } from 'zustand';
import { MetaDataType, MetaDataAction } from '@/types/metadata';

export type MetadataStoreType = MetaDataType & MetaDataAction;

export const initMetadataState: MetaDataType = {
  balance: 0,
  pnl: 0,
  tradeshistory: [], // Fixed typo from tradeshistory
  winRate: 0,
  totalTrades: 0,
  activeTrades: null, // Changed to null to match MetaDataType
};

export const useMetadataStore = create<MetadataStoreType>((set) => ({
  ...initMetadataState,
  setMetaData: (metadata: MetaDataType) => set(metadata),
}));