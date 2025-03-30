// frontend/src/types/metadata.ts
export interface TradeType {
  symbol: string;
  type: string; // Historical trade type
  entryPrice: string;
  lotSize: string;
  profit: string;
  time: string;
}

export interface OpenTradeType {
  symbol: string;
  volume: string;
  priceOpen: string;
  sl: string;
  tp: string;
  type: string; // Active trade type (e.g., "BUY" or "SELL")
  time: string;
}

export interface MetaDataType {
  balance: number;
  pnl: number;
  tradeshistory: TradeType[];
  winRate: number;
  totalTrades: number;
  activeTrades: OpenTradeType[] | null;
}

export interface MetaDataAction {
  setMetaData: (metadata: MetaDataType) => void;
}