export interface Trade {
  id: string;
  signalId: string;
  symbol: string;
  action: "BUY" | "SELL";
  entryPrice: number;
  stopLoss: number;
  takeProfits: number[];
  lotSize: number;
  status: "OPEN" | "CLOSED" | "PARTIAL";
  pnl: number;
  openTime: Date;
  closeTime?: Date;
}

export interface RiskSettings {
  riskType: "FIXED" | "PERCENTAGE";
  riskValue: number;
  maxDailyLoss: number;
  maxDrawdown: number;
  minimumRRR: number;
  enableTrailingStop: boolean;
  tradingHoursStart: string;
  tradingHoursEnd: string;
  maxTradesPerDay: number;
  allowedSymbols: string; // Changed from string[] to string to fix type errors
  botStatus?: "ACTIVE" | "INACTIVE" | "ERROR"; // Made optional
}

export interface AccountStatus {
  balance: number;
  equity: number;
  openPositions: number;
  dailyPnL: number;
  totalTrades: number;
  winRate: number;
  botStatus: "ACTIVE" | "INACTIVE" | "ERROR";
  lastUpdated: Date;
}
