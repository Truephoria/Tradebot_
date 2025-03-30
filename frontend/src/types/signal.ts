export type SignalStateType = {
  symbol: string;
  entry_price: number;
  action: string;
  take_profits: number[];
  stop_loss: number;
};

export type SignalStateAction = {
  setSignalState: (signal: SignalStateType) => void;
};
