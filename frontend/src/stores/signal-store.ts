import { create } from 'zustand';

interface SignalState {
  symbol: string;
  entry_price: number;
  action: string;
  stop_loss: number;
  take_profits: number[];
  setSignal: (signal: { symbol: string; entry_price: number; action: string; stop_loss: number; take_profits: number[] }) => void;
}

export const useSignalStore = create<SignalState>((set) => ({
  symbol: '',
  entry_price: 0,
  action: '',
  stop_loss: 0,
  take_profits: [],
  setSignal: (signal) => set((state) => {
    const newSignal = {
      symbol: signal.symbol !== undefined ? signal.symbol : state.symbol,
      entry_price: signal.entry_price !== undefined ? signal.entry_price : state.entry_price,
      action: signal.action !== undefined ? signal.action : state.action,
      stop_loss: signal.stop_loss !== undefined ? signal.stop_loss : state.stop_loss,
      take_profits: signal.take_profits !== undefined 
        ? (Array.isArray(signal.take_profits) ? signal.take_profits : state.take_profits)
        : state.take_profits,
    };
    console.log("Setting signal state:", JSON.stringify(newSignal, null, 2));
    return newSignal;
  }),
}));