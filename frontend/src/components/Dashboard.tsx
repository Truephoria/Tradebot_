'use client';

import React, { useEffect } from "react";
import { cn } from "@/lib/utils";
import axios from "@/utils/axios";
import StatusCard from "./StatusCard";
import SignalMonitor from "./SignalMonitor";
import RiskManager from "./RiskManager";
import OpenTrades from "./OpenTrades";
import SettingsPanel from "./SettingsPanel";
import TradeHistory from "./TradeHistory";
import { SignalStateType } from "@/types/signal";
import { MetaDataType } from "@/types/metadata";
import { useSignalStore } from "@/stores/signal-store";
import { useMetadataStore } from "@/stores/metadata-store";
import useAuth from "@/hooks/useAuth";

interface DashboardProps {
  className?: string;
}

const Dashboard: React.FC<DashboardProps> = ({ className }) => {
  const metadataState = useMetadataStore();
  const signalState = useSignalStore();
  const { token } = useAuth();

  useEffect(() => {
    if (!token) return;

    const fetchUpdates = async () => {
      try {
        const signalResponse = await axios.get('/api/signal', {
          headers: { Authorization: `Bearer ${token}` }
        });
        const latestSignal: SignalStateType = signalResponse.data.signal;
        if (latestSignal) {
          signalState.setSignal(latestSignal);
        }

        const tradeResponse = await axios.get('/api/trade/history', {
          headers: { Authorization: `Bearer ${token}` }
        });
        const tradeData: MetaDataType = tradeResponse.data;
        if (tradeData) {
          metadataState.setMetaData({
            balance: tradeData.balance ?? metadataState.balance,
            pnl: tradeData.pnl ?? metadataState.pnl,
            activeTrades: tradeData.activeTrades ?? metadataState.activeTrades,
            tradeshistory: tradeData.tradeshistory ?? metadataState.tradeshistory,
            totalTrades: tradeData.totalTrades ?? metadataState.totalTrades,
            winRate: tradeData.winRate ?? metadataState.winRate,
          });
        }
      } catch (err) {
        console.error("Error fetching updates:", err);
      }
    };

    fetchUpdates();
    const interval = setInterval(fetchUpdates, 10000);
    return () => clearInterval(interval);
  }, [token, signalState, metadataState]);

  return (
    <div className={cn("w-full py-8", className)}>
      <div className="container px-4 mx-auto max-w-7xl space-y-5">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
          <div className="space-y-2">
            <StatusCard />
            <SettingsPanel />
            <RiskManager />
          </div>
          <SignalMonitor />
          <OpenTrades />
        </div>
        <TradeHistory />
      </div>
    </div>
  );
};

export default Dashboard;