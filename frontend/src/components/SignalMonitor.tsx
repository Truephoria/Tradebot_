"use client"; // Ensure this is a client component

import React, { useEffect, useState } from "react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Checkbox } from "./ui/checkbox";
import { Label } from "./ui/label";
import { useSignalStore } from "@/stores/signal-store";
import { useChannelStore } from "@/stores/channel-store";
import { useSettingStore } from "@/stores/settings-store";
import { useMetadataStore } from "@/stores/metadata-store"
import { useAuthStore } from "@/stores/auth-store";
import axios from "@/utils/axios";
import { initializeSocket, getSocket } from "@/utils/socket";
import { Socket } from "socket.io-client";
import { AxiosError } from "axios";
import { debounce } from "lodash"; // Add lodash for debouncing

interface SignalMonitorProps {
  className?: string;
}

const SignalMonitor: React.FC<SignalMonitorProps> = ({ className }) => {
  const signalState = useSignalStore();
  const channelState = useChannelStore();
  const settingState = useSettingStore();
  const metadataState = useMetadataStore();
  const { token } = useAuthStore();
  const [error, setError] = useState<string | null>(null);
  const [isMounted, setIsMounted] = useState(false); // Track client-side mount
  const { settings } = useSettingStore();
 



  // Initialize Socket.IO and fetch settings only once on client mount
  useEffect(() => {
    setIsMounted(true); // Mark as mounted on client

    initializeSocket();
    const socket = getSocket();

    if (socket) {
      socket.on("connect", () => {
        console.log("Socket.IO connected");
      });

      socket.on("new_signal", (signal) => {
        console.log("New signal received:", signal);
        signalState.setSignal(signal); // Update signal state
      });

      socket.on("connect_error", (err) => {
        console.error("Socket.IO connection error:", err.message);
      });
    }

    // Fetch settings only once on mount
    settingState.getSettings().catch((err) => {
      console.error("Failed to fetch settings in useEffect:", err);
    });

    // Cleanup
    return () => {
      if (socket) {
        socket.off("connect");
        socket.off("new_signal");
        socket.off("connect_error");
      }
    };

    

  }, []); // Empty dependency array to run only on mount/unmount

  const handleSubscribe = async () => {
    try {
      await channelState.fetchChannelList();
    } catch (err) {
      console.error("Failed to fetch channel list:", err);
      setError("Failed to fetch channels");
    }
  };

  const startMonitoring = async (channelId: string[]) => {
    console.log("Starting monitoring for channel:", channelId);
    try {
      if (!token) {
        throw new Error("No authentication token available. Please log in.");
      }
      const response = await axios.post("/api/monitor", { channel_id: channelId });
      console.log("Monitoring started:", response.data);
      setError(null);
    } catch (error) {
      const axiosError = error as AxiosError<{ message?: string }>;
      const errorMessage =
        axiosError.response?.data?.message || axiosError.message || "Failed to start monitoring";
      console.error("Error starting monitoring:", errorMessage);
      setError(errorMessage);
    }
  };

  const isFavorable = () => {
    if (!signalState.action || 
        !Array.isArray(signalState.take_profits) || 
        signalState.take_profits.length === 0 || 
        signalState.entry_price === 0 || 
        signalState.stop_loss === 0) {
      console.log("Signal incomplete, not trading:", signalState);
      return false;
    }
    if (!settingState.settings.allowedSymbols || !settingState.settings.minimumRRR || !settingState.settings.botEnabled) {
      console.log("Settings incomplete or bot disabled:", settingState.settings);
      return false;
    }

    // Calculate RRR based on trade direction
    let reward, risk;
    if (signalState.action === "BUY") {
      reward = Math.abs(signalState.take_profits[0] - signalState.entry_price); // TP > Entry
      risk = Math.abs(signalState.entry_price - signalState.stop_loss);         // Entry > SL
    } else if (signalState.action === "SELL") {
      reward = Math.abs(signalState.entry_price - signalState.take_profits[0]); // Entry > TP
      risk = Math.abs(signalState.stop_loss - signalState.entry_price);         // SL > Entry
    } else {
      console.log("Invalid action, cannot calculate RRR:", signalState.action);
      return false;
    }

    const rrr = reward / risk;
    console.log("RRR calculated:", rrr, "vs minimumRRR:", settingState.settings.minimumRRR);

    const inAllowedSymbols = settingState.settings.allowedSymbols.split(',').includes(signalState.symbol);
    const isFavorableResult = settingState.settings.botEnabled && 
                              rrr >= settingState.settings.minimumRRR && 
                              inAllowedSymbols;

    console.log("Favorable check:", { 
      rrr, 
      minimumRRR: settingState.settings.minimumRRR, 
      inAllowedSymbols, 
      botEnabled: settingState.settings.botEnabled, 
      result: isFavorableResult 
    });
    return isFavorableResult;
};

  const calculateLotSize = (balance: number, riskPercent: number) => {
    if (balance <= 0) {
      console.error("Invalid balance for lot size calculation:", balance);
      return 0.01; // Minimum lot size fallback
    }
    const riskAmount = balance * (riskPercent / 100);
    
    // Calculate stop-loss distance in points
    const slDistance = Math.abs(signalState.entry_price - signalState.stop_loss);
    const pipDivider = signalState.symbol === "XAUUSD" ? 1 : 0.0001; // 1 for XAUUSD, 0.0001 for forex
    const slPips = slDistance / pipDivider;
    
    const pipValue = signalState.symbol === "XAUUSD" ? 10 : 1; // $10 per lot for XAUUSD, $1 for forex (adjust as needed)
    const lotSizeRaw = riskAmount / (slPips * pipValue);
    const lotSize = Math.max(0.01, Math.round(lotSizeRaw * 100) / 100); // Minimum 0.01, 2 decimals
    
    console.log("Calculated lot size:", {
      balance,
      riskPercent,
      riskAmount,
      slDistance,
      pipDivider,
      slPips,
      pipValue,
      lotSizeRaw,
      lotSize
    });
    
    return lotSize;
  };

  const executeTrade = async () => {
    if (!token) {
      console.error("No token available, cannot trade");
      return;
    }
    const tradeData = {
      symbol: signalState.symbol,
      action: signalState.action,
      entry_price: signalState.entry_price,
      stop_loss: signalState.stop_loss,
      take_profits: signalState.take_profits,
      volume: settingState.settings.riskType === 'PERCENTAGE' ?
        calculateLotSize(metadataState.balance, settingState.settings.riskValue) :
        settingState.settings.riskValue,     
    };
    console.log("RISK VALUE", settingState.settings.riskValue)
    try {
      const response = await axios.post('/api/trade', tradeData, {
        headers: { Authorization: `Bearer ${token}` }
      });
      console.log("Trade sent to Flask successfully:", response.data);
    } catch (err) {
      console.error("Failed to send trade to Flask:", err);
    }
  };

  const handleTrade = debounce(() => {
    if (signalState.action && metadataState.balance > 0 && Object.keys(settingState.settings).length > 0) {
      if (isFavorable()) {
        executeTrade();
      }
    }
  }, 500);

  useEffect(() => {
    handleTrade();
  }, [signalState]);

  if (!isMounted) return null;

  return (
    <div className={cn("bg-card rounded-xl p-5 card-shadow border border-border", className)}>
      <div className="flex justify-between items-start mb-1">
        <h3 className="text-sm font-medium text-muted-foreground">Signal Monitor</h3>
      </div>
      <div className="space-y-4">
        <Button onClick={handleSubscribe} className="w-full bg-violet-600 hover:bg-violet-700 text-white" disabled={channelState.isLoading}>
          {channelState.isLoading ? "Fetching..." : "Fetch Subscribed Channel"}
        </Button>
        {error && <p className="text-red-500 text-xs">{error}</p>}
        <div className="space-y-2">
          <label htmlFor="channel-select" className="text-xs font-medium text-violet-200">Trading Channel</label>
          {channelState.channelList.length === 0 ? (
            <div className="text-center p-1">No channels found</div>
          ) : (
            channelState.channelList.map((channel, index) => (
              <div key={index} className="flex items-center space-x-2">
                <Checkbox
                  id={`channel-${channel.channel_id}`}
                  checked={channelState.selectedChannel.includes(channel.channel_id)}
                  onCheckedChange={(checked) => {
                    if (checked) {
                      channelState.addChannel(channel.channel_id);
                      startMonitoring([...channelState.selectedChannel, channel.channel_id]);
                    } else {
                      channelState.removeChannel(channel.channel_id);
                      startMonitoring(channelState.selectedChannel.filter((c) => c !== channel.channel_id));
                    }
                  }}
                />
                <Label htmlFor={`channel-${channel.channel_id}`} className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70">
                  {channel.channel_name}
                </Label>
              </div>
            ))
          )}
        </div>
      </div>
      <div className="mt-3 space-y-4">
        {signalState.action ? ( // Changed from !== "" to truthy check
          <div className="space-y-3 animate-fade-in">
            <div className="bg-slate-800/50 rounded-lg p-3 border border-violet-500/20">
              <div className="grid grid-cols-2 gap-2 mb-2">
                <div>
                  <p className="text-xs font-medium text-violet-200">Symbol</p>
                  <p className="text-sm font-semibold text-white">{signalState.symbol || "N/A"}</p>
                </div>
                <div>
                  <p className="text-xs font-medium text-violet-200">Action</p>
                  <p className={cn("text-sm font-semibold", signalState.action === "BUY" ? "text-green-400" : "text-red-400")}>
                    {signalState.action || "N/A"}
                  </p>
                </div>
              </div>
              <div className="grid grid-cols-2 gap-2 mb-2">
                <div>
                  <p className="text-xs font-medium text-violet-200">Entry</p>
                  <p className="text-sm font-semibold text-white">{signalState.entry_price || "N/A"}</p>
                </div>
                <div>
                  <p className="text-xs font-medium text-violet-200">Stop Loss</p>
                  <p className="text-sm font-semibold text-white">{signalState.stop_loss || "N/A"}</p>
                </div>
              </div>
              <div className="mb-2">
                <p className="text-xs font-medium text-violet-200">Take Profits</p>
                <div className="flex gap-2 mt-1">
                  {Array.isArray(signalState.take_profits) && signalState.take_profits.length > 0 ? (
                    signalState.take_profits.map((tp, index) => (
                      <div key={index} className="bg-slate-700/50 rounded px-2 py-1 text-xs border border-violet-500/20 text-white">
                        TP{index + 1}: {tp}
                      </div>
                    ))
                  ) : (
                    <p className="text-xs text-muted-foreground">No take profits set</p>
                  )}
                </div>
              </div>
              <div className="flex justify-between items-center">
                <div>
                  <p className="text-xs font-medium text-violet-200">Risk/Reward Ratio</p>
                  <p className="text-sm font-semibold text-white">
                    {Array.isArray(signalState.take_profits) && signalState.take_profits.length > 0 && signalState.entry_price && signalState.stop_loss
                      ? Number(
                          (Math.abs(signalState.entry_price - signalState.take_profits[0]) /
                            Math.abs(signalState.entry_price - signalState.stop_loss)).toFixed(2)
                        )
                      : "N/A"}
                  </p>
                </div>
              </div>
            </div>
          </div>
        ) : (
          <div className="flex flex-col mt-4 items-center justify-center py-8 text-center">
            <div className="w-16 h-16 mb-4 rounded-full bg-slate-800/50 flex items-center justify-center border border-violet-500/20">
              <svg viewBox="0 0 24 24" width="24" height="24" stroke="currentColor" strokeWidth="2" fill="none" strokeLinecap="round" strokeLinejoin="round" className="text-violet-300">
                <path d="M22 8.5a8.5 8.5 0 0 1-17 0 8.5 8.5 0 0 1 17 0Z"></path>
                <path d="m17.5 17.5 2.5 2.5"></path>
              </svg>
            </div>
            <h3 className="text-sm font-medium text-white mb-1">Awaiting Signals</h3>
            <p className="text-xs text-violet-200 max-w-xs">Monitoring the channel for new trading signals. They will appear here when detected.</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default SignalMonitor;