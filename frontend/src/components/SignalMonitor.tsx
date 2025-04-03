"use client";

import React, { useEffect, useState } from "react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Checkbox } from "./ui/checkbox";
import { Label } from "./ui/label";
import { Input } from "@/components/ui/input";
import { useSignalStore } from "@/stores/signal-store";
import { useChannelStore } from "@/stores/channel-store";
import { useSettingStore } from "@/stores/settings-store";
import { useMetadataStore } from "@/stores/metadata-store";
import useAuth from "@/hooks/useAuth";
import axios from "@/utils/axios";
import { AxiosError } from "axios";
import { debounce } from "lodash";

interface SignalMonitorProps {
  className?: string;
}

const SignalMonitor: React.FC<SignalMonitorProps> = ({ className }) => {
  // -------------------------
  // 1. React state & stores
  // -------------------------
  const signalState = useSignalStore();
  const channelState = useChannelStore();
  const settingState = useSettingStore();
  const metadataState = useMetadataStore();

  // This is your custom hook that presumably stores the user's JWT token
  const { token } = useAuth();

  const [error, setError] = useState<string | null>(null);
  const [isMounted, setIsMounted] = useState(false);

  // For Telegram code verification modal
  const [showCodeModal, setShowCodeModal] = useState(false);
  const [telegramCode, setTelegramCode] = useState("");

  // ----------------------------------
  // 2. On mount, fetch settings
  // ----------------------------------
  useEffect(() => {
    setIsMounted(true);
    settingState.getSettings().catch((err) => {
      console.error("Failed to fetch settings in useEffect:", err);
    });
  }, [settingState]);

  // ----------------------------------
  // 3. handleSubscribe
  // ----------------------------------
  //  We added:
  //   - If no token, throw an error immediately.
  //   - A better catch for 401 from the server.
  const handleSubscribe = async () => {
    // First, ensure we have a token so the server's @token_required passes
    if (!token) {
      setError("No authentication token available. Please log in first.");
      return;
    }

    try {
      // Attempt to fetch channels, passing the token
      const res = await channelState.fetchChannelList(); 
      // ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
      // Make sure your `fetchChannelList(token)` actually uses:
      //   axios.get("/api/channels", { headers: { Authorization: `Bearer ${token}` } })
      // in the channelStore code.

      setError(null);

      
    } catch (err) {
      console.error("Failed to fetch channel list:", err);

      // Convert to AxiosError for status checks
      const axiosErr = err as AxiosError<{ message?: string }>;

      // If the server returned a 401, it likely means Telegram session isn't authorized
      if (axiosErr?.response?.status === 401) {
        setShowCodeModal(true);
        setError("Telegram authentication required. Check your phone for a code.");
      } else {
        // Some other error
        setError("Failed to fetch channels");
      }
    }
  };

  // ----------------------------------
  // 4. handleVerifyCode
  // ----------------------------------
  //  This part is mostly the same, we just confirm we had a token check already.
  const handleVerifyCode = async () => {
    if (!token) {
      setError("No authentication token available.");
      return;
    }
    try {
      // Send the verification code with your token
      const response = await axios.post(
        "/api/telegram/verify_code",
        { code: telegramCode },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      if (response.data.status === "success") {
        setShowCodeModal(false);
        setTelegramCode("");
        setError(null);
        // Retry fetching channels after successful verification
        handleSubscribe();
      } else {
        setError(response.data.message || "Failed to verify code.");
      }
    } catch (err) {
      const axiosError = err as AxiosError<{ message?: string }>;
      setError(axiosError.response?.data?.message || "Error verifying code.");
    }
  };

  // ----------------------------------
  // 5. startMonitoring
  // ----------------------------------
  //  This calls /api/monitor. 
  //  That route doesn’t have @token_required in your code, so no headers needed.
  const startMonitoring = async (channelId: string[]) => {
    console.log("Starting monitoring for channel:", channelId);
    try {
      if (!token) {
        throw new Error("No authentication token available. Please log in.");
      }
      // /api/monitor did NOT have @token_required, so no headers needed
      const response = await axios.post("/api/monitor", { channel_id: channelId });
      console.log("Monitoring started:", response.data);
      setError(null);
    } catch (error) {
      const axiosError = error as AxiosError<{ message?: string }>;
      const errorMessage =
        axiosError.response?.data?.message ||
        axiosError.message ||
        "Failed to start monitoring";
      console.error("Error starting monitoring:", errorMessage);
      setError(errorMessage);
    }
  };

  // ----------------------------------
  // 6. isFavorable: no changes
  // ----------------------------------
  const isFavorable = () => {
    if (
      !signalState.action ||
      !Array.isArray(signalState.take_profits) ||
      signalState.take_profits.length === 0 ||
      signalState.entry_price === 0 ||
      signalState.stop_loss === 0
    ) {
      console.log("Signal incomplete, not trading:", signalState);
      return false;
    }
    if (
      !settingState.settings.allowedSymbols ||
      !settingState.settings.minimumRRR ||
      !settingState.settings.botEnabled
    ) {
      console.log("Settings incomplete or bot disabled:", settingState.settings);
      return false;
    }

    let reward, risk;
    if (signalState.action === "BUY") {
      reward = Math.abs(signalState.take_profits[0] - signalState.entry_price);
      risk = Math.abs(signalState.entry_price - signalState.stop_loss);
    } else if (signalState.action === "SELL") {
      reward = Math.abs(signalState.entry_price - signalState.take_profits[0]);
      risk = Math.abs(signalState.stop_loss - signalState.entry_price);
    } else {
      console.log("Invalid action, cannot calculate RRR:", signalState.action);
      return false;
    }

    const rrr = reward / risk;
    console.log("RRR calculated:", rrr, "vs minimumRRR:", settingState.settings.minimumRRR);

    const inAllowedSymbols = settingState.settings.allowedSymbols
      .split(",")
      .includes(signalState.symbol);
    const isFavorableResult =
      settingState.settings.botEnabled && rrr >= settingState.settings.minimumRRR && inAllowedSymbols;

    console.log("Favorable check:", {
      rrr,
      minimumRRR: settingState.settings.minimumRRR,
      inAllowedSymbols,
      botEnabled: settingState.settings.botEnabled,
      result: isFavorableResult,
    });
    return isFavorableResult;
  };

  // ----------------------------------
  // 7. calculateLotSize: no changes
  // ----------------------------------
  const calculateLotSize = (balance: number, riskPercent: number) => {
    if (balance <= 0) {
      console.error("Invalid balance for lot size calculation:", balance);
      return 0.01;
    }
    const riskAmount = balance * (riskPercent / 100);

    const slDistance = Math.abs(signalState.entry_price - signalState.stop_loss);
    const pipDivider = signalState.symbol === "XAUUSD" ? 1 : 0.0001;
    const slPips = slDistance / pipDivider;

    const pipValue = signalState.symbol === "XAUUSD" ? 10 : 1;
    const lotSizeRaw = riskAmount / (slPips * pipValue);
    const lotSize = Math.max(0.01, Math.round(lotSizeRaw * 100) / 100);

    console.log("Calculated lot size:", {
      balance,
      riskPercent,
      riskAmount,
      slDistance,
      pipDivider,
      slPips,
      pipValue,
      lotSizeRaw,
      lotSize,
    });

    return lotSize;
  };

  // ----------------------------------
  // 8. executeTrade: no changes except token check
  // ----------------------------------
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
      volume:
        settingState.settings.riskType === "PERCENTAGE"
          ? calculateLotSize(metadataState.balance, settingState.settings.riskValue)
          : settingState.settings.riskValue,
    };
    console.log("RISK VALUE", settingState.settings.riskValue);
    try {
      const response = await axios.post("/api/trade", tradeData, {
        headers: { Authorization: `Bearer ${token}` },
      });
      console.log("Trade sent to Flask successfully:", response.data);
    } catch (err) {
      console.error("Failed to send trade to Flask:", err);
    }
  };

  // ----------------------------------
  // 9. handleTrade: no changes
  // ----------------------------------
  const handleTrade = debounce(() => {
    if (
      signalState.action &&
      metadataState.balance > 0 &&
      Object.keys(settingState.settings).length > 0
    ) {
      if (isFavorable()) {
        executeTrade();
      }
    }
  }, 500);

  // ----------------------------------
  // 10. watch for new signals
  // ----------------------------------
  useEffect(() => {
    handleTrade();
  }, [signalState]);

  if (!isMounted) return null;

  // ----------------------------------
  // 11. JSX Return
  // ----------------------------------
  return (
    <div className={cn("bg-card rounded-xl p-5 card-shadow border border-border", className)}>
      {/* Title */}
      <div className="flex justify-between items-start mb-1">
        <h3 className="text-sm font-medium text-muted-foreground">Signal Monitor</h3>
      </div>

      {/* Subscribe & Channels */}
      <div className="space-y-4">
        <Button
          onClick={handleSubscribe}
          className="w-full bg-violet-600 hover:bg-violet-700 text-white"
          disabled={channelState.isLoading}
        >
          {channelState.isLoading ? "Fetching..." : "Fetch Subscribed Channel"}
        </Button>
        {error && <p className="text-red-500 text-xs">{error}</p>}
        <div className="space-y-2">
          <label htmlFor="channel-select" className="text-xs font-medium text-violet-200">
            Trading Channel
          </label>
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
                      startMonitoring(
                        channelState.selectedChannel.filter((c) => c !== channel.channel_id)
                      );
                    }
                  }}
                />
                <Label
                  htmlFor={`channel-${channel.channel_id}`}
                  className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70"
                >
                  {channel.channel_name}
                </Label>
              </div>
            ))
          )}
        </div>
      </div>

      {/* Signal Info */}
      <div className="mt-3 space-y-4">
        {signalState.action ? (
          <div className="space-y-3 animate-fade-in">
            <div className="bg-slate-800/50 rounded-lg p-3 border border-violet-500/20">
              <div className="grid grid-cols-2 gap-2 mb-2">
                <div>
                  <p className="text-xs font-medium text-violet-200">Symbol</p>
                  <p className="text-sm font-semibold text-white">{signalState.symbol || "N/A"}</p>
                </div>
                <div>
                  <p className="text-xs font-medium text-violet-200">Action</p>
                  <p
                    className={cn(
                      "text-sm font-semibold",
                      signalState.action === "BUY" ? "text-green-400" : "text-red-400"
                    )}
                  >
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
                      <div
                        key={index}
                        className="bg-slate-700/50 rounded px-2 py-1 text-xs border border-violet-500/20 text-white"
                      >
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
                    {Array.isArray(signalState.take_profits) &&
                    signalState.take_profits.length > 0 &&
                    signalState.entry_price &&
                    signalState.stop_loss
                      ? Number(
                          (
                            Math.abs(signalState.entry_price - signalState.take_profits[0]) /
                            Math.abs(signalState.entry_price - signalState.stop_loss)
                          ).toFixed(2)
                        )
                      : "N/A"}
                  </p>
                </div>
              </div>
            </div>
          </div>
        ) : (
          <div className="flex flex-col mt-4 items-center justify-center py-8 text-center">
            <h3 className="w-16 h-16 mb-4 rounded">Awaiting Signals</h3>
            <p className="text-xs text-violet-200 max-w-xs">
              Monitoring the channel for new trading signals. They will appear here when detected.
            </p>
          </div>
        )}
      </div>

      {/* Telegram Verification Modal */}
      {showCodeModal && (
        <div className="fixed inset-0 flex items-center justify-center bg-black bg-opacity-50 z-50">
          <div className="bg-card p-5 rounded-xl border border-border max-w-sm w-full">
            <h3 className="text-lg font-medium text-white mb-2">Telegram Verification</h3>
            <p className="text-sm text-muted-foreground mb-4">
              A code has been sent to your Telegram phone number. Enter it below:
            </p>
            {error && showCodeModal && <p className="text-red-500 text-xs mb-2">{error}</p>}
            <Input
              value={telegramCode}
              onChange={(e) => setTelegramCode(e.target.value)}
              placeholder="e.g., 12345"
              className="mb-4"
            />
            <div className="flex justify-end space-x-2">
              <Button
                onClick={() => setShowCodeModal(false)}
                variant="outline"
                className="text-white"
              >
                Cancel
              </Button>
              <Button
                onClick={handleVerifyCode}
                disabled={!telegramCode}
                className="bg-violet-600 hover:bg-violet-700 text-white"
              >
                Submit
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default SignalMonitor;
