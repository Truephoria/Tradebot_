// frontend/src/components/Dashboard.tsx
"use client"; // Required for client-side hooks in Next.js App Router
import React, { useEffect, useRef } from "react";
import { cn } from "@/lib/utils";
import { AccountStatus } from "@/utils/types"; // Ensure this exists
import { initializeSocket, getSocket } from "@/utils/socket";
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
import { useSettingStore } from "@/stores/settings-store";
import { Socket } from "socket.io-client"; // Import Socket type

interface DashboardProps {
  className?: string;
}

const Dashboard: React.FC<DashboardProps> = ({ className }) => {
  const metadataState = useMetadataStore();
  const signalState = useSignalStore();
  // Type the ref to allow Socket | null
  const socket = useRef<Socket | null>(null);

  // Listen for new signals from WebSocket
  useEffect(() => {
    // Initialize socket connection
    initializeSocket();
    socket.current = getSocket();

    if (!socket.current) {
      console.error("Socket is not initialized.");
      return;
    }

    // Type assertion or non-null check ensures socket.current is Socket here
    const currentSocket = socket.current;

    currentSocket.on("new_signal", (signal: SignalStateType) => {
      signalState.setSignal(signal); // Fixed: Changed setSignalState to setSignal
    });

    currentSocket.on("new_metadata", (data: MetaDataType) => {
      console.log("Received metadata:", data);
      metadataState.setMetaData(data);
    });

    // Cleanup function
    return () => {
      currentSocket.off("new_signal");
      currentSocket.off("new_metadata");
    };
  }, [signalState, metadataState]); // Dependencies for stores

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