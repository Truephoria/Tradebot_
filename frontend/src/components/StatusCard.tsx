import React from "react";
import { cn } from "@/lib/utils";
import { useMetadataStore } from "@/stores/metadata-store";

interface StatusCardProps {
  className?: string;
}

const StatusCard: React.FC<StatusCardProps> = ({ className }) => {
  const metadataState = useMetadataStore();
  const formattedBalance = new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
  }).format(metadataState.balance);

  const formattedPnL = new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    signDisplay: "always",
  }).format(metadataState.pnl);

  return (
    <div
      className={cn(
        "bg-card rounded-xl p-5 card-shadow border border-border",
        className
      )}
    >
      <div className="flex justify-between items-start mb-4">
        <h3 className="text-sm font-medium text-muted-foreground">
          Account Status
        </h3>
      </div>

      <div className="grid grid-cols-2 gap-4 mb-4">
        <div>
          <p className="text-xs font-medium text-muted-foreground mb-1">
            Balance
          </p>
          <p className="text-2xl font-semibold text-foreground">
            {formattedBalance}
          </p>
        </div>
        <div>
          <p className="text-xs font-medium text-muted-foreground mb-1">
            Daily P&L
          </p>
          <p
            className={cn(
              "text-2xl font-semibold",
              metadataState.pnl >= 0
                ? "text-green-600 dark:text-green-400"
                : "text-red-600 dark:text-red-400"
            )}
          >
            {formattedPnL}
          </p>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-2">
        <div className="bg-accent rounded-lg p-2 text-center">
          <p className="text-xl font-semibold text-foreground">{0}</p>
          <p className="text-xs text-muted-foreground">Open</p>
        </div>
        <div className="bg-accent rounded-lg p-2 text-center">
          <p className="text-xl font-semibold text-foreground">
            {metadataState.totalTrades}
          </p>
          <p className="text-xs text-muted-foreground">Trades</p>
        </div>
        <div className="bg-accent rounded-lg p-2 text-center">
          <p className="text-xl font-semibold text-foreground">
            {parseFloat(metadataState.winRate.toFixed(2))}%
          </p>
          <p className="text-xs text-muted-foreground">Win Rate</p>
        </div>
      </div>
    </div>
  );
};

export default StatusCard;
