import React, { useEffect, useState } from "react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Input } from "@/components/ui/input";
import { toast } from "sonner";
import { useSettingStore } from "@/stores/settings-store";

interface SettingsPanelProps {
  className?: string;
}

const SettingsPanel: React.FC<SettingsPanelProps> = ({ className }) => {
  const settingState = useSettingStore();
  const [autoTrading, setAutoTrading] = useState(
    settingState.settings.botEnabled
  );
  const [isLoading, setIsLoading] = useState(false);
  const [minRRR, setMinRRR] = useState(settingState.settings.minimumRRR);

  useEffect(() => {
    // Load settings from API
    settingState.getSettings();
  }, []);

  const handleToggleAutoTrading = async () => {
    setIsLoading(true);
    try {
      settingState.updateSettings({ botEnabled: !autoTrading });
      setAutoTrading(!autoTrading);
      toast.success(`Auto-trading ${!autoTrading ? "enabled" : "disabled"}`);
    } catch (error) {
      toast.error("Error updating auto trading");
      console.error("Error updating auto trading:", error);
    }
    setIsLoading(false);
  };

  const handleUpdateRRR = async () => {
    setIsLoading(true);
    try {
      settingState.updateSettings({ minimumRRR: minRRR });
      toast.success(`Minimum RRR updated to ${minRRR}`);
    } catch (error) {
      toast.error("Error updating minimum RRR");
      console.error("Error updating minimum RRR:", error);
    }
    setIsLoading(false);
  };

  return (
    <div
      className={cn(
        "bg-card rounded-xl p-5 card-shadow border border-border",
        className
      )}
    >
      <div className="flex justify-between items-start mb-4">
        <h3 className="text-sm font-medium text-muted-foreground">
          Quick Controls
        </h3>
      </div>

      <div className="space-y-5">
        <div className="bg-accent rounded-lg p-4">
          <div className="flex justify-between items-center">
            <div className="space-y-1">
              <h4 className="text-sm font-medium text-foreground">
                Auto-Trading
              </h4>
              <p className="text-xs text-muted-foreground">
                Automatically execute trades based on signals
              </p>
            </div>
            <Switch
              checked={autoTrading}
              onCheckedChange={handleToggleAutoTrading}
              disabled={isLoading}
            />
          </div>
        </div>

        <div className="bg-accent rounded-lg p-4">
          <h4 className="text-sm font-medium text-foreground mb-2">
            Minimum Risk/Reward Ratio
          </h4>
          <p className="text-xs text-muted-foreground mb-3">
            Ignore trades with RRR below this threshold
          </p>

          <div className="flex space-x-2">
            <Input
              type="number"
              value={minRRR}
              onChange={(e) => setMinRRR(parseFloat(e.target.value))}
              min={0.5}
              max={10}
              step={0.1}
              className="text-xs h-8"
            />
            <Button
              onClick={handleUpdateRRR}
              className="h-8 text-xs px-3"
              disabled={isLoading}
            >
              Update
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SettingsPanel;