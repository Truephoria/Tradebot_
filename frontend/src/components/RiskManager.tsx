import React, { useEffect, useState } from "react";
import { cn } from "@/lib/utils";
import { RiskSettings } from "@/utils/types";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Slider } from "@/components/ui/slider";
import { toast } from "sonner";
import { useSettingStore } from "@/stores/settings-store";
import { SettingsType } from "@/types/settings";

interface RiskManagerProps {
  className?: string;
}

const RiskManager: React.FC<RiskManagerProps> = ({ className }) => {
  
  const settingState = useSettingStore();
  const [settings, setSettings] = useState<SettingsType>(settingState.settings);
  const [isEditing, setIsEditing] = useState(false);
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    // Load settings from API
    settingState.getSettings();
  }, []);

  const handleChange = (field: keyof RiskSettings, value: any) => {
    setSettings((prev) => ({
      ...prev,
      [field]: value,
    }));
  };

  const handleSave = () => {
    setIsLoading(true);
    try {
      settingState.updateSettings(settings);
      toast.success("Risk settings saved successfully");
    } catch (error) {
      toast.error("Error updating Risk settings");
      console.error("Error updating Risk settings:", error);
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
          Risk Management
        </h3>
        <button
          onClick={() => setIsEditing(!isEditing)}
          className="text-xs font-medium text-primary hover:text-primary/80 transition-colors"
        >
          {isEditing ? "Cancel" : "Edit"}
        </button>
      </div>

      <div className="space-y-4">
        <div className="space-y-4">
          <div>
            <div className="flex justify-between items-center mb-1">
              <label className="text-xs font-medium text-muted-foreground">
                Risk Type
              </label>
              <span className="flex items-center">
                <span className="text-xs text-muted-foreground mr-2">
                  Fixed
                </span>
                <Switch
                  checked={settings.riskType === "PERCENTAGE"}
                  onCheckedChange={(checked) =>
                    handleChange("riskType", checked ? "PERCENTAGE" : "FIXED")
                  }
                  disabled={!isEditing}
                />
                <span className="text-xs text-muted-foreground ml-2">
                  Percentage
                </span>
              </span>
            </div>
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs text-muted-foreground">
                  {settings.riskType === "PERCENTAGE"
                    ? "Risk per Trade (%)"
                    : "Fixed Lot Size"}
                </span>
                <span className="text-xs font-medium">
                  {settings.riskType === "PERCENTAGE"
                    ? settings.riskValue + "%"
                    : settings.riskValue}
                </span>
              </div>
              <Slider
                value={[settings.riskValue]}
                min={settings.riskType === "PERCENTAGE" ? 0.1 : 0.01}
                max={settings.riskType === "PERCENTAGE" ? 5 : 10}
                step={settings.riskType === "PERCENTAGE" ? 0.1 : 0.01}
                onValueChange={(value) => handleChange("riskValue", value[0])}
                disabled={!isEditing}
              />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs font-medium text-muted-foreground mb-1 block">
                Max Daily Loss (%)
              </label>
              <Input
                type="number"
                value={settings.maxDailyLoss}
                onChange={(e) =>
                  handleChange("maxDailyLoss", parseFloat(e.target.value))
                }
                min={1}
                max={100}
                step={1}
                disabled={!isEditing}
                className="text-xs h-8 bg-background text-foreground"
              />
            </div>
            <div>
              <label className="text-xs font-medium text-muted-foreground mb-1 block">
                Min Risk/Reward
              </label>
              <Input
                type="number"
                value={settings.minimumRRR}
                onChange={(e) =>
                  handleChange("minimumRRR", parseFloat(e.target.value))
                }
                min={0.5}
                max={10}
                step={0.1}
                disabled={!isEditing}
                className="text-xs h-8 bg-background text-foreground"
              />
            </div>
          </div>

          <div className="flex items-center space-x-2">
            <Switch
              id="trailing-stop"
              checked={settings.enableTrailingStop}
              onCheckedChange={(checked) =>
                handleChange("enableTrailingStop", checked)
              }
              disabled={!isEditing}
            />
            <Label htmlFor="trailing-stop" className="text-xs text-foreground">
              Enable Trailing Stop Loss
            </Label>
          </div>

          {isEditing && (
            <Button
              onClick={handleSave}
              className="w-full"
              disabled={isLoading}
            >
              {isLoading ? "Saving..." : "Save Settings"}
            </Button>
          )}
        </div>

        {!isEditing && (
          <div className="border-t border-border pt-3 mt-3">
            <h4 className="text-xs font-medium text-muted-foreground mb-2">
              Allowed Symbols
            </h4>
            <div className="flex flex-wrap gap-2">
              {settings.allowedSymbols &&
                settings.allowedSymbols.split(",").map((symbol, index) => (
                  <div
                    key={symbol + index}
                    className="bg-muted rounded-full px-2.5 py-1 text-xs text-muted-foreground"
                  >
                    {symbol.trim()}
                  </div>
                ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default RiskManager;
