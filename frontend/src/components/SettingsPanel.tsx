import React, { useEffect, useState } from "react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Input } from "@/components/ui/input";
import { toast } from "sonner";
import { useSettingStore } from "@/stores/settings-store";
// If you have a custom axios instance or an auth store:
import axios from "@/utils/axios";

type TabKey = "trading" | "auth";

interface SettingsPanelProps {
  className?: string;
}

const SettingsPanel: React.FC<SettingsPanelProps> = ({ className }) => {
  const settingState = useSettingStore();
  const [autoTrading, setAutoTrading] = useState(settingState.settings.botEnabled);
  const [isLoading, setIsLoading] = useState(false);
  const [minRRR, setMinRRR] = useState(settingState.settings.minimumRRR);

  // Tab management
  const [activeTab, setActiveTab] = useState<TabKey>("trading");

  // Fields to store what was in .env:
  const [apiId, setApiId] = useState("");
  const [apiHash, setApiHash] = useState("");
  const [phoneNumber, setPhoneNumber] = useState("");
  const [feedback, setFeedback] = useState("");

  useEffect(() => {
    // Load settings from API
    settingState.getSettings();

    // Optionally fetch the current API_ID, API_HASH, PHONE_NUMBER from the server
    // If you store them in a config table or an endpoint like `/api/telegram/creds`
    // you can call it here to pre-fill the fields:
    /*
    axios.get("/api/telegram/creds")
      .then(res => {
        setApiId(res.data.api_id || "");
        setApiHash(res.data.api_hash || "");
        setPhoneNumber(res.data.phone_number || "");
      })
      .catch(err => console.error("Failed to fetch existing Telegram creds:", err));
    */
  }, []);

  // Trading tab handlers
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

  // Authentication tab handler - sending .env-like creds to server
  const handleUpdateTelegramCreds = async () => {
    setIsLoading(true);
    setFeedback("Updating Telegram credentials...");
    try {
      // Example: call a new endpoint where you store these in DB or memory
      const response = await axios.post("/api/telegram/creds", {
        api_id: apiId,
        api_hash: apiHash,
        phone_number: phoneNumber,
      });
      setFeedback(response.data.message || "Credentials updated successfully.");
    } catch (error: any) {
      console.error("Error updating Telegram creds:", error);
      const msg = error.response?.data?.message || error.message;
      setFeedback(`Error: ${msg}`);
    }
    setIsLoading(false);
  };

  return (
    <div className={cn("bg-card rounded-xl p-5 card-shadow border border-border", className)}>
      <div className="flex justify-between items-center mb-4">
        <h3 className="text-sm font-medium text-muted-foreground">
          Settings
        </h3>
        <div className="space-x-2">
          <Button
            variant={activeTab === "trading" ? "default" : "outline"}
            size="sm"
            onClick={() => setActiveTab("trading")}
          >
            Trading Settings
          </Button>
          <Button
            variant={activeTab === "auth" ? "default" : "outline"}
            size="sm"
            onClick={() => setActiveTab("auth")}
          >
            Authentication
          </Button>
        </div>
      </div>

      {activeTab === "trading" && (
        <div className="space-y-5">
          {/* Auto-Trading */}
          <div className="bg-accent rounded-lg p-4">
            <div className="flex justify-between items-center">
              <div className="space-y-1">
                <h4 className="text-sm font-medium text-foreground">Auto-Trading</h4>
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

          {/* Minimum RRR */}
          <div className="bg-accent rounded-lg p-4">
            <h4 className="text-sm font-medium text-foreground mb-2">Minimum Risk/Reward Ratio</h4>
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
      )}

      {activeTab === "auth" && (
        <div className="space-y-5">
          <div className="bg-accent rounded-lg p-4">
            <h4 className="text-sm font-medium text-foreground mb-2">Telegram (.env) Credentials</h4>
            <p className="text-xs text-muted-foreground mb-3">
              Provide your Telegram API credentials (API_ID, API_HASH, PHONE_NUMBER). 
              This is for single-user session creation.
            </p>

            {/* API_ID */}
            <div className="mb-2">
              <label className="text-xs font-medium text-muted-foreground block mb-1">
                API_ID
              </label>
              <Input
                placeholder="123456"
                value={apiId}
                onChange={(e) => setApiId(e.target.value)}
                disabled={isLoading}
                className="text-xs h-8"
              />
            </div>

            {/* API_HASH */}
            <div className="mb-2">
              <label className="text-xs font-medium text-muted-foreground block mb-1">
                API_HASH
              </label>
              <Input
                placeholder="abcdef123456"
                value={apiHash}
                onChange={(e) => setApiHash(e.target.value)}
                disabled={isLoading}
                className="text-xs h-8"
              />
            </div>

            {/* PHONE_NUMBER */}
            <div className="mb-2">
              <label className="text-xs font-medium text-muted-foreground block mb-1">
                PHONE_NUMBER
              </label>
              <Input
                placeholder="+1 555 123 4567"
                value={phoneNumber}
                onChange={(e) => setPhoneNumber(e.target.value)}
                disabled={isLoading}
                className="text-xs h-8"
              />
            </div>

            <Button
              onClick={handleUpdateTelegramCreds}
              className="h-8 text-xs px-3"
              disabled={isLoading}
            >
              Update Credentials
            </Button>

            {feedback && (
              <div className="mt-2 text-xs text-muted-foreground">
                {feedback}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default SettingsPanel;
