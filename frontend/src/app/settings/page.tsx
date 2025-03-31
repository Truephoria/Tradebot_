'use client';
import React, { useEffect, useRef, useState } from 'react';

import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { DollarSign, Shield } from 'lucide-react';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
} from '@/components/ui/form';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { initializeSocket, getSocket } from '@/utils/socket';
import { useSignalStore } from '@/stores/signal-store';
import { SignalStateType } from '@/types/signal';
import { toast } from 'sonner';
import { useSettingStore } from '@/stores/settings-store';
import { Socket } from 'socket.io-client';

const formSchema = z.object({
  riskType: z.enum(['FIXED', 'PERCENTAGE']),
  riskValue: z.coerce.number().min(0.01).max(100),
  maxDailyLoss: z.coerce.number().min(0),
  minimumRRR: z.coerce.number().min(0),
  enableTrailingStop: z.boolean(),
  tradingHoursStart: z.string(),
  tradingHoursEnd: z.string(),
  maxTradesPerDay: z.coerce.number().min(0).max(100),
  allowedSymbols: z.string(),
  botEnabled: z.boolean().default(true),
});

const defaultSettings = {
  riskType: 'PERCENTAGE' as const,
  riskValue: 1.5,
  maxDailyLoss: 3,
  minimumRRR: 1.5,
  enableTrailingStop: true,
  tradingHoursStart: '08:00',
  tradingHoursEnd: '16:00',
  maxTradesPerDay: 10,
  allowedSymbols: 'EURUSD,GBPUSD,XAUUSD,USDJPY,US30',
  botEnabled: true,
};

const SettingsPage: React.FC = () => {
  const socket = useRef<Socket | null>(null);
  const setSignalState = useSignalStore((state) => state.setSignal);
  const { settings, getSettings, updateSettings } = useSettingStore();
  const [isEditing, setIsEditing] = useState(false); // Track editing state

  const form = useForm<z.infer<typeof formSchema>>({
    resolver: zodResolver(formSchema),
    defaultValues: defaultSettings,
  });

  useEffect(() => {
    // Fetch settings only once on mount
    getSettings()
      .then(() => {
        form.reset(settings || defaultSettings);
      })
      .catch((err) => {
        console.error('Failed to fetch settings:', err);
        form.reset(defaultSettings);
      });

    initializeSocket();
    socket.current = getSocket();

    if (!socket.current) {
      console.error('Socket is not initialized.');
      return;
    }

    const currentSocket = socket.current;
    currentSocket.on('new_signal', (signal: SignalStateType) => {
      setSignalState(signal);
    });

    return () => {
      currentSocket.off('new_signal');
    };
  }, []); // Empty dependency array to run only on mount

  // Sync form with settings changes only when not editing
  useEffect(() => {
    if (!isEditing && settings) {
      form.reset(settings);
    }
  }, [settings, isEditing]);

  const onSubmit = async (values: z.infer<typeof formSchema>) => {
    try {
      await updateSettings(values);
      toast.success('Settings saved successfully');
      setIsEditing(false); // Stop editing after save
    } catch (error) {
      console.error('Error updating settings:', error);
      toast.error('Error updating settings');
    }
  };

  const handleFormChange = () => {
    if (!isEditing) {
      setIsEditing(true); // Mark as editing when user changes form
    }
  };

  return (
    <div className="min-h-screen bg-background transition-colors duration-300">
      
      <main className="container mx-auto py-6 px-4 min-h-[calc(100vh-73px)] animate-fade-in">
        <h1 className="text-2xl font-bold mb-6">Settings</h1>

        <Tabs defaultValue="risk" className="w-full">
          <TabsList className="mb-4">
            <TabsTrigger value="risk" className="flex items-center gap-2">
              <Shield size={16} />
              <span>Risk Management</span>
            </TabsTrigger>
            <TabsTrigger value="trading" className="flex items-center gap-2">
              <DollarSign size={16} />
              <span>Trading</span>
            </TabsTrigger>
          </TabsList>

          <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)} onChange={handleFormChange}>
              <TabsContent value="risk" className="space-y-4">
                <Card className="card-shadow border border-border">
                  <CardHeader>
                    <CardTitle>Risk Settings</CardTitle>
                    <CardDescription>
                      Configure your risk management parameters to protect your capital
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                      <FormField
                        control={form.control}
                        name="riskType"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Risk Type</FormLabel>
                            <Select
                              onValueChange={field.onChange}
                              defaultValue={field.value}
                            >
                              <FormControl>
                                <SelectTrigger>
                                  <SelectValue placeholder="Select risk type" />
                                </SelectTrigger>
                              </FormControl>
                              <SelectContent>
                                <SelectItem value="FIXED">Fixed Lot Size</SelectItem>
                                <SelectItem value="PERCENTAGE">Percentage Based</SelectItem>
                              </SelectContent>
                            </Select>
                            <FormDescription>
                              Choose how you want to calculate position size
                            </FormDescription>
                          </FormItem>
                        )}
                      />
                      <FormField
                        control={form.control}
                        name="riskValue"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>
                              {form.watch('riskType') === 'FIXED'
                                ? 'Fixed Lot Size'
                                : 'Risk Percentage (%)'}
                            </FormLabel>
                            <FormControl>
                              <Input type="number" step="0.01" {...field} />
                            </FormControl>
                            <FormDescription>
                              {form.watch('riskType') === 'FIXED'
                                ? 'Standard lot size for each trade'
                                : 'Percentage of account balance to risk per trade'}
                            </FormDescription>
                          </FormItem>
                        )}
                      />
                      <FormField
                        control={form.control}
                        name="maxDailyLoss"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Maximum Daily Loss (%)</FormLabel>
                            <FormControl>
                              <Input type="number" step="0.1" {...field} />
                            </FormControl>
                            <FormDescription>
                              Stop trading if daily loss exceeds this percentage
                            </FormDescription>
                          </FormItem>
                        )}
                      />
                      <FormField
                        control={form.control}
                        name="minimumRRR"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Minimum Risk-Reward Ratio</FormLabel>
                            <FormControl>
                              <Input type="number" step="0.1" {...field} />
                            </FormControl>
                            <FormDescription>
                              Minimum RRR required to take a trade
                            </FormDescription>
                          </FormItem>
                        )}
                      />
                      <FormField
                        control={form.control}
                        name="enableTrailingStop"
                        render={({ field }) => (
                          <FormItem className="flex flex-row items-center justify-between rounded-lg border p-4">
                            <div className="space-y-0.5">
                              <FormLabel className="text-base">Trailing Stop Loss</FormLabel>
                              <FormDescription>
                                Automatically adjust stop loss as trade moves in your favor
                              </FormDescription>
                            </div>
                            <FormControl>
                              <Switch
                                checked={field.value}
                                onCheckedChange={field.onChange}
                              />
                            </FormControl>
                          </FormItem>
                        )}
                      />
                    </div>
                  </CardContent>
                </Card>
              </TabsContent>

              <TabsContent value="trading" className="space-y-4">
                <Card className="card-shadow border border-border">
                  <CardHeader>
                    <CardTitle>Trading Settings</CardTitle>
                    <CardDescription>Configure when and what to trade</CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                      <FormField
                        control={form.control}
                        name="tradingHoursStart"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Trading Hours Start</FormLabel>
                            <FormControl>
                              <Input type="time" {...field} />
                            </FormControl>
                            <FormDescription>
                              Start time for automated trading (24h format)
                            </FormDescription>
                          </FormItem>
                        )}
                      />
                      <FormField
                        control={form.control}
                        name="tradingHoursEnd"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Trading Hours End</FormLabel>
                            <FormControl>
                              <Input type="time" {...field} />
                            </FormControl>
                            <FormDescription>
                              End time for automated trading (24h format)
                            </FormDescription>
                          </FormItem>
                        )}
                      />
                      <FormField
                        control={form.control}
                        name="maxTradesPerDay"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Maximum Trades Per Day</FormLabel>
                            <FormControl>
                              <Input type="number" {...field} />
                            </FormControl>
                            <FormDescription>
                              Maximum number of trades to execute per day
                            </FormDescription>
                          </FormItem>
                        )}
                      />
                      <FormField
                        control={form.control}
                        name="allowedSymbols"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Allowed Symbols</FormLabel>
                            <FormControl>
                              <Input {...field} />
                            </FormControl>
                            <FormDescription>
                              Comma-separated list of tradable symbols
                            </FormDescription>
                          </FormItem>
                        )}
                      />
                      <FormField
                        control={form.control}
                        name="botEnabled"
                        render={({ field }) => (
                          <FormItem className="flex flex-row items-center justify-between rounded-lg border p-4 col-span-full">
                            <div className="space-y-0.5">
                              <FormLabel className="text-base">Enable Trading Bot</FormLabel>
                              <FormDescription>
                                Turn automated trading on or off
                              </FormDescription>
                            </div>
                            <FormControl>
                              <Switch
                                checked={field.value}
                                onCheckedChange={field.onChange}
                              />
                            </FormControl>
                          </FormItem>
                        )}
                      />
                    </div>
                  </CardContent>
                </Card>
              </TabsContent>

              <div className="mt-6 flex justify-end space-x-4">
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => {
                    form.reset(settings || defaultSettings);
                    setIsEditing(false);
                  }}
                >
                  Cancel
                </Button>
                <Button type="submit" disabled={!isEditing}>
                  Save Settings
                </Button>
              </div>
            </form>
          </Form>
        </Tabs>
      </main>
    </div>
  );
};

export default SettingsPage;