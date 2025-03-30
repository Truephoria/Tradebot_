// frontend/src/components/OpenTrades.tsx
'use client'; // Required for client-side hooks in Next.js App Router
import React, { useState } from 'react';
import { cn } from '@/lib/utils';
import { OpenTradeType } from '@/types/metadata'; // Use OpenTradeType from metadata.ts
import { useMetadataStore } from '@/stores/metadata-store';

interface OpenTradesProps {
  className?: string;
}

const OpenTrades: React.FC<OpenTradesProps> = ({ className }) => {
  const { activeTrades } = useMetadataStore();

  // Sample trade data as fallback (typed as OpenTradeType)
  const [sampleTrades] = useState<OpenTradeType[]>([
    {
      symbol: 'EURUSD',
      volume: '0.1',
      priceOpen: '1.0765',
      sl: '1.074',
      tp: '1.079', // Single TP as string (adjust if your backend sends an array)
      type: 'BUY',
      time: new Date(Date.now() - 3600000 * 2).toISOString(),
    },
    {
      symbol: 'GBPUSD',
      volume: '0.15',
      priceOpen: '1.264',
      sl: '1.2665',
      tp: '1.2615',
      type: 'SELL',
      time: new Date(Date.now() - 3600000 * 5).toISOString(),
    },
    {
      symbol: 'XAUUSD',
      volume: '0.05',
      priceOpen: '1890.5',
      sl: '1885.0',
      tp: '1896.0',
      type: 'BUY',
      time: new Date(Date.now() - 3600000 / 2).toISOString(),
    },
  ]);

  // Handle null case with fallback to sampleTrades
  const tradesToDisplay = activeTrades ?? sampleTrades;

  return (
    <div
      className={cn(
        'bg-card rounded-xl p-5 card-shadow border border-border',
        className
      )}
    >
      <div className="flex justify-between items-start mb-4">
        <h3 className="text-sm font-medium text-muted-foreground">Open Trades</h3>
        <button className="text-xs font-medium text-primary hover:text-primary/80 transition-colors">
          View All
        </button>
      </div>

      <div className="space-y-3">
        {tradesToDisplay.length > 0 ? (
          tradesToDisplay.map((trade) => (
            <div
              key={trade.symbol + trade.time} // Unique key (adjust if you have an ID)
              className="bg-accent rounded-lg p-3 transition-all duration-300 hover:bg-accent/80"
            >
              <div className="flex justify-between items-start mb-2">
                <div className="flex items-center">
                  <span
                    className={cn(
                      'inline-flex items-center justify-center w-6 h-6 rounded mr-2 text-xs font-medium',
                      trade.type === 'BUY'
                        ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400'
                        : 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400'
                    )}
                  >
                    {trade.type === 'BUY' ? 'B' : 'S'}
                  </span>
                  <div>
                    <p className="text-sm font-medium text-foreground">{trade.symbol}</p>
                    <p className="text-xs text-muted-foreground">
                      {trade.volume} lot{parseFloat(trade.volume) !== 1 ? 's' : ''}
                    </p>
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-3 gap-2 text-xs text-muted-foreground">
                <div>
                  <p>Entry</p>
                  <p className="font-medium text-foreground">{trade.priceOpen}</p>
                </div>
                <div>
                  <p>SL</p>
                  <p className="font-medium text-foreground">{trade.sl}</p>
                </div>
                <div>
                  <p>TP</p>
                  <p className="font-medium text-foreground">{trade.tp || 'N/A'}</p>
                </div>
              </div>

              <div className="mt-2 pt-2 border-t border-border flex justify-between items-center text-xs">
                <span className="text-muted-foreground">
                  {new Date(trade.time).toLocaleTimeString([], {
                    hour: '2-digit',
                    minute: '2-digit',
                  })}
                </span>
              </div>
            </div>
          ))
        ) : (
          <p className="text-sm text-muted-foreground">No active trades available.</p>
        )}
      </div>
    </div>
  );
};

export default OpenTrades;