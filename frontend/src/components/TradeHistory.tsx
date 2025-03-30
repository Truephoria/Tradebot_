import React from "react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Trade } from "@/utils/types";
import { TrendingUp, TrendingDown } from "lucide-react";
import {
  Table,
  TableBody,
  TableCaption,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useMetadataStore } from "@/stores/metadata-store";

// Sample data for the trades
const sampleTrades: Trade[] = [
  {
    id: "1",
    signalId: "sig1",
    symbol: "EURUSD",
    action: "BUY",
    entryPrice: 1.0876,
    stopLoss: 1.085,
    takeProfits: [1.089, 1.092, 1.095],
    lotSize: 0.1,
    status: "OPEN",
    pnl: 14.5,
    openTime: new Date("2023-06-15T10:30:00"),
  },
  {
    id: "2",
    signalId: "sig2",
    symbol: "GBPUSD",
    action: "SELL",
    entryPrice: 1.276,
    stopLoss: 1.2785,
    takeProfits: [1.2735, 1.271, 1.2685],
    lotSize: 0.25,
    status: "CLOSED",
    pnl: -12.5,
    openTime: new Date("2023-06-14T15:45:00"),
    closeTime: new Date("2023-06-14T17:30:00"),
  },
  {
    id: "3",
    signalId: "sig3",
    symbol: "USDJPY",
    action: "BUY",
    entryPrice: 149.85,
    stopLoss: 149.5,
    takeProfits: [150.2, 150.5, 151.0],
    lotSize: 0.15,
    status: "PARTIAL",
    pnl: 35.2,
    openTime: new Date("2023-06-13T09:15:00"),
  },
  {
    id: "4",
    signalId: "sig4",
    symbol: "XAUUSD",
    action: "BUY",
    entryPrice: 1925.4,
    stopLoss: 1915.2,
    takeProfits: [1935.6, 1945.8, 1955.0],
    lotSize: 0.05,
    status: "CLOSED",
    pnl: 51.0,
    openTime: new Date("2023-06-12T14:20:00"),
    closeTime: new Date("2023-06-13T11:45:00"),
  },
  {
    id: "5",
    signalId: "sig5",
    symbol: "AUDUSD",
    action: "SELL",
    entryPrice: 0.6585,
    stopLoss: 0.661,
    takeProfits: [0.656, 0.6535, 0.651],
    lotSize: 0.2,
    status: "CLOSED",
    pnl: 22.5,
    openTime: new Date("2023-06-11T08:30:00"),
    closeTime: new Date("2023-06-11T16:15:00"),
  },
];

const formatDate = (date: Date) => {
  return new Intl.DateTimeFormat("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
};

const TradeHistory: React.FC = () => {
  const metadataState = useMetadataStore();

  return (
    <div className="space-y-4">
      <Card className="card-shadow border border-border">
        <CardHeader className="pb-2">
          <div className="flex justify-between items-center">
            <CardTitle>Trade History</CardTitle>
          </div>
          <CardDescription>
            View all your executed trades and their outcomes
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableCaption>Recent trade history</TableCaption>
            <TableHeader>
              <TableRow>
                <TableHead>Symbol</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Entry Price</TableHead>
                <TableHead>Lot Size</TableHead>
                <TableHead>PnL</TableHead>
                <TableHead>Time</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {metadataState.tradeshistory.map((trade, index) => (
                <TableRow key={index}>
                  <TableCell className="font-medium">{trade.symbol}</TableCell>
                  <TableCell>
                    <span
                      className={`inline-flex items-center px-2.5 py-0.5 rounded-md text-xs font-medium ${
                        trade.type === "BUY"
                          ? "bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400"
                          : "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400"
                      }`}
                    >
                      {trade.type === "BUY" ? (
                        <TrendingUp className="mr-1 h-3 w-3" />
                      ) : (
                        <TrendingDown className="mr-1 h-3 w-3" />
                      )}
                      {trade.type}
                    </span>
                  </TableCell>
                  <TableCell>
                    {parseFloat(trade.entryPrice).toFixed(2)}
                  </TableCell>
                  <TableCell>{parseFloat(trade.lotSize).toFixed(2)}</TableCell>
                  <TableCell
                    className={
                      parseFloat(trade.profit) >= 0
                        ? "text-green-600 dark:text-green-400"
                        : "text-red-600 dark:text-red-400"
                    }
                  >
                    {parseFloat(trade.profit) > 0 ? "+" : ""}
                    {parseFloat(trade.profit).toFixed(2)}
                  </TableCell>
                  <TableCell>{formatDate(new Date(trade.time))}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
};

export default TradeHistory;
