//+------------------------------------------------------------------+
//|                                                 Telegram2Mt5.mq5 |
//|                                  Copyright 2024, MetaQuotes Ltd. |
//|                                             https://www.mql5.com |
//+------------------------------------------------------------------+
#property copyright "Copyright 2024, MetaQuotes Ltd."
#property link      "https://www.mql5.com"
#property version   "1.00"
#property strict

#include <JAson.mqh>
#include <Trade\Trade.mqh>
#include <Trade\SymbolInfo.mqh>

input string Userinfo = "!!!===== User Information =====!!!";
input string useremail = "theyumplays@gmail.com";
input string userpassword = "bingbong123";
input string Server= "!!!===== Server =====!!!";
input string TradingOptin = "!!!===== Trading Option =====!!!";
input double tp1Lots = 0.4; // Closing lots of tp1
input double tp2Lots = 0.2; // Closing lots of tp2;
input double tp3Lots = 0.2; // Closing lots of tp3
input double tp4Lots = 0.2; // Closing lots of tp4

input bool usePrefix = false; // Use Prefix
input string prefix = "PRO"; //Prefix
input bool useSuffix = true; // Use Suffix
input string suffix = "PRO"; //Suffix

input string ServerUrl = "";

float AccountBalance, ssPnL, wRate;
int Timeout = 5000, TTrades, dailyTrades;
string ResHeaders, symbol;
char Response[];
uchar Body[];
bool trailingStop, isRisk, isMaxTrades, isDailyProfit;
double lotSize, risk, dailyLoss;
bool isUser;


CJAVal json;
CTrade trade;

struct TradeDetails
  {
   string            symbol;      // Symbol of the trade
   string            type;        // Type of the trade (BUY or SELL)
   string            entryPrice;  // Entry price of the trade
   string            lotSize;     // Lot size of the trade
   string            profit;      // Profit of the trade
   string            time;        // Time of the trade
  };

struct ActiveTradeDetails
  {
   string            symbol;      // Symbol
   double            volume;      // Volume (lot size)
   double            priceOpen;   // Open price
   double            sl;          // Stop Loss
   double            tp;          // Take Profit
   string            type;        // Trade type (BUY or SELL)
   string            time;        // Open Time
  };

struct PnLAndHistory
  {
   double            todaysPnL;               // Today's profit and loss
   TradeDetails      TradesHistory[];   // Array of trade details
   double            winRate; // WinRate
   int               tTrades; //Total trades
   ActiveTradeDetails ActiveTrades[]; // Array of active trades
  };

//+------------------------------------------------------------------+
//| Expert initialization function                                   |
//+------------------------------------------------------------------+
int OnInit()
  {
   CheckUser();
   EventSetTimer(2);
   return(INIT_SUCCEEDED);
  }
//+------------------------------------------------------------------+
//| Expert deinitialization function                                 |
//+------------------------------------------------------------------+
void OnDeinit(const int reason)
  {
   EventKillTimer();
  }
//+------------------------------------------------------------------+
//| Expert tick function                                             |
//+------------------------------------------------------------------+
void OnTick()
  {

  }
//+------------------------------------------------------------------+
void OnTimer()
  {
   if(isUser)
      SendAccountInfo();
  }
//+------------------------------------------------------------------+
//|                                                                  |
//+------------------------------------------------------------------+

  // Fetch ServerUrl
  bool FetchServerUrl() {
    string baseUrl = "https://sweeping-lovely-sunbird.ngrok-free.app"; // Fallback URL
    string url = baseUrl + "/mt/ngrok_url";
    string Headers = "Content-Type: application/json";
    int res = WebRequest("GET", url, Headers, Timeout, NULL, Response, ResHeaders);
    if (res == 200) {
       json.Deserialize(Response);
       ServerUrl = json["ngrok_url"].ToStr();
       Print("Fetched ServerUrl: ", ServerUrl);
       return true;
    } else {
       Print("Failed to fetch ngrok URL. Status: ", res, ", Response: ", CharArrayToString(Response));
       ServerUrl = baseUrl; // Use fallback if fetch fails
       return false;
    }
  }
//+------------------------------------------------------------------+
void CheckUser() {
  string userURL = ServerUrl + "/api/login";
  string Headers = "Content-Type: application/json";
  string BodyText = StringFormat("{\"email\": \"%s\", \"password\": \"%s\"}", useremail, userpassword);
  StringToCharArray(BodyText, Body, 0, StringLen(BodyText), CP_UTF8);
  int res = WebRequest("POST", userURL, Headers, Timeout, Body, Response, ResHeaders);
  if (res == 200) {
     isUser = true;
     Print("User authenticated successfully.");
  } else {
     isUser = false;
     Print("Authentication failed. HTTP Status: ", res);
  }
}
//+------------------------------------------------------------------+
void SendAccountInfo()
  {
   string AccountBalanceURL = ServerUrl + "/mt/accountinfo";
   AccountBalance = AccountInfoDouble(ACCOUNT_BALANCE);
   string Headers = "Content-Type: application/json";
   PnLAndHistory result = TradesHistory();
   PnL = result.todaysPnL;
   wRate = result.winRate;
   TTrades = result.tTrades;
   bool activeTrades = false;
   bool tHistory = false;

   CJAVal jsonTradesHistory;
   if(ArraySize(result.TradesHistory) > 0)
     {
      for(int i = 0; i < ArraySize(result.TradesHistory); i++)
        {
         CJAVal trade;
         trade["symbol"] = result.TradesHistory[i].symbol;
         trade["type"] = result.TradesHistory[i].type;
         trade["entryPrice"] = result.TradesHistory[i].entryPrice;
         trade["lotSize"] = result.TradesHistory[i].lotSize;
         trade["profit"] = result.TradesHistory[i].profit;
         trade["time"] = result.TradesHistory[i].time;
         jsonTradesHistory.Add(trade);
        }
      tHistory = true;
     }
   else
     {
      tHistory = false;
     }

   CJAVal jsonActiveTrades;
   if(ArraySize(result.ActiveTrades) > 0)
     {
      for(int i = 0; i < ArraySize(result.ActiveTrades); i++)
        {
         CJAVal trade;
         trade["symbol"] = result.ActiveTrades[i].symbol;
         trade["volume"] = result.ActiveTrades[i].volume;
         trade["priceOpen"] = result.ActiveTrades[i].priceOpen;
         trade["sl"] = result.ActiveTrades[i].sl;
         trade["tp"] = result.ActiveTrades[i].tp;
         trade["type"] = result.ActiveTrades[i].type;
         trade["time"] = result.ActiveTrades[i].time;
         jsonActiveTrades.Add(trade);
        }
      activeTrades = true;
     }
   else
     {
      activeTrades = false;
     }


   string BodyText;
   if(activeTrades != false && tHistory != false)
     {
      BodyText = StringFormat(
                    "{\"email\": \"%s\", \"password\": \"%s\", \"balance\": \"%f\", \"pnl\": \"%f\", \"tradeshistory\": %s, \"winRate\": %f, \"totalTrades\": %i, \"activeTrades\": %s}",
                    useremail, userpassword, AccountBalance, PnL, jsonTradesHistory.Serialize(), wRate, TTrades, jsonActiveTrades.Serialize()
                 );
     }
   if(activeTrades == false && tHistory != false)
     {
      BodyText = StringFormat(
                    "{\"email\": \"%s\", \"password\": \"%s\", \"balance\": \"%f\", \"pnl\": \"%f\", \"tradeshistory\": %s, \"winRate\": %f, \"totalTrades\": %i, \"activeTrades\": null}",
                    useremail, userpassword, AccountBalance, PnL, jsonTradesHistory.Serialize(), wRate, TTrades
                 );
     }
   if(activeTrades == false && tHistory == false)
     {
      BodyText = StringFormat(
                    "{\"email\": \"%s\", \"password\": \"%s\", \"balance\": \"%f\", \"pnl\": \"%f\", \"tradeshistory\": null, \"winRate\": %f, \"totalTrades\": %i, \"activeTrades\": null}",
                    useremail, userpassword, AccountBalance, PnL, wRate, TTrades
                 );
     }
   if(activeTrades != false && tHistory == false)
     {
      BodyText = StringFormat(
                    "{\"email\": \"%s\", \"password\": \"%s\", \"balance\": \"%f\", \"pnl\": \"%f\", \"tradeshistory\": null, \"winRate\": %f, \"totalTrades\": %i, \"activeTrades\": %s}",
                    useremail, userpassword, AccountBalance, PnL, wRate, TTrades, jsonActiveTrades.Serialize()
                 );
     }
   StringToCharArray(BodyText, Body, 0, StringLen(BodyText), CP_UTF8);
   int res = WebRequest("POST", AccountBalanceURL, Headers, Timeout, Body, Response, ResHeaders);
   json.Deserialize(Response);
   Print(res);
   if(res == 200)
     {
      trailingStop = json["setting"]["enableTrailingStop"].ToBool();
      if(json["setting"]["riskType"].ToStr() == "PERCENTAGE")
        {
         risk = json["setting"]["riskValue"].ToDbl();
         isRisk = true;
        }
      else
        {
         lotSize = json["setting"]["riskValue"].ToDbl();
         isRisk = false;
        }
      dailyTrades = json["setting"]["maxTradesPerDay"].ToInt();
      dailyLoss = json["setting"]["maxDailyLoss"].ToDbl();
      CJAVal *take_profits = json["signal"]["take_profits"];
      double tp_levels[];
      ArrayResize(tp_levels, take_profits.Size());
      for(int i = 0; i < take_profits.Size(); i++)
        {
         tp_levels[i] = take_profits[i].ToDbl();
        }
      string symbol = json["signal"]["symbol"].ToStr();
      if(useSuffix)
        {
         symbol = symbol + "." + suffix;
        }
      else
         if(usePrefix)
           {
            symbol = prefix + "." + symbol;
           }
      string type = json["signal"]["action"].ToStr();
      double entryPrice = json["signal"]["entry_price"].ToDbl();
      double stoploss = json["signal"]["stop_loss"].ToDbl();
      executeTrade(symbol, type, entryPrice, stoploss, tp_levels);
     }
   if(res == 201)
     {
      CJAVal *take_profits = json["signal"]["take_profits"];
      double tp_levels[];
      ArrayResize(tp_levels, take_profits.Size());
      for(int i = 0; i < take_profits.Size(); i++)
        {
         tp_levels[i] = take_profits[i].ToDbl();
        }
      string symbol = json["signal"]["symbol"].ToStr();
      string type = json["signal"]["action"].ToStr();
      double entryPrice = json["signal"]["entry_price"].ToDbl();
      double stoploss = json["signal"]["stop_loss"].ToDbl();
      if(useSuffix)
        {
         symbol = symbol + "." + suffix;
        }
      else
         if(usePrefix)
           {
            symbol = prefix + "." + symbol;
           }
      executeTrade(symbol, type, entryPrice, stoploss, tp_levels);
     }
   if(res == 202)
     {
      trailingStop = json["setting"]["enableTrailingStop"].ToBool();
      if(json["setting"]["riskType"].ToStr() == "PERCENTAGE")
        {
         risk = json["setting"]["riskValue"].ToDbl();
         isRisk = true;
        }
      else
        {
         lotSize = json["setting"]["riskValue"].ToDbl();
         isRisk = false;
        }
      dailyTrades = json["setting"]["maxTradesPerDay"].ToInt();
      dailyLoss = json["setting"]["maxDailyLoss"].ToDbl();
     }
   if(res == 203)
     {
      return;
     }

  }

//+------------------------------------------------------------------+
PnLAndHistory TradesHistory()
  {
   int size;
   PnLAndHistory result;
   result.todaysPnL = 0.0;
   ArrayFree(result.TradesHistory);
   ArrayFree(result.ActiveTrades);

   if(!HistorySelect(0, TimeCurrent()))
     {
      Print("HistorySelect() failed. Error ", GetLastError());
     }
   double todaysPnL = 0.0;
   datetime todayStart = iTime(Symbol(), PERIOD_D1, 0); // Start of today (00:00)
   datetime todayEnd = todayStart + 86400;          // End of today (23:59:59)
   int TotalTrades = 0, WinningTrades = 0;

   uint HistoryTrades = HistoryDealsTotal();

   for(int i = HistoryDealsTotal() - 1; i >= 0; i--)
     {
      ulong dealTicket = HistoryDealGetTicket(i);
      if(dealTicket > 0)
        {
         if(HistoryDealGetInteger(dealTicket, DEAL_ENTRY) == DEAL_ENTRY_OUT)
           {
            TotalTrades++; // Increment total trades
            double profit = HistoryDealGetDouble(dealTicket, DEAL_PROFIT);
            if(profit > 0) // Check if the trade was profitable
              {
               WinningTrades++; // Increment winning trades
              }
           }
         result.winRate = (double)WinningTrades / TotalTrades * 100;
         result.tTrades = TotalTrades;
         datetime dealTime = (datetime)HistoryDealGetInteger(dealTicket, DEAL_TIME);
         if(dealTime >= todayStart && dealTime < todayEnd)
           {
            if(HistoryDealGetInteger(dealTicket, DEAL_ENTRY) == DEAL_ENTRY_OUT)
              {
               TradeDetails trade;
               double profit = HistoryDealGetDouble(dealTicket, DEAL_PROFIT);
               trade.symbol = HistoryDealGetString(dealTicket, DEAL_SYMBOL); // Symbol
               trade.type = HistoryDealGetInteger(dealTicket, DEAL_TYPE) == 0 ? "SELL" : "BUY"; //Type
               trade.entryPrice = DoubleToString(HistoryDealGetDouble(dealTicket, DEAL_PRICE)); //Entry Price
               trade.lotSize = DoubleToString(HistoryDealGetDouble(dealTicket, DEAL_VOLUME)); //Lots Size
               trade.profit = DoubleToString(HistoryDealGetDouble(dealTicket, DEAL_PROFIT)); //Profit
               trade.time = TimeToString(HistoryDealGetInteger(dealTicket, DEAL_TIME));

               size = ArraySize(result.TradesHistory);
               ArrayResize(result.TradesHistory, size + 1); // Resize the array
               result.TradesHistory[size] = trade; // Add the trade to the array
               result.todaysPnL += HistoryDealGetDouble(dealTicket, DEAL_PROFIT);
              }
           }
        }
     }

   int totalPositions = PositionsTotal();
   for(int i = 0; i < totalPositions; i++)
     {
      ulong ticket = PositionGetTicket(i);
      if(ticket > 0)
        {
         ActiveTradeDetails trade;
         trade.symbol = PositionGetString(POSITION_SYMBOL);
         trade.volume = DoubleToString(PositionGetDouble(POSITION_VOLUME));
         trade.priceOpen = DoubleToString(PositionGetDouble(POSITION_PRICE_OPEN));
         trade.sl = DoubleToString(PositionGetDouble(POSITION_SL));
         trade.tp = DoubleToString(PositionGetDouble(POSITION_TP));
         trade.type = PositionGetInteger(POSITION_TYPE) == POSITION_TYPE_BUY ? "BUY" : "SELL";
         trade.time = TimeToString(PositionGetInteger(POSITION_TIME));
         int size = ArraySize(result.ActiveTrades);
         ArrayResize(result.ActiveTrades, size + 1);
         result.ActiveTrades[size] = trade;
        }
     }
   if(ArraySize(result.TradesHistory) > dailyTrades)
      isMaxTrades = false;
   Print("Size---------->", ArraySize(result.TradesHistory));
   if(result.todaysPnL < 0 && MathAbs(result.todaysPnL) > AccountInfoDouble(ACCOUNT_BALANCE) * dailyLoss / 100)
      isDailyProfit = false;
   Print("Profit---------->", result.todaysPnL);
   return result;
  }
//+------------------------------------------------------------------+
double CalculateLotSize(string fsymbol, double entryPrice, double stopLoss, double RiskPercent)
  {
   double balance = AccountInfoDouble(ACCOUNT_BALANCE);

   double riskAmount = balance * RiskPercent / 100;

   double point = SymbolInfoDouble(fsymbol, SYMBOL_POINT);
   double tickValue = SymbolInfoDouble(fsymbol, SYMBOL_TRADE_TICK_VALUE);
   double lotStep = SymbolInfoDouble(fsymbol, SYMBOL_VOLUME_STEP);
   double minLot = SymbolInfoDouble(fsymbol, SYMBOL_VOLUME_MIN);
   double maxLot = SymbolInfoDouble(fsymbol, SYMBOL_VOLUME_MAX);

   double slPoints = MathAbs(entryPrice - stopLoss) / point;

   double lotSize = riskAmount / (slPoints * point * tickValue * 100);

   lotSize = MathFloor(lotSize / lotStep) * lotStep;
   lotSize = NormalizeDouble(lotSize, 2);

   if(lotSize < minLot)
      lotSize = minLot;
   if(lotSize > maxLot)
      lotSize = maxLot;

   return lotSize;
  }
//+------------------------------------------------------------------+
//|                                                                  |
//+------------------------------------------------------------------+
void executeTrade(string gsymbol, string type, double entryPrice, double stoploss, double &takeprofit[])
  {
   if(isRisk)
     {
      if(type == "SELL")
         lotSize = CalculateLotSize(gsymbol, SymbolInfoDouble(gsymbol, SYMBOL_BID), stoploss, risk);
      else
         if(type == "BUY")
            lotSize = CalculateLotSize(gsymbol, SymbolInfoDouble(gsymbol, SYMBOL_ASK), stoploss, risk);
         else
            lotSize = CalculateLotSize(gsymbol, entryPrice, stoploss, risk);
     }
   Print(lotSize);
   Print(takeprofit[0]);
   Print(stoploss);
   Print(gsymbol);
   if(!isDailyProfit && !isMaxTrades)
     {
      if(type == "SELL")
         trade.Sell(lotSize, gsymbol, SymbolInfoDouble(symbol, SYMBOL_BID), stoploss, takeprofit[0], "abc");
      if(type == "BUY")
         trade.Buy(lotSize, gsymbol, SymbolInfoDouble(symbol, SYMBOL_ASK), stoploss, takeprofit[0], "abc");
     }

   return;
  }
////+------------------------------------------------------------------+

//+------------------------------------------------------------------+
