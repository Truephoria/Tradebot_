import { io, Socket } from "socket.io-client";

let socket: Socket;

export const initializeSocket = () => {
  if (socket) {
    console.log("Socket is already initialized.");
    return;
  }

  socket = io("http://localhost:5000");

  socket.on("connect_error", (error) => {
    console.error("Connection error:", error);
  });

  socket.on("reconnect_attempt", () => {
    console.log("Attempting to reconnect...");
  });

  socket.on("reconnect", () => {
    console.log("Reconnected to the server.");
  });

  socket.on("disconnect", () => {
    console.log("Disconnected from the server.");
  });
};

export const getSocket = () => {
  if (!socket) {
    console.error("Socket has not been initialized.");
    return null;
  }
  return socket;
};
