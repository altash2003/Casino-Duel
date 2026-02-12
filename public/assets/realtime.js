import { io } from "https://cdn.socket.io/4.7.5/socket.io.esm.min.js";
export function connectRealtime() {
  const token = localStorage.getItem("token");
  return io("/", { auth: { token } });
}
