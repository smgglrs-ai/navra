import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/metrics": "http://127.0.0.1:9315",
      "/mcp": "http://127.0.0.1:9315",
      "/approvals": "http://127.0.0.1:9315",
    },
  },
});
