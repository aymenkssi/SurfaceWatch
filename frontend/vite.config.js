import path from "node:path";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { "@": path.resolve(import.meta.dirname, "src") },
  },
  server: {
    // Dev: forward API calls to the FastAPI backend (uvicorn on :8000)
    proxy: { "/api": "http://localhost:8000" },
  },
});
