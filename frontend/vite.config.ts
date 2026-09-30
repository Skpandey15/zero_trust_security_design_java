import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The dev server proxies /api to the BFF so the browser stays same-origin.
// ADR-SEC-007: the session cookie is HttpOnly and SameSite, so a cross-origin
// dev setup would not send it - same-origin in dev keeps dev honest to prod.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      // Everything the BFF owns. The SPA's own /login and /register routes are
      // NOT proxied - only the OAuth client endpoints under /oauth2 and /login/oauth2.
      "/api": { target: "http://localhost:8080", changeOrigin: false },
      "/oauth2": { target: "http://localhost:8080", changeOrigin: false },
      "/login/oauth2": { target: "http://localhost:8080", changeOrigin: false },
    },
  },
});
