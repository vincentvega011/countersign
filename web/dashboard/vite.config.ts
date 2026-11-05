// The dashboard build (docs/PROTOCOL.md Decision 112). The AG Studio licence key is read from the
// environment (AG_STUDIO_LICENSE_KEY, also from the repository's gitignored .env) at build or dev time
// and compiled into the bundle, which is how a browser licence key works. It is never committed: the
// dist folder is gitignored and a test scans tracked files for it. Without a key the build still works
// and Studio shows its trial watermark.
import { fileURLToPath } from "node:url";
import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";

const root = fileURLToPath(new URL("../..", import.meta.url));

export default defineConfig(({ mode }) => {
  const env = { ...loadEnv(mode, root, "AG_STUDIO_"), ...process.env };
  const key = (env.AG_STUDIO_LICENSE_KEY ?? "").trim();
  const api = process.env.DASHBOARD_API ?? "http://127.0.0.1:8000";
  return {
    base: "/dashboard/",
    plugins: [react()],
    define: { __AG_STUDIO_LICENSE_KEY__: JSON.stringify(key) },
    build: {
      manifest: true,
      outDir: "dist",
      emptyOutDir: true,
      assetsInlineLimit: 0,
      chunkSizeWarningLimit: 8000,
      modulePreload: { polyfill: false },
    },
    server: {
      fs: { allow: [root] },
      proxy: { "/dashboard/api": api, "/.well-known": api },
    },
  };
});
