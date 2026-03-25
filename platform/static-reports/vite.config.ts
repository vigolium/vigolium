import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { viteSingleFile } from "vite-plugin-singlefile";
import { rename } from "fs/promises";
import { resolve } from "path";

function renameOutput(from: string, to: string): Plugin {
  return {
    name: "rename-output",
    closeBundle: async () => {
      await rename(from, to);
    },
  };
}

export default defineConfig({
  plugins: [
    react(),
    tailwindcss(),
    viteSingleFile(),
    renameOutput(
      resolve(__dirname, "dist/index.html"),
      resolve(__dirname, "dist/template.html"),
    ),
  ],
  build: {
    target: "esnext",
    assetsInlineLimit: 100000000,
    cssCodeSplit: false,
    minify: true,
    rollupOptions: {
      external: [
        "react",
        "react/jsx-runtime",
        "react-dom",
        "react-dom/client",
        "recharts",
        "ag-grid-community",
        "ag-grid-react",
      ],
    },
  },
});
