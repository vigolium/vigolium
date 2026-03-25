import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { ThemeProvider } from "./utils/theme";
import App from "./App";
import "./styles/index.css";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <ThemeProvider>
      <App />
    </ThemeProvider>
  </StrictMode>
);
