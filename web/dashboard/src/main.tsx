import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "../../ui/tokens.css";
import "../../ui/fonts.css";
import "./dashboard.css";
import { App } from "./App";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
