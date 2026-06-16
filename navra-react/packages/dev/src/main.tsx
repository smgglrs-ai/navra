import React from "react";
import { createRoot } from "react-dom/client";
import "@patternfly/react-core/dist/styles/base.css";
import { App } from "./App";

createRoot(document.getElementById("root")!).render(<App />);
