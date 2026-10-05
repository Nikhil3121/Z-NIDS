import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import App from "@/App";
import { AuthProvider } from "@/auth/AuthProvider";
import { ApiError } from "@/lib/api";
import { RealtimeProvider } from "@/realtime/RealtimeProvider";
import "@/index.css";

try {
  if ((localStorage.getItem("znids-theme") ?? "dark") === "dark") document.documentElement.classList.add("dark");
} catch {
  document.documentElement.classList.add("dark");
}

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 15_000,
      refetchOnWindowFocus: false,
      // Never retry client errors (401/403/404/422); retry transient ones twice.
      retry: (count, err) => !(err instanceof ApiError && err.status >= 400 && err.status < 500) && count < 2,
    },
  },
});

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <RealtimeProvider>
          <App />
        </RealtimeProvider>
      </AuthProvider>
    </QueryClientProvider>
  </StrictMode>,
);
