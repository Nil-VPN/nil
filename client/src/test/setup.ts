// Registers @testing-library/jest-dom matchers (toBeInTheDocument, toBeDisabled, …) on vitest's expect.
import "@testing-library/jest-dom/vitest";
import { afterEach, beforeEach, vi } from "vitest";

// React uses console.error for missing-act and render/lifecycle warnings. Treat those as failed
// assertions so an asynchronous UI regression cannot hide behind a green Vitest exit code.
beforeEach(() => {
  vi.spyOn(console, "error").mockImplementation((...args: unknown[]) => {
    throw new Error(`unexpected console.error: ${args.map(String).join(" ")}`);
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});
