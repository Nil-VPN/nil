import { describe, it, expect, vi, beforeEach } from "vitest";
import { act, render, screen, fireEvent, waitFor } from "@testing-library/react";
import type { PortalConfig } from "./lib/types";

// Mock the Tauri bridge so components run without a Rust backend.
const invokeMock = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (cmd: string, args?: unknown) => invokeMock(cmd, args),
}));

// Import AFTER the mock is registered.
import {
  MainScreen,
  BuyTokensScreen,
  SettingsScreen,
  RecoverAccountScreen,
  SubscribeScreen,
} from "./screens";

const liveCfg: PortalConfig = {
  portal_url: "https://api.nilvpn.net",
  coordinator_url: "https://ctrl.nilvpn.net",
  monero_address: "",
  expected_measurement: "",
  expected_tee: "sev-snp",
  kill_switch: true,
  node_host: "",
};

function routeInvoke(overrides: Record<string, unknown> = {}) {
  const map: Record<string, unknown> = {
    status: "disconnected",
    token_balance: 0,
    get_config: liveCfg,
    ...overrides,
  };
  invokeMock.mockImplementation((cmd: string) =>
    Promise.resolve(cmd in map ? map[cmd] : undefined),
  );
}

beforeEach(() => {
  vi.useRealTimers();
  invokeMock.mockReset();
});

describe("MainScreen fail-closed token gate", () => {
  it("disables Connect when a Coordinator is configured but balance is 0", async () => {
    routeInvoke({ token_balance: 0 });
    render(<MainScreen onError={() => {}} onNavigate={() => {}} />);
    const connect = await screen.findByRole("button", { name: /^connect$/i });
    await waitFor(() => expect(connect).toBeDisabled());
    expect(screen.getByText(/buy a one-off pass/i)).toBeInTheDocument();
  });

  it("enables Connect when a token is available", async () => {
    routeInvoke({ token_balance: 2 });
    render(<MainScreen onError={() => {}} onNavigate={() => {}} />);
    const connect = await screen.findByRole("button", { name: /^connect$/i });
    await waitFor(() => expect(connect).toBeEnabled());
  });

  it("keeps Connect disabled while an active subscription has no prefetched pass", async () => {
    routeInvoke({
      token_balance: 0,
      subscription_status: { entitlement: "active", until: 9_999_999_999 },
    });
    render(<MainScreen onError={() => {}} onNavigate={() => {}} />);
    const connect = await screen.findByRole("button", { name: /^connect$/i });
    await waitFor(() => expect(connect).toBeDisabled());
    expect(screen.getByText(/subscription active/i)).toBeInTheDocument();
    expect(screen.getByText(/passes are being prepared in the background/i)).toBeInTheDocument();
    expect(screen.getByText(/small blind-signed batches at randomized times/i)).toBeInTheDocument();
  });

  it("unlocks Connect when the local balance poll observes a background refill", async () => {
    vi.useFakeTimers();
    let localBalance = 0;
    const map: Record<string, unknown> = {
      status: "disconnected",
      get_config: liveCfg,
      subscription_status: { entitlement: "active", until: 9_999_999_999 },
    };
    invokeMock.mockImplementation((cmd: string) =>
      Promise.resolve(cmd === "token_balance" ? localBalance : map[cmd]),
    );

    const view = render(<MainScreen onError={() => {}} onNavigate={() => {}} />);
    const connect = screen.getByRole("button", { name: /^connect$/i });
    await act(async () => {
      await Promise.resolve();
    });
    expect(connect).toBeDisabled();

    localBalance = 2;
    await act(async () => {
      await vi.advanceTimersByTimeAsync(5_000);
    });
    expect(connect).toBeEnabled();
    expect(screen.getByText(/use one locally prepared private connection pass/i)).toBeInTheDocument();
    view.unmount();
    vi.useRealTimers();
  });

  it("labels empty-endpoint loopback as debug-only and not a VPN", async () => {
    routeInvoke({
      get_config: { ...liveCfg, coordinator_url: "", node_host: "" },
      token_balance: 0,
    });
    render(<MainScreen onError={() => {}} onNavigate={() => {}} />);
    const connect = await screen.findByRole("button", { name: /^connect$/i });
    await waitFor(() => expect(connect).toBeEnabled());
    expect(
      screen.getByText(/debug builds can exercise the in-memory loopback seam/i),
    ).toBeInTheDocument();
    expect(screen.getByText(/release builds refuse to connect/i)).toBeInTheDocument();
  });

  it("does not require a pass for the debug-only direct-node path", async () => {
    routeInvoke({
      get_config: { ...liveCfg, coordinator_url: "", node_host: "127.0.0.1" },
      token_balance: 0,
    });
    render(<MainScreen onError={() => {}} onNavigate={() => {}} />);
    const connect = await screen.findByRole("button", { name: /^connect$/i });
    await waitFor(() => expect(connect).toBeEnabled());
    expect(screen.getByText(/debug-only direct-node mode/i)).toBeInTheDocument();
    expect(screen.getByText(/does not consume a connection pass/i)).toBeInTheDocument();
  });

  it("allows an explicit retry when fail-closed desktop cleanup is incomplete", async () => {
    routeInvoke({ status: "disconnecting", disconnect: "disconnected" });
    render(<MainScreen onError={() => {}} onNavigate={() => {}} />);

    const retry = await screen.findByRole("button", { name: /retry cleanup/i });
    expect(retry).toBeEnabled();
    fireEvent.click(retry);

    await waitFor(() => expect(invokeMock).toHaveBeenCalledWith("disconnect", undefined));
    expect(await screen.findByRole("button", { name: /^connect$/i })).toBeInTheDocument();
  });
});

describe("SubscribeScreen", () => {
  it("starts a subscription and shows the payment reference to pay", async () => {
    routeInvoke({
      subscription_status: { entitlement: "none" },
      subscribe: "ref-abc123",
    });
    render(<SubscribeScreen onError={() => {}} onBack={() => {}} />);
    const start = await screen.findByRole("button", { name: /start subscription/i });
    await waitFor(() => expect(start).toBeEnabled());
    expect(screen.getByText(/small batches at randomized times/i)).toBeInTheDocument();
    expect(screen.getByText(/connect waits for a locally stored pass/i)).toBeInTheDocument();
    fireEvent.click(start);
    // The payment reference is shown for the user to pay, plus the activate step.
    expect(await screen.findByText("ref-abc123")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /i've paid — activate/i })).toBeInTheDocument();
  });
});

describe("BuyTokensScreen", () => {
  it("requires a payment id before claiming and forwards it", async () => {
    routeInvoke();
    const onBuy = vi.fn();
    render(<BuyTokensScreen busy={false} onBuy={onBuy} onBack={() => {}} />);
    const claim = await screen.findByRole("button", { name: /claim pass/i });
    await waitFor(() => expect(claim).toBeDisabled());
    fireEvent.change(screen.getByPlaceholderText(/payment-or-comp-id/i), {
      target: { value: "alpha-004" },
    });
    expect(claim).toBeEnabled();
    fireEvent.click(claim);
    expect(onBuy).toHaveBeenCalledWith("alpha-004");
  });
});

describe("SettingsScreen", () => {
  it("restore live defaults sets the nilvpn.net endpoints", async () => {
    routeInvoke({
      get_config: { ...liveCfg, portal_url: "http://127.0.0.1:8080", coordinator_url: "" },
    });
    render(<SettingsScreen onError={() => {}} onBack={() => {}} />);
    expect(await screen.findByDisplayValue("http://127.0.0.1:8080")).toBeInTheDocument();
    fireEvent.click(screen.getByText(/restore live defaults/i));
    expect(await screen.findByDisplayValue("https://api.nilvpn.net")).toBeInTheDocument();
    expect(screen.getByDisplayValue("https://ctrl.nilvpn.net")).toBeInTheDocument();
    expect(screen.getByText(/release builds require https/i)).toBeInTheDocument();
    expect(screen.getByText(/loopback seam in debug builds only/i)).toBeInTheDocument();
  });
});

describe("RecoverAccountScreen", () => {
  it("enables Recover only with exactly 12 words", () => {
    const onSubmit = vi.fn();
    render(<RecoverAccountScreen busy={false} onSubmit={onSubmit} onBack={() => {}} />);
    const btn = screen.getByRole("button", { name: /^recover$/i });
    expect(btn).toBeDisabled();
    fireEvent.change(screen.getByPlaceholderText(/word1 word2/i), {
      target: {
        value: "alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima",
      },
    });
    expect(btn).toBeEnabled();
    fireEvent.click(btn);
    expect(onSubmit).toHaveBeenCalledWith(
      [
        "alpha",
        "bravo",
        "charlie",
        "delta",
        "echo",
        "foxtrot",
        "golf",
        "hotel",
        "india",
        "juliet",
        "kilo",
        "lima",
      ],
    );
  });
});
