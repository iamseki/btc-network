function normalizedFlag(value: string | undefined): string {
  return value?.trim().toLowerCase() ?? "";
}

export function isDemoModeEnabled(): boolean {
  const flag = normalizedFlag(import.meta.env.VITE_DEMO_MODE);
  return flag === "1" || flag === "true" || flag === "yes" || flag === "on";
}

export function analyticsModeLabel(): string {
  return isDemoModeEnabled() ? "Public Demo Mode" : "Public Read-Only Analytics";
}
