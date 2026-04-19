function resolveApiBaseUrl(): string {
  const configured = import.meta.env.VITE_API_BASE_URL?.trim();

  if (configured) {
    return configured.replace(/\/+$/, "");
  }

  if (import.meta.env.DEV) {
    return "http://127.0.0.1:8080";
  }

  return "https://api.btcnetwork.info";
}

export async function fetchJson<T>(path: string): Promise<T> {
  const response = await fetch(`${resolveApiBaseUrl()}${path}`, {
    method: "GET",
    headers: {
      Accept: "application/json",
    },
  });

  if (!response.ok) {
    let message = `Request failed with ${response.status}`;

    try {
      const body = (await response.json()) as
        | { error?: string }
        | { error?: { message?: string } };
      if (typeof body.error === "string") {
        message = body.error;
      } else if (body.error?.message) {
        message = body.error.message;
      }
    } catch {
      // Keep the fallback message when the body is not valid JSON.
    }

    throw new Error(message);
  }

  return (await response.json()) as T;
}

export function apiBaseUrl(): string {
  return resolveApiBaseUrl();
}
