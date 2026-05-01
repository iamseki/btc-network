import { Minus, Plus, RotateCcw } from "lucide-react";
import {
  type ComponentType,
  lazy,
  type ReactNode,
  type Ref,
  Suspense,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import type { GlobeMethods, GlobeProps } from "react-globe.gl";

import { Button } from "@/components/ui/button";
import type { LastRunCountryCountItem } from "@/lib/api/types";
import { getCountryGeoAnchor } from "@/lib/maps/world-map";

const EARTH_IMAGE_URL = new URL("../../../node_modules/three-globe/example/img/earth-day.jpg", import.meta.url).href;
const Globe = lazy(
  () =>
    import("react-globe.gl") as Promise<{
      default: ComponentType<GlobeProps & { ref?: Ref<GlobeMethods> }>;
    }>,
);

const DEFAULT_GLOBE_WIDTH = 760;
const DEFAULT_GLOBE_HEIGHT = 420;
const COUNTRY_LIMIT = 32;

type GlobeCountry = {
  key: string;
  country: string;
  nodeCount: number;
  lat: number;
  lng: number;
  rank: number;
};

type CountryGlobeProps = {
  countries: LastRunCountryCountItem[];
  playback: CountryGlobePlayback | null;
  variant?: "analytics" | "preview";
  interactive?: boolean;
  summaryNodeCount?: number;
};

type CountryGlobePlayback = {
  isLive: boolean;
  playbackSnapshot: {
    successfulHandshakes: number;
  };
  finalSnapshot: {
    successfulHandshakes: number;
  };
};

export function CountryGlobe({
  countries,
  playback,
  variant = "analytics",
  interactive = true,
  summaryNodeCount,
}: CountryGlobeProps) {
  const globeRef = useRef<GlobeMethods | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const autoRotateEnabledRef = useRef(true);
  const defaultViewAppliedRef = useRef(false);
  const ignoreNextGlobeClickRef = useRef(false);
  const rotationFrameRef = useRef<number | null>(null);
  const [width, setWidth] = useState(DEFAULT_GLOBE_WIDTH);
  const [height, setHeight] = useState(DEFAULT_GLOBE_HEIGHT);
  const [canRenderWebGl, setCanRenderWebGl] = useState(false);
  const [hoveredCountryKey, setHoveredCountryKey] = useState<string | null>(null);
  const [pinnedCountryKey, setPinnedCountryKey] = useState<string | null>(null);
  const globeCountries = useMemo(() => buildGlobeCountries(countries), [countries]);
  const maxNodes = Math.max(1, ...globeCountries.map((country) => country.nodeCount));
  const countryMap = useMemo(
    () => new Map(globeCountries.map((country) => [country.key, country])),
    [globeCountries],
  );
  const populationRatio = playback
    ? Math.max(0.08, progressRatio(playback.playbackSnapshot.successfulHandshakes, playback.finalSnapshot.successfulHandshakes))
    : 1;
  const visibleLimit = Math.max(1, Math.ceil(globeCountries.length * populationRatio));
  const revealedCountries = globeCountries.slice(0, visibleLimit);
  const activeCountryKey = pinnedCountryKey ?? hoveredCountryKey;
  const activeCountry = activeCountryKey ? countryMap.get(activeCountryKey) ?? null : null;
  const isCompactGlobe = width < 520;
  const renderWidth = isCompactGlobe ? Math.max(width, Math.round(height * 1.12)) : width;
  const isPreview = variant === "preview";
  const autoRotateSpeed = playback?.isLive ? 0.22 : 0.14;
  const frameClass = isPreview
    ? "relative isolate min-h-[18rem] flex-1 overflow-hidden rounded-[12px] border border-primary/14 bg-black sm:min-h-[31rem]"
    : "relative isolate min-h-[22rem] flex-1 overflow-hidden rounded-[12px] border border-primary/14 bg-black sm:min-h-[26rem] lg:min-h-[30rem] xl:min-h-[34rem]";

  const configureGlobeControls = useCallback(() => {
    const controls = globeRef.current?.controls();

    if (!controls) {
      return;
    }

    controls.autoRotate = autoRotateEnabledRef.current;
    controls.autoRotateSpeed = autoRotateSpeed;
    controls.enableDamping = true;
    controls.dampingFactor = 0.08;
    controls.minDistance = 170;
    controls.maxDistance = 520;
  }, [autoRotateSpeed]);

  const stopAutoRotateSmoothly = useCallback(() => {
    autoRotateEnabledRef.current = false;

    if (rotationFrameRef.current !== null) {
      window.cancelAnimationFrame(rotationFrameRef.current);
      rotationFrameRef.current = null;
    }

    const controls = globeRef.current?.controls();

    if (!controls) {
      return;
    }

    const startSpeed = Math.max(controls.autoRotateSpeed || autoRotateSpeed, autoRotateSpeed);
    const startedAt = performance.now();
    const durationMs = 520;
    controls.autoRotate = true;

    const tick = (now: number) => {
      const progress = clamp((now - startedAt) / durationMs, 0, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      controls.autoRotateSpeed = startSpeed * (1 - eased);

      if (progress < 1) {
        rotationFrameRef.current = window.requestAnimationFrame(tick);
        return;
      }

      controls.autoRotate = false;
      controls.autoRotateSpeed = autoRotateSpeed;
      rotationFrameRef.current = null;
    };

    rotationFrameRef.current = window.requestAnimationFrame(tick);
  }, [autoRotateSpeed]);

  const resumeAutoRotate = useCallback(() => {
    autoRotateEnabledRef.current = true;

    if (rotationFrameRef.current !== null) {
      window.cancelAnimationFrame(rotationFrameRef.current);
      rotationFrameRef.current = null;
    }

    const controls = globeRef.current?.controls();

    if (!controls) {
      return;
    }

    controls.autoRotate = true;
    controls.autoRotateSpeed = autoRotateSpeed;
  }, [autoRotateSpeed]);

  const setDefaultView = useCallback((duration: number) => {
    globeRef.current?.pointOfView(
      {
        lat: isCompactGlobe ? 12 : 18,
        lng: isCompactGlobe ? -18 : -28,
        altitude: isCompactGlobe ? 2.7 : 2.35,
      },
      duration,
    );
  }, [isCompactGlobe]);

  const focusCountry = useCallback((country: GlobeCountry) => {
    if (!interactive) {
      return;
    }

    setPinnedCountryKey(country.key);
    stopAutoRotateSmoothly();

    globeRef.current?.pointOfView(
      {
        lat: country.lat,
        lng: country.lng,
        altitude: 1.25,
      },
      780,
    );
  }, [interactive, stopAutoRotateSmoothly]);

  const resetView = useCallback(() => {
    defaultViewAppliedRef.current = true;
    setPinnedCountryKey(null);
    setHoveredCountryKey(null);
    resumeAutoRotate();
    setDefaultView(760);
    window.setTimeout(() => {
      if (autoRotateEnabledRef.current) {
        resumeAutoRotate();
      }
    }, 820);
  }, [resumeAutoRotate, setDefaultView]);

  const clearCountryFocus = useCallback(() => {
    if (ignoreNextGlobeClickRef.current) {
      ignoreNextGlobeClickRef.current = false;
      return;
    }

    setPinnedCountryKey(null);
    setHoveredCountryKey(null);
    resumeAutoRotate();
  }, [resumeAutoRotate]);

  const zoom = useCallback((delta: number) => {
    const pov = globeRef.current?.pointOfView();

    if (!pov) {
      return;
    }

    globeRef.current?.pointOfView(
      {
        altitude: clamp(pov.altitude + delta, 1.28, 3.15),
      },
      320,
    );
    window.setTimeout(configureGlobeControls, 360);
  }, [configureGlobeControls]);

  const createCountryNodeElement = useCallback((datum: object) => {
    const country = datum as GlobeCountry;
    const isActive = pinnedCountryKey === country.key;
    const markerScale = 1.12 + Math.sqrt(country.nodeCount / maxNodes) * 0.62 + (isActive ? 0.26 : 0);
    const markerSize = 50 * markerScale;
    const countrySummary = `${country.country}: ${formatCount(country.nodeCount)} verified nodes`;
    const element = document.createElement("span");

    element.innerHTML = countryNodeMarkerSvg(isActive, country.country);
    element.setAttribute("aria-label", countrySummary);
    element.style.width = `${markerSize.toFixed(1)}px`;
    element.style.height = `${markerSize.toFixed(1)}px`;
    element.style.display = "grid";
    element.style.placeItems = "center";
    element.style.border = "0";
    element.style.padding = "0";
    element.style.background = "transparent";
    element.style.pointerEvents = "none";
    element.style.position = "relative";
    element.style.filter = isActive
      ? "drop-shadow(0 0 10px rgba(245,179,1,0.52)) drop-shadow(0 8px 8px rgba(0,0,0,0.36))"
      : "drop-shadow(0 5px 5px rgba(0,0,0,0.32))";

    if (interactive) {
      const tooltip = document.createElement("span");
      tooltip.textContent = `${country.country} • ${formatCount(country.nodeCount)} nodes`;
      tooltip.style.position = "absolute";
      tooltip.style.left = "50%";
      tooltip.style.bottom = "26%";
      tooltip.style.transform = "translate(-50%, -6px)";
      tooltip.style.whiteSpace = "nowrap";
      tooltip.style.border = "1px solid rgba(245,179,1,0.42)";
      tooltip.style.borderRadius = "8px";
      tooltip.style.background = "rgba(8,8,8,0.92)";
      tooltip.style.color = "rgba(245,239,226,0.96)";
      tooltip.style.fontFamily = "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace";
      tooltip.style.fontSize = "10px";
      tooltip.style.fontWeight = "700";
      tooltip.style.lineHeight = "1";
      tooltip.style.padding = "5px 7px";
      tooltip.style.opacity = "0";
      tooltip.style.pointerEvents = "none";
      tooltip.style.transition = "none";
      tooltip.style.zIndex = "3";
      const badgeButton = document.createElement("button");
      badgeButton.type = "button";
      badgeButton.setAttribute("aria-label", countrySummary);
      badgeButton.style.position = "absolute";
      badgeButton.style.left = "21%";
      badgeButton.style.bottom = "5%";
      badgeButton.style.width = "58%";
      badgeButton.style.height = "24%";
      badgeButton.style.border = "0";
      badgeButton.style.borderRadius = "999px";
      badgeButton.style.background = "transparent";
      badgeButton.style.cursor = "pointer";
      badgeButton.style.padding = "0";
      badgeButton.style.pointerEvents = "auto";
      badgeButton.style.zIndex = "2";
      badgeButton.addEventListener("mouseenter", () => {
        setHoveredCountryKey(country.key);
        tooltip.style.opacity = "1";
        element.style.filter = "drop-shadow(0 0 9px rgba(245,179,1,0.42)) drop-shadow(0 7px 7px rgba(0,0,0,0.36))";
      });
      badgeButton.addEventListener("mouseleave", () => {
        setHoveredCountryKey((currentKey) => (currentKey === country.key ? null : currentKey));
        tooltip.style.opacity = "0";
        element.style.filter = isActive
          ? "drop-shadow(0 0 10px rgba(245,179,1,0.52)) drop-shadow(0 8px 8px rgba(0,0,0,0.36))"
          : "drop-shadow(0 5px 5px rgba(0,0,0,0.32))";
      });
      badgeButton.addEventListener("focus", () => {
        setHoveredCountryKey(country.key);
        tooltip.style.opacity = "1";
      });
      badgeButton.addEventListener("blur", () => {
        setHoveredCountryKey((currentKey) => (currentKey === country.key ? null : currentKey));
        tooltip.style.opacity = "0";
      });
      badgeButton.addEventListener("click", (event) => {
        event.preventDefault();
        event.stopPropagation();
        ignoreNextGlobeClickRef.current = true;
        focusCountry(country);
      });
      element.appendChild(tooltip);
      element.appendChild(badgeButton);
    }

    return element;
  }, [focusCountry, interactive, maxNodes, pinnedCountryKey]);

  useEffect(() => {
    setCanRenderWebGl(hasWebGlSupport());

    return () => {
      if (rotationFrameRef.current !== null) {
        window.cancelAnimationFrame(rotationFrameRef.current);
      }
    };
  }, []);

  useEffect(() => {
    const element = containerRef.current;

    if (!element || typeof ResizeObserver === "undefined") {
      return;
    }

    const observer = new ResizeObserver(([entry]) => {
      setWidth(Math.max(320, Math.round(entry.contentRect.width)));
      setHeight(Math.max(340, Math.round(entry.contentRect.height)));
    });
    observer.observe(element);

    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    configureGlobeControls();

    if (!canRenderWebGl) {
      return;
    }

    const timers = [80, 320, 880].map((delayMs) =>
      window.setTimeout(() => {
        if (autoRotateEnabledRef.current) {
          resumeAutoRotate();
        }
      }, delayMs),
    );

    return () => {
      timers.forEach((timer) => window.clearTimeout(timer));
    };
  }, [canRenderWebGl, configureGlobeControls, resumeAutoRotate]);

  useEffect(() => {
    if (!canRenderWebGl || defaultViewAppliedRef.current) {
      return;
    }

    const timeout = window.setTimeout(() => {
      defaultViewAppliedRef.current = true;
      setDefaultView(0);
      configureGlobeControls();
    }, 80);

    return () => window.clearTimeout(timeout);
  }, [canRenderWebGl, configureGlobeControls, setDefaultView]);

  return (
    <section className="flex h-full flex-col">
      <div
        ref={containerRef}
        role="img"
        aria-label="Interactive 3D globe of verified Bitcoin nodes aggregated by country"
        className={frameClass}
      >
        {interactive ? (
          <div className="absolute right-2 top-2 z-[2] flex items-center gap-1 rounded-[9px] border border-border/60 bg-background/60 p-1 shadow-[0_12px_26px_rgba(0,0,0,0.24)] backdrop-blur sm:right-3 sm:top-3 sm:gap-1.5 sm:p-1.5">
            <GlobeControl label="Zoom out globe" onClick={() => zoom(0.22)}>
              <Minus className="h-4 w-4" />
            </GlobeControl>
            <GlobeControl label="Zoom in globe" onClick={() => zoom(-0.22)}>
              <Plus className="h-4 w-4" />
            </GlobeControl>
            <GlobeControl label="Reset globe view" onClick={resetView}>
              <RotateCcw className="h-4 w-4" />
            </GlobeControl>
          </div>
        ) : null}

        <div className="absolute left-2 top-2 z-[2] max-w-[calc(100%-7.5rem)] rounded-[9px] border border-primary/20 bg-[linear-gradient(180deg,rgba(10,10,10,0.86),rgba(10,10,10,0.66))] px-2.5 py-2 shadow-[0_12px_26px_rgba(0,0,0,0.28)] sm:left-3 sm:top-3 sm:max-w-none sm:px-3">
          <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.16em] text-primary">
            {activeCountry?.country ?? "Crawler sweep"}
          </p>
          <p className="mt-1 font-mono text-sm text-foreground">
            {activeCountry
              ? `${formatCount(activeCountry.nodeCount)} nodes`
              : summaryNodeCount
                ? `${formatCount(summaryNodeCount)} crawled`
                : `${Math.round(populationRatio * 100)}% populated`}
          </p>
          <p className="mt-1 hidden text-[11px] text-muted-foreground sm:block">
            {activeCountry ? `Rank ${activeCountry.rank} of ${globeCountries.length}` : "Drag rotate · wheel zoom"}
          </p>
        </div>

        {canRenderWebGl ? (
          <Suspense fallback={<GlobeFallback message="Loading WebGL globe." />}>
            <div className="absolute inset-0 flex items-center justify-center">
              <div style={{ width: renderWidth }}>
                <Globe
                  ref={globeRef}
                  width={renderWidth}
                  height={height}
                  backgroundColor="#000011"
                  animateIn={false}
                  waitForGlobeReady={false}
                  globeCurvatureResolution={4}
                  globeImageUrl={EARTH_IMAGE_URL}
                  htmlElementsData={revealedCountries}
                  htmlLat={(country) => (country as GlobeCountry).lat}
                  htmlLng={(country) => (country as GlobeCountry).lng}
                  htmlAltitude={0.012}
                  htmlElement={createCountryNodeElement}
                  htmlTransitionDuration={450}
                  showPointerCursor={interactive}
                  onGlobeClick={interactive ? clearCountryFocus : undefined}
                  onGlobeReady={() => {
                    resetView();
                    resumeAutoRotate();
                  }}
                />
              </div>
            </div>
          </Suspense>
        ) : (
          <GlobeFallback message="WebGL unavailable. Showing country replay controls and ranked buckets." />
        )}

        <div className="pointer-events-none absolute bottom-2 left-2 right-2 z-[2] hidden flex-wrap items-center justify-between gap-2 rounded-[9px] border border-border/60 bg-background/55 px-3 py-2 backdrop-blur sm:flex">
          <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-muted-foreground">
            react-globe.gl · country labels · aggregate nodes
          </p>
          <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-primary">
            {Math.round(populationRatio * 100)}% replay populated
          </p>
        </div>
      </div>

      <div className="mt-2 grid grid-cols-3 gap-2 sm:mt-3">
        {globeCountries.slice(0, 3).map((country) => (
          <CountryShortcut
            key={`country-shortcut-${country.key}`}
            country={country}
            interactive={interactive}
            onClick={() => focusCountry(country)}
          />
        ))}
      </div>
    </section>
  );
}

function CountryShortcut({
  country,
  interactive,
  onClick,
}: {
  country: GlobeCountry;
  interactive: boolean;
  onClick: () => void;
}) {
  const content = (
    <>
      <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">
        <span className="block truncate">{country.country}</span>
      </p>
      <p className="mt-1 truncate font-mono text-xs text-foreground sm:text-sm">{formatCount(country.nodeCount)}</p>
    </>
  );

  if (!interactive) {
    return (
      <div className="rounded-[9px] border border-border/70 bg-background/48 px-2.5 py-2 text-left sm:px-3">
        {content}
      </div>
    );
  }

  return (
    <button
      type="button"
      className="cursor-pointer rounded-[9px] border border-border/70 bg-background/48 px-2.5 py-2 text-left outline-none transition-colors hover:border-primary/35 hover:bg-muted/40 focus-visible:ring-2 focus-visible:ring-ring sm:px-3"
      onClick={onClick}
    >
      {content}
    </button>
  );
}

function GlobeControl({
  children,
  label,
  onClick,
}: {
  children: ReactNode;
  label: string;
  onClick: () => void;
}) {
  return (
    <Button
      type="button"
      variant="ghost"
      size="sm"
      className="h-8 w-8 rounded-md px-0"
      aria-label={label}
      title={label}
      onClick={onClick}
    >
      {children}
    </Button>
  );
}

function GlobeFallback({ message }: { message: string }) {
  return (
    <div className="relative z-[1] flex min-h-[22rem] items-center justify-center px-4 text-center sm:min-h-[26rem] sm:px-6">
      <div className="max-w-sm rounded-[12px] border border-primary/20 bg-background/72 p-4">
        <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-primary">
          Globe renderer
        </p>
        <p className="mt-2 text-sm leading-6 text-muted-foreground">{message}</p>
      </div>
    </div>
  );
}

function countryNodeMarkerSvg(isActive: boolean, countryCode: string) {
  const strokeOpacity = isActive ? "0.82" : "0.52";
  const glowOpacity = isActive ? "0.28" : "0.14";
  const safeCountryCode = countryCode.replace(/[^A-Z0-9]/g, "").slice(0, 3);

  return `
    <svg width="100%" height="100%" viewBox="-16 -15 32 36" aria-hidden="true" focusable="false">
      <ellipse cx="0.8" cy="7.3" rx="8.4" ry="1.9" fill="rgba(0,0,0,0.46)" />
      <path
        d="M-7 -6.9 L3.1 -6.9 L7.2 -3.6 L-3 -3.6 Z"
        fill="rgba(112,112,112,0.98)"
        stroke="rgba(9,9,9,0.98)"
        stroke-width="1.2"
        stroke-linejoin="round"
      />
      <path
        d="M2.9 -6.8 L7.2 -3.6 L7.2 6.5 L2.9 5.1 Z"
        fill="rgba(63,63,63,0.98)"
        stroke="rgba(9,9,9,0.98)"
        stroke-width="1.2"
        stroke-linejoin="round"
      />
      <rect x="-7" y="-6.8" width="10.1" height="12.4" rx="2.3" fill="rgba(18,18,18,0.98)" stroke="rgba(9,9,9,0.98)" stroke-width="1.2" />
      <path d="M-5.7 -5.4 Q-3.7 -6.4 -1.2 -6" fill="none" stroke="rgba(245,239,226,0.2)" stroke-width="0.9" stroke-linecap="round" />
      <path d="M-5.55 -5.45 L-5.55 4.2 M1.75 -5.45 L1.75 4.2" stroke="rgba(245,239,226,0.16)" stroke-width="0.58" />
      <rect x="-4.8" y="-4.75" width="5.95" height="1.85" rx="0.68" fill="rgba(49,49,49,0.98)" stroke="rgba(245,239,226,0.16)" stroke-width="0.48" />
      <rect x="-4.8" y="-1.55" width="5.95" height="1.85" rx="0.68" fill="rgba(49,49,49,0.98)" stroke="rgba(245,239,226,0.16)" stroke-width="0.48" />
      <rect x="-4.8" y="1.65" width="5.95" height="1.85" rx="0.68" fill="rgba(49,49,49,0.98)" stroke="rgba(245,239,226,0.16)" stroke-width="0.48" />
      <path d="M-3.95 -4.08 L-1.72 -4.08 M-3.95 -3.47 L-2.25 -3.47 M-3.95 -0.88 L-1.72 -0.88 M-3.95 -0.27 L-2.25 -0.27 M-3.95 2.32 L-1.72 2.32 M-3.95 2.93 L-2.25 2.93" stroke="rgba(245,239,226,0.42)" stroke-width="0.5" stroke-linecap="round" />
      <circle cx="0.25" cy="-3.84" r="0.46" fill="rgba(245,179,1,0.98)" />
      <circle cx="0.25" cy="-0.64" r="0.46" fill="rgba(245,179,1,0.98)" />
      <circle cx="0.25" cy="2.56" r="0.46" fill="rgba(245,179,1,0.98)" />
      <path d="M4.05 -3.65 L5.45 -2.55 M4.05 -1.05 L5.45 0.05 M4.05 1.55 L5.45 2.65" stroke="rgba(245,239,226,0.2)" stroke-width="0.56" stroke-linecap="round" />
      <path d="M-5.8 7.55 L5.8 7.55 Q8.9 7.55 8.9 10.35 L8.9 11.8 Q8.9 14.6 5.8 14.6 L-5.8 14.6 Q-8.9 14.6 -8.9 11.8 L-8.9 10.35 Q-8.9 7.55 -5.8 7.55 Z" fill="rgba(8,8,8,0.94)" stroke="rgba(245,179,1,${strokeOpacity})" stroke-width="1" />
      <rect x="-7.2" y="8.95" width="14.4" height="4.2" rx="1.65" fill="rgba(245,179,1,${glowOpacity})" stroke="rgba(245,179,1,${glowOpacity})" stroke-width="0.45" />
      <text x="0" y="12.25" text-anchor="middle" font-size="4.35" font-family="ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace" font-weight="900" fill="rgba(245,239,226,0.98)" letter-spacing="0.25">${safeCountryCode}</text>
    </svg>
  `;
}

function buildGlobeCountries(countries: LastRunCountryCountItem[]): GlobeCountry[] {
  return countries
    .map((country) => {
      const code = country.country.trim().toUpperCase();
      const anchor = getCountryGeoAnchor(code);

      if (!anchor) {
        return null;
      }

      return {
        key: code.toLowerCase(),
        country: code,
        nodeCount: country.nodeCount,
        lat: anchor.lat,
        lng: anchor.lon,
      };
    })
    .filter((country) => country !== null)
    .sort((left, right) => right.nodeCount - left.nodeCount)
    .slice(0, COUNTRY_LIMIT)
    .map((country, index) => ({ ...country, rank: index + 1 }));
}

function hasWebGlSupport() {
  if (typeof document === "undefined") {
    return false;
  }

  if (typeof navigator !== "undefined" && navigator.userAgent.toLowerCase().includes("jsdom")) {
    return false;
  }

  const canvas = document.createElement("canvas");

  try {
    return Boolean(canvas.getContext("webgl") ?? canvas.getContext("experimental-webgl"));
  } catch {
    return false;
  }
}

function progressRatio(current: number, total: number) {
  if (total <= 0) {
    return 0;
  }

  return clamp(current / total, 0, 1);
}

function clamp(value: number, min: number, max: number) {
  return Math.min(max, Math.max(min, value));
}

function formatCount(value: number) {
  return value.toLocaleString();
}
