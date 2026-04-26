import { Minus, Plus, RotateCcw } from "lucide-react";
import {
  type ComponentType,
  lazy,
  type ReactNode,
  type Ref,
  Suspense,
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
  const frameClass = isPreview
    ? "relative isolate min-h-[18rem] flex-1 overflow-hidden rounded-[12px] border border-primary/14 bg-black sm:min-h-[31rem]"
    : "relative isolate min-h-[22rem] flex-1 overflow-hidden rounded-[12px] border border-primary/14 bg-black sm:min-h-[26rem] lg:min-h-[30rem] xl:min-h-[34rem]";

  useEffect(() => {
    setCanRenderWebGl(hasWebGlSupport());
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
  }, [playback?.isLive, canRenderWebGl]);

  useEffect(() => {
    if (!canRenderWebGl || pinnedCountryKey) {
      return;
    }

    const timeout = window.setTimeout(() => {
      setDefaultView(0);
      configureGlobeControls();
    }, 80);

    return () => window.clearTimeout(timeout);
  }, [canRenderWebGl, height, pinnedCountryKey, width]);

  function configureGlobeControls() {
    const controls = globeRef.current?.controls();

    if (!controls) {
      return;
    }

    controls.autoRotate = true;
    controls.autoRotateSpeed = playback?.isLive ? 0.22 : 0.14;
    controls.enableDamping = true;
    controls.dampingFactor = 0.08;
    controls.minDistance = 170;
    controls.maxDistance = 520;
  }

  function focusCountry(country: GlobeCountry) {
    if (!interactive) {
      return;
    }

    setPinnedCountryKey(country.key);
    globeRef.current?.pointOfView(
      {
        lat: country.lat,
        lng: country.lng,
        altitude: 1.25,
      },
      780,
    );
    window.setTimeout(configureGlobeControls, 820);
  }

  function resetView() {
    setPinnedCountryKey(null);
    setHoveredCountryKey(null);
    setDefaultView(760);
    window.setTimeout(configureGlobeControls, 800);
  }

  function setDefaultView(duration: number) {
    globeRef.current?.pointOfView(
      {
        lat: isCompactGlobe ? 12 : 18,
        lng: isCompactGlobe ? -18 : -28,
        altitude: isCompactGlobe ? 2.7 : 2.35,
      },
      duration,
    );
  }

  function zoom(delta: number) {
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
  }

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
                  labelsData={revealedCountries}
                  labelLat={(country) => (country as GlobeCountry).lat}
                  labelLng={(country) => (country as GlobeCountry).lng}
                  labelText={(country) => (country as GlobeCountry).country}
                  labelSize={(country) => 0.34 + Math.sqrt((country as GlobeCountry).nodeCount / maxNodes) * 0.82}
                  labelDotRadius={(country) => 0.28 + Math.sqrt((country as GlobeCountry).nodeCount / maxNodes) * 0.52}
                  labelColor={(country) =>
                    activeCountryKey === (country as GlobeCountry).key
                      ? "rgba(255, 215, 128, 0.92)"
                      : "rgba(255, 165, 0, 0.75)"
                  }
                  labelAltitude={0.01}
                  labelResolution={2}
                  labelsTransitionDuration={450}
                  labelLabel={(country) => countryLabel(country as GlobeCountry)}
                  onLabelHover={interactive ? (country) => setHoveredCountryKey(country ? (country as GlobeCountry).key : null) : undefined}
                  onLabelClick={interactive ? (country) => focusCountry(country as GlobeCountry) : undefined}
                  showPointerCursor={interactive}
                  onGlobeReady={() => {
                    resetView();
                    configureGlobeControls();
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

function countryLabel(country: GlobeCountry) {
  return `<b>${country.country}</b><br/>${formatCount(country.nodeCount)} verified nodes<br/>Rank ${country.rank}`;
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
