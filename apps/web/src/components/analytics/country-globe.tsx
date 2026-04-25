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
import type { CrawlerSignalPlayback } from "@/components/crawler-live-signal";
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
const DEFAULT_GLOBE_HEIGHT = 520;
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
  playback: CrawlerSignalPlayback | null;
};

export function CountryGlobe({ countries, playback }: CountryGlobeProps) {
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
      setHeight(Math.max(420, Math.round(entry.contentRect.height)));
    });
    observer.observe(element);

    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    configureGlobeControls();
  }, [playback?.isLive, canRenderWebGl]);

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
    globeRef.current?.pointOfView({ lat: 18, lng: -28, altitude: 2.35 }, 760);
    window.setTimeout(configureGlobeControls, 800);
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
        className="relative min-h-[30rem] flex-1 overflow-hidden rounded-[12px] border border-primary/14 bg-black xl:min-h-[34rem]"
      >
        <div className="absolute right-3 top-3 z-10 flex items-center gap-1.5 rounded-[9px] border border-border/60 bg-background/60 p-1.5 shadow-[0_12px_26px_rgba(0,0,0,0.24)] backdrop-blur">
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

        <div className="absolute left-3 top-3 z-10 rounded-[9px] border border-primary/20 bg-[linear-gradient(180deg,rgba(10,10,10,0.86),rgba(10,10,10,0.66))] px-3 py-2 shadow-[0_12px_26px_rgba(0,0,0,0.28)]">
          <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.16em] text-primary">
            {activeCountry?.country ?? "Crawler sweep"}
          </p>
          <p className="mt-1 font-mono text-sm text-foreground">
            {activeCountry ? `${formatCount(activeCountry.nodeCount)} nodes` : `${Math.round(populationRatio * 100)}% populated`}
          </p>
          <p className="mt-1 text-[11px] text-muted-foreground">
            {activeCountry ? `Rank ${activeCountry.rank} of ${globeCountries.length}` : "Drag rotate · wheel zoom"}
          </p>
        </div>

        {canRenderWebGl ? (
          <Suspense fallback={<GlobeFallback message="Loading WebGL globe." />}>
            <Globe
              ref={globeRef}
              width={width}
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
              onLabelHover={(country) => setHoveredCountryKey(country ? (country as GlobeCountry).key : null)}
              onLabelClick={(country) => focusCountry(country as GlobeCountry)}
              showPointerCursor
              onGlobeReady={() => {
                resetView();
                configureGlobeControls();
              }}
            />
          </Suspense>
        ) : (
          <GlobeFallback message="WebGL unavailable. Showing country replay controls and ranked buckets." />
        )}

        <div className="pointer-events-none absolute bottom-3 left-3 right-3 z-10 flex flex-wrap items-center justify-between gap-2 rounded-[9px] border border-border/60 bg-background/55 px-3 py-2 backdrop-blur">
          <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-muted-foreground">
            react-globe.gl · country labels · aggregate nodes
          </p>
          <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-primary">
            {Math.round(populationRatio * 100)}% replay populated
          </p>
        </div>
      </div>

      <div className="mt-3 grid gap-2 sm:grid-cols-3">
        {globeCountries.slice(0, 3).map((country) => (
          <button
            key={`country-shortcut-${country.key}`}
            type="button"
            className="cursor-pointer rounded-[9px] border border-border/70 bg-background/48 px-3 py-2 text-left outline-none transition-colors hover:border-primary/35 hover:bg-muted/40 focus-visible:ring-2 focus-visible:ring-ring"
            onClick={() => focusCountry(country)}
          >
            <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">
              {country.country}
            </p>
            <p className="mt-1 font-mono text-sm text-foreground">{formatCount(country.nodeCount)}</p>
          </button>
        ))}
      </div>
    </section>
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
    <div className="relative z-10 flex min-h-[27rem] items-center justify-center px-6 text-center">
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
