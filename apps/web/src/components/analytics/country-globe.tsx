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
const GLOBE_HEIGHT = 390;
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
    });
    observer.observe(element);

    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    const controls = globeRef.current?.controls();

    if (!controls) {
      return;
    }

    controls.autoRotate = true;
    controls.autoRotateSpeed = playback?.isLive ? 0.32 : 0.18;
    controls.enableDamping = true;
    controls.dampingFactor = 0.08;
    controls.minDistance = 170;
    controls.maxDistance = 520;
  }, [playback?.isLive, canRenderWebGl]);

  function focusCountry(country: GlobeCountry) {
    setPinnedCountryKey(country.key);
    globeRef.current?.pointOfView(
      {
        lat: country.lat,
        lng: country.lng,
        altitude: 1.7,
      },
      780,
    );
  }

  function resetView() {
    setPinnedCountryKey(null);
    setHoveredCountryKey(null);
    globeRef.current?.pointOfView({ lat: 18, lng: -28, altitude: 2.35 }, 760);
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
  }

  return (
    <section className="rounded-[14px] border border-primary/16 bg-[linear-gradient(180deg,rgba(255,255,255,0.035),rgba(255,255,255,0))] p-4 shadow-[0_18px_40px_rgba(0,0,0,0.2)] sm:p-5">
      <div className="flex flex-wrap items-center justify-end gap-3">
        <div className="flex items-center gap-1.5">
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
      </div>

      <div
        ref={containerRef}
        role="img"
        aria-label="Interactive 3D globe of verified Bitcoin nodes aggregated by country"
        className="relative mt-4 min-h-[27rem] overflow-hidden rounded-[12px] border border-primary/14 bg-black"
      >
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
              height={GLOBE_HEIGHT}
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
              onGlobeReady={resetView}
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
            className="rounded-[9px] border border-border/70 bg-background/48 px-3 py-2 text-left outline-none transition-colors hover:border-primary/35 focus-visible:ring-2 focus-visible:ring-ring"
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
