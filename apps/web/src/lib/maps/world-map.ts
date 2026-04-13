import worldMapJson from "./world-low-res.json";

export type MapPoint = {
  x: number;
  y: number;
};

type CountryNodeInput = {
  countryCode: string;
  lat: number;
  lon: number;
  city: string;
  asnLabel: string;
};

export const worldMap = worldMapJson;
export const WORLD_MAP_VIEWBOX = worldMap.viewBox;
export const WORLD_MAP_FRAME = {
  x: 10,
  y: 10,
  width: 364,
  height: 208,
} as const;
const [WORLD_MAP_MIN_X, WORLD_MAP_MIN_Y, WORLD_MAP_WIDTH, WORLD_MAP_HEIGHT] = WORLD_MAP_VIEWBOX
  .split(/\s+/)
  .map(Number);
export const WORLD_MAP_LAYER_INDEX = new Map(
  worldMap.layers.map((layer) => [layer.id.toLowerCase(), layer]),
);
const FALLBACK_WORLD_COUNTRY_VISUAL_ANCHORS: Record<string, MapPoint> = {
  ae: { x: 252, y: 116 },
  ar: { x: 119, y: 185 },
  au: { x: 321, y: 186 },
  br: { x: 124, y: 151 },
  ca: { x: 82, y: 58 },
  cl: { x: 102, y: 174 },
  co: { x: 96, y: 130 },
  de: { x: 193, y: 82 },
  gb: { x: 181, y: 74 },
  hk: { x: 318, y: 118 },
  id: { x: 317, y: 161 },
  in: { x: 271, y: 119 },
  ir: { x: 242, y: 101 },
  is: { x: 159, y: 48 },
  jp: { x: 343, y: 100 },
  ke: { x: 223, y: 151 },
  mx: { x: 67, y: 110 },
  nz: { x: 351, y: 208 },
  pe: { x: 102, y: 151 },
  ph: { x: 338, y: 131 },
  pt: { x: 172, y: 90 },
  ru: { x: 268, y: 56 },
  se: { x: 208, y: 54 },
  sg: { x: 319, y: 154 },
  th: { x: 305, y: 128 },
  tn: { x: 201, y: 106 },
  ug: { x: 218, y: 145 },
  us: { x: 75, y: 84 },
  za: { x: 216, y: 194 },
  zm: { x: 216, y: 173 },
};

let measurementSvg: SVGSVGElement | null = null;
const COMPUTED_WORLD_COUNTRY_ANCHORS = new Map<string, MapPoint | null>();

export function getCountryVisualAnchor(countryCode: string): MapPoint | null {
  const normalizedCountryCode = countryCode.toLowerCase();

  if (COMPUTED_WORLD_COUNTRY_ANCHORS.has(normalizedCountryCode)) {
    return COMPUTED_WORLD_COUNTRY_ANCHORS.get(normalizedCountryCode) ?? null;
  }

  const computedAnchor = computeCountryVisualAnchor(normalizedCountryCode);
  const anchor = computedAnchor ?? FALLBACK_WORLD_COUNTRY_VISUAL_ANCHORS[normalizedCountryCode] ?? null;

  COMPUTED_WORLD_COUNTRY_ANCHORS.set(normalizedCountryCode, anchor);

  return anchor;
}

export function projectCountryNode(seed: CountryNodeInput): MapPoint {
  const anchor = getCountryVisualAnchor(seed.countryCode) ?? fallbackCountryVisualAnchor(seed.lat, seed.lon);
  const offset = getCountryNodeOffset(seed);

  return {
    x: anchor.x + offset.x,
    y: anchor.y + offset.y,
  };
}

export function fallbackCountryVisualAnchor(lat: number, lon: number): MapPoint {
  return {
    x: WORLD_MAP_FRAME.x + ((lon + 180) / 360) * WORLD_MAP_FRAME.width,
    y: WORLD_MAP_FRAME.y + ((90 - lat) / 180) * WORLD_MAP_FRAME.height,
  };
}

function getCountryNodeOffset(seed: CountryNodeInput): MapPoint {
  const hash = hashString(`${seed.countryCode}:${seed.city}:${seed.asnLabel}`);
  const angle = ((hash % 360) * Math.PI) / 180;
  const radius = 2.5 + ((hash >> 8) % 8);

  return {
    x: Math.cos(angle) * radius,
    y: Math.sin(angle) * radius * 0.72,
  };
}

function computeCountryVisualAnchor(countryCode: string): MapPoint | null {
  const layer = WORLD_MAP_LAYER_INDEX.get(countryCode);

  if (!layer) {
    return null;
  }

  const path = createMeasurementPath(layer.d);

  if (!path) {
    return null;
  }

  try {
    const bbox = path.getBBox();
    const point = findRepresentativePoint(path, bbox);

    if (!point) {
      return null;
    }

    return {
      x: WORLD_MAP_FRAME.x + ((point.x - WORLD_MAP_MIN_X) / WORLD_MAP_WIDTH) * WORLD_MAP_FRAME.width,
      y: WORLD_MAP_FRAME.y + ((point.y - WORLD_MAP_MIN_Y) / WORLD_MAP_HEIGHT) * WORLD_MAP_FRAME.height,
    };
  } catch {
    return null;
  } finally {
    path.remove();
  }
}

function createMeasurementPath(pathData: string) {
  const svg = ensureMeasurementSvg();

  if (!svg) {
    return null;
  }

  const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
  path.setAttribute("d", pathData);
  svg.appendChild(path);

  if (typeof path.getBBox !== "function") {
    path.remove();
    return null;
  }

  return path;
}

function ensureMeasurementSvg() {
  if (measurementSvg) {
    return measurementSvg;
  }

  if (typeof document === "undefined") {
    return null;
  }

  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", WORLD_MAP_VIEWBOX);
  svg.setAttribute("width", WORLD_MAP_WIDTH.toString());
  svg.setAttribute("height", WORLD_MAP_HEIGHT.toString());
  svg.setAttribute("aria-hidden", "true");
  svg.style.position = "absolute";
  svg.style.width = "0";
  svg.style.height = "0";
  svg.style.opacity = "0";
  svg.style.pointerEvents = "none";
  svg.style.overflow = "hidden";

  document.body.appendChild(svg);
  measurementSvg = svg;

  return measurementSvg;
}

function findRepresentativePoint(path: SVGPathElement, bbox: DOMRect) {
  const center = { x: bbox.x + bbox.width / 2, y: bbox.y + bbox.height / 2 };

  if (isPointInsidePath(path, center.x, center.y)) {
    return center;
  }

  let bestPoint: MapPoint | null = null;
  let bestDistance = Number.POSITIVE_INFINITY;
  let candidateBounds = {
    minX: bbox.x,
    maxX: bbox.x + bbox.width,
    minY: bbox.y,
    maxY: bbox.y + bbox.height,
  };

  for (const steps of [12, 16, 20]) {
    let nextBestPoint: MapPoint | null = bestPoint;
    let nextBestDistance = bestDistance;

    for (let xIndex = 0; xIndex <= steps; xIndex += 1) {
      const x = interpolate(candidateBounds.minX, candidateBounds.maxX, xIndex / steps);

      for (let yIndex = 0; yIndex <= steps; yIndex += 1) {
        const y = interpolate(candidateBounds.minY, candidateBounds.maxY, yIndex / steps);

        if (!isPointInsidePath(path, x, y)) {
          continue;
        }

        const distance = Math.hypot(x - center.x, y - center.y);

        if (distance < nextBestDistance) {
          nextBestDistance = distance;
          nextBestPoint = { x, y };
        }
      }
    }

    if (!nextBestPoint) {
      continue;
    }

    bestPoint = nextBestPoint;
    bestDistance = nextBestDistance;
    candidateBounds = {
      minX: Math.max(bbox.x, nextBestPoint.x - bbox.width / (steps + 2)),
      maxX: Math.min(bbox.x + bbox.width, nextBestPoint.x + bbox.width / (steps + 2)),
      minY: Math.max(bbox.y, nextBestPoint.y - bbox.height / (steps + 2)),
      maxY: Math.min(bbox.y + bbox.height, nextBestPoint.y + bbox.height / (steps + 2)),
    };
  }

  return bestPoint;
}

function isPointInsidePath(path: SVGPathElement, x: number, y: number) {
  const geometryPath = path as SVGGeometryElement & {
    isPointInFill?: (point?: DOMPointInit) => boolean;
  };

  if (typeof geometryPath.isPointInFill !== "function") {
    return false;
  }

  return geometryPath.isPointInFill({ x, y });
}

function interpolate(start: number, end: number, ratio: number) {
  return start + (end - start) * ratio;
}

function hashString(value: string) {
  let hash = 0;

  for (let index = 0; index < value.length; index += 1) {
    hash = (hash * 31 + value.charCodeAt(index)) >>> 0;
  }

  return hash;
}
