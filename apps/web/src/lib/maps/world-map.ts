import worldMapJson from "./world-low-res.json";

export type MapPoint = {
  x: number;
  y: number;
};

export type GeoPoint = {
  lat: number;
  lon: number;
};

export type CountryGeoLayer = {
  id: string;
  name: string;
  rings: GeoPoint[][];
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
let WORLD_LAND_GEO_LAYERS: CountryGeoLayer[] | null = null;
const ISO_COUNTRY_GEO_ANCHORS: Record<string, GeoPoint> = {
  ae: { lat: 23.42, lon: 53.85 },
  ar: { lat: -38.42, lon: -63.62 },
  at: { lat: 47.52, lon: 14.55 },
  au: { lat: -25.27, lon: 133.78 },
  be: { lat: 50.5, lon: 4.47 },
  br: { lat: -14.24, lon: -51.93 },
  ca: { lat: 56.13, lon: -106.35 },
  ch: { lat: 46.82, lon: 8.23 },
  cl: { lat: -35.68, lon: -71.54 },
  co: { lat: 4.57, lon: -74.3 },
  cz: { lat: 49.82, lon: 15.47 },
  de: { lat: 51.16, lon: 10.45 },
  dk: { lat: 56.26, lon: 9.5 },
  es: { lat: 40.46, lon: -3.75 },
  fi: { lat: 61.92, lon: 25.75 },
  fr: { lat: 46.23, lon: 2.21 },
  gb: { lat: 55.38, lon: -3.44 },
  hk: { lat: 22.32, lon: 114.17 },
  id: { lat: -0.79, lon: 113.92 },
  ie: { lat: 53.41, lon: -8.24 },
  in: { lat: 20.59, lon: 78.96 },
  ir: { lat: 32.43, lon: 53.69 },
  is: { lat: 64.96, lon: -19.02 },
  it: { lat: 41.87, lon: 12.57 },
  jp: { lat: 36.2, lon: 138.25 },
  ke: { lat: -0.02, lon: 37.91 },
  mx: { lat: 23.63, lon: -102.55 },
  nl: { lat: 52.13, lon: 5.29 },
  no: { lat: 60.47, lon: 8.47 },
  nz: { lat: -40.9, lon: 174.89 },
  pe: { lat: -9.19, lon: -75.02 },
  ph: { lat: 12.88, lon: 121.77 },
  pl: { lat: 51.92, lon: 19.15 },
  pt: { lat: 39.4, lon: -8.22 },
  ru: { lat: 61.52, lon: 105.32 },
  se: { lat: 60.13, lon: 18.64 },
  sg: { lat: 1.35, lon: 103.82 },
  th: { lat: 15.87, lon: 100.99 },
  tn: { lat: 33.89, lon: 9.54 },
  ug: { lat: 1.37, lon: 32.29 },
  us: { lat: 39.5, lon: -98.35 },
  za: { lat: -30.56, lon: 22.94 },
  zm: { lat: -13.13, lon: 27.85 },
};
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

export function getCountryGeoAnchor(countryCode: string): GeoPoint | null {
  const normalizedCountryCode = countryCode.toLowerCase();
  const isoAnchor = ISO_COUNTRY_GEO_ANCHORS[normalizedCountryCode];

  if (isoAnchor) {
    return isoAnchor;
  }

  const anchor = getCountryVisualAnchor(countryCode);

  if (!anchor) {
    return null;
  }

  return mapPointToGeoPoint(anchor);
}

export function getWorldLandGeoLayers(): CountryGeoLayer[] {
  if (WORLD_LAND_GEO_LAYERS) {
    return WORLD_LAND_GEO_LAYERS;
  }

  WORLD_LAND_GEO_LAYERS = worldMap.layers
    .map((layer) => ({
      id: layer.id.toLowerCase(),
      name: layer.name,
      rings: parseWorldPathRings(layer.d),
    }))
    .filter((layer) => layer.rings.length > 0);

  return WORLD_LAND_GEO_LAYERS;
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

function parseWorldPathRings(pathData: string): GeoPoint[][] {
  const tokens = pathData.match(/[A-Za-z]|-?\d*\.?\d+(?:e[-+]?\d+)?/gi) ?? [];
  const rings: GeoPoint[][] = [];
  let command = "";
  let tokenIndex = 0;
  let x = 0;
  let y = 0;
  let currentRing: GeoPoint[] = [];

  function closeCurrentRing() {
    if (currentRing.length >= 3) {
      rings.push(currentRing);
    }

    currentRing = [];
  }

  while (tokenIndex < tokens.length) {
    const token = tokens[tokenIndex];

    if (isPathCommand(token)) {
      command = token;
      tokenIndex += 1;

      if (command === "z" || command === "Z") {
        closeCurrentRing();
        continue;
      }
    }

    if (command === "m" || command === "M") {
      let firstPair = true;

      while (hasNumberPair(tokens, tokenIndex)) {
        const nextX = Number(tokens[tokenIndex]);
        const nextY = Number(tokens[tokenIndex + 1]);
        tokenIndex += 2;

        if (command === "m") {
          x += nextX;
          y += nextY;
        } else {
          x = nextX;
          y = nextY;
        }

        if (firstPair) {
          closeCurrentRing();
          firstPair = false;
        }

        currentRing.push(rawWorldPointToGeoPoint({ x, y }));
      }

      command = command === "m" ? "l" : "L";
      continue;
    }

    if (command === "l" || command === "L") {
      while (hasNumberPair(tokens, tokenIndex)) {
        const nextX = Number(tokens[tokenIndex]);
        const nextY = Number(tokens[tokenIndex + 1]);
        tokenIndex += 2;

        if (command === "l") {
          x += nextX;
          y += nextY;
        } else {
          x = nextX;
          y = nextY;
        }

        currentRing.push(rawWorldPointToGeoPoint({ x, y }));
      }

      continue;
    }

    tokenIndex += 1;
  }

  closeCurrentRing();

  return rings;
}

function rawWorldPointToGeoPoint(point: MapPoint): GeoPoint {
  const xRatio = clampRatio((point.x - WORLD_MAP_MIN_X) / WORLD_MAP_WIDTH);
  const yRatio = clampRatio((point.y - WORLD_MAP_MIN_Y) / WORLD_MAP_HEIGHT);

  return {
    lat: 90 - yRatio * 180,
    lon: xRatio * 360 - 180,
  };
}

function mapPointToGeoPoint(point: MapPoint): GeoPoint {
  const xRatio = clampRatio((point.x - WORLD_MAP_FRAME.x) / WORLD_MAP_FRAME.width);
  const yRatio = clampRatio((point.y - WORLD_MAP_FRAME.y) / WORLD_MAP_FRAME.height);

  return {
    lat: 90 - yRatio * 180,
    lon: xRatio * 360 - 180,
  };
}

function hasNumberPair(tokens: string[], tokenIndex: number) {
  return tokenIndex + 1 < tokens.length && !isPathCommand(tokens[tokenIndex]) && !isPathCommand(tokens[tokenIndex + 1]);
}

function isPathCommand(token: string) {
  return /^[A-Za-z]$/.test(token);
}

function clampRatio(value: number) {
  if (value < 0) {
    return 0;
  }

  if (value > 1) {
    return 1;
  }

  return value;
}

function hashString(value: string) {
  let hash = 0;

  for (let index = 0; index < value.length; index += 1) {
    hash = (hash * 31 + value.charCodeAt(index)) >>> 0;
  }

  return hash;
}
