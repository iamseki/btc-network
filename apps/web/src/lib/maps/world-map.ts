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
export const WORLD_MAP_LAYER_INDEX = new Map(
  worldMap.layers.map((layer) => [layer.id.toLowerCase(), layer]),
);
export const WORLD_COUNTRY_VISUAL_ANCHORS: Record<string, MapPoint> = {
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

export function getCountryVisualAnchor(countryCode: string): MapPoint | null {
  return WORLD_COUNTRY_VISUAL_ANCHORS[countryCode.toLowerCase()] ?? null;
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

function hashString(value: string) {
  let hash = 0;

  for (let index = 0; index < value.length; index += 1) {
    hash = (hash * 31 + value.charCodeAt(index)) >>> 0;
  }

  return hash;
}
