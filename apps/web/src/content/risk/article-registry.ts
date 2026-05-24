import identityConcentrationMarkdown from "./articles/identity-concentration.md?raw";

export type RiskArticleMetadata = {
  id: string;
  title: string;
  category: string;
  status: "draft" | "planned" | "ready";
  summary: string;
};

export type RiskArticleNavItem = {
  id: string;
  label: string;
};

export type RiskArticleBlock =
  | { type: "paragraph"; text: string }
  | { type: "list"; items: string[] }
  | { type: "widget"; widgetType: string; props: Record<string, string> };

export type RiskArticleSection = {
  id: string;
  label: string;
  blocks: RiskArticleBlock[];
};

export type RiskArticleDocument = RiskArticleMetadata & {
  navItems: RiskArticleNavItem[];
  sections: RiskArticleSection[];
};

export const riskArticlesById = {
  "identity-concentration": parseRiskArticleMarkdown(identityConcentrationMarkdown),
} satisfies Record<string, RiskArticleDocument>;

export const identityConcentrationArticle = riskArticlesById["identity-concentration"];

function parseRiskArticleMarkdown(markdown: string): RiskArticleDocument {
  const { frontmatter, body } = splitFrontmatter(markdown);
  const sections: RiskArticleSection[] = [];
  let currentSection: RiskArticleSection | null = null;
  let paragraphLines: string[] = [];
  let listItems: string[] = [];

  function flushParagraph() {
    if (!currentSection || paragraphLines.length === 0) {
      return;
    }

    currentSection.blocks.push({
      type: "paragraph",
      text: paragraphLines.join(" ").trim(),
    });
    paragraphLines = [];
  }

  function flushList() {
    if (!currentSection || listItems.length === 0) {
      return;
    }

    currentSection.blocks.push({ type: "list", items: listItems });
    listItems = [];
  }

  for (const rawLine of body.split(/\r?\n/)) {
    const line = rawLine.trim();
    const headingMatch = line.match(/^#\s+(.+)$/);
    const widgetMatch = line.match(/^::widget\{(.+)\}$/);
    const listMatch = line.match(/^-\s+(.+)$/);

    if (headingMatch) {
      flushParagraph();
      flushList();
      currentSection = {
        id: slugify(headingMatch[1]),
        label: headingMatch[1],
        blocks: [],
      };
      sections.push(currentSection);
      continue;
    }

    if (!currentSection) {
      continue;
    }

    if (line.length === 0) {
      flushParagraph();
      flushList();
      continue;
    }

    if (widgetMatch) {
      flushParagraph();
      flushList();
      const props = parseWidgetProps(widgetMatch[1]);
      const widgetType = props.type;
      delete props.type;
      currentSection.blocks.push({ type: "widget", widgetType, props });
      continue;
    }

    if (listMatch) {
      flushParagraph();
      listItems.push(listMatch[1]);
      continue;
    }

    flushList();
    paragraphLines.push(line);
  }

  flushParagraph();
  flushList();

  return {
    id: requiredFrontmatter(frontmatter, "id"),
    title: requiredFrontmatter(frontmatter, "title"),
    category: requiredFrontmatter(frontmatter, "category"),
    status: parseStatus(requiredFrontmatter(frontmatter, "status")),
    summary: requiredFrontmatter(frontmatter, "summary"),
    navItems: sections.map((section) => ({
      id: section.id,
      label: section.label,
    })),
    sections,
  };
}

function splitFrontmatter(markdown: string): {
  frontmatter: Record<string, string>;
  body: string;
} {
  const match = markdown.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n([\s\S]*)$/);

  if (!match) {
    throw new Error("Risk article Markdown must start with frontmatter.");
  }

  const frontmatter: Record<string, string> = {};

  for (const rawLine of match[1].split(/\r?\n/)) {
    const [key, ...valueParts] = rawLine.split(":");
    const value = valueParts.join(":").trim();

    if (key && value) {
      frontmatter[key.trim()] = stripQuotes(value);
    }
  }

  return { frontmatter, body: match[2] };
}

function parseWidgetProps(rawProps: string): Record<string, string> {
  const props: Record<string, string> = {};
  const propPattern = /([a-zA-Z][\w-]*)="([^"]*)"/g;
  let match = propPattern.exec(rawProps);

  while (match) {
    props[match[1]] = match[2];
    match = propPattern.exec(rawProps);
  }

  if (!props.type) {
    throw new Error(`Risk article widget is missing a type: ${rawProps}`);
  }

  return props;
}

function requiredFrontmatter(frontmatter: Record<string, string>, key: string): string {
  const value = frontmatter[key];

  if (!value) {
    throw new Error(`Risk article frontmatter is missing "${key}".`);
  }

  return value;
}

function parseStatus(status: string): RiskArticleMetadata["status"] {
  if (status === "draft" || status === "planned" || status === "ready") {
    return status;
  }

  throw new Error(`Unsupported risk article status "${status}".`);
}

function slugify(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

function stripQuotes(value: string): string {
  return value.replace(/^["']|["']$/g, "");
}
