#!/usr/bin/env node

import { Command } from "commander";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const cvss = require("cvss");

const DEPS_DEV_BASE_URL = "https://api.deps.dev/v3";
const OSV_QUERY_BATCH_URL = "https://api.osv.dev/v1/querybatch";
const OSV_VULN_DETAILS_BASE_URL = "https://api.osv.dev/v1/vulns";

const SUPPORTED_ECOSYSTEMS = {
  npm: {
    depsDevSystem: "npm",
    osvEcosystem: "npm"
  },
  java: {
    depsDevSystem: "maven",
    osvEcosystem: "Maven"
  },
  pypi: {
    depsDevSystem: "pypi",
    osvEcosystem: "PyPI"
  }
};

const DEFAULT_ECOSYSTEM = "npm";

function normalizeInput(name) {
  if (!name || typeof name !== "string") {
    return "";
  }

  return name.trim();
}

function encodePackageName(name) {
  return encodeURIComponent(name);
}

function encodeVersion(version) {
  return encodeURIComponent(version);
}

function normalizeEcosystem(ecosystem) {
  if (!ecosystem || typeof ecosystem !== "string") {
    return DEFAULT_ECOSYSTEM;
  }

  const normalized = ecosystem.trim().toLowerCase();

  if (Object.hasOwn(SUPPORTED_ECOSYSTEMS, normalized)) {
    return normalized;
  }

  return "";
}

function resolveEcosystemConfig(ecosystem) {
  const normalized = normalizeEcosystem(ecosystem);

  if (!normalized) {
    return null;
  }

  return {
    name: normalized,
    ...SUPPORTED_ECOSYSTEMS[normalized]
  };
}

async function fetchJson(url) {
  const response = await fetch(url);

  if (!response.ok) {
    throw new Error(`Erreur HTTP ${response.status} sur ${url}`);
  }

  return response.json();
}

async function resolveDefaultVersion(packageName, ecosystemConfig) {
  const url = `${DEPS_DEV_BASE_URL}/systems/${ecosystemConfig.depsDevSystem}/packages/${encodePackageName(packageName)}`;
  const data = await fetchJson(url);
  const versions = Array.isArray(data.versions) ? data.versions : [];

  if (versions.length === 0) {
    throw new Error(`Aucune version trouvée pour ${packageName}`);
  }

  const defaultVersion = versions.find((item) => item?.isDefault)?.versionKey?.version;

  if (defaultVersion) {
    return defaultVersion;
  }

  const sorted = versions
    .map((item) => ({
      version: item?.versionKey?.version,
      publishedAt: item?.publishedAt ? Date.parse(item.publishedAt) : 0
    }))
    .filter((item) => Boolean(item.version))
    .sort((a, b) => b.publishedAt - a.publishedAt);

  if (sorted.length === 0) {
    throw new Error(`Impossible de déterminer une version pour ${packageName}`);
  }

  return sorted[0].version;
}

async function resolveRootVersion(packageName, inputVersion, ecosystemConfig) {
  if (inputVersion) {
    return inputVersion;
  }

  return resolveDefaultVersion(packageName, ecosystemConfig);
}

async function fetchDependencyGraph(packageName, version, ecosystemConfig) {
  const url = `${DEPS_DEV_BASE_URL}/systems/${ecosystemConfig.depsDevSystem}/packages/${encodePackageName(packageName)}/versions/${encodeVersion(version)}:dependencies`;
  const data = await fetchJson(url);
  const nodes = Array.isArray(data.nodes) ? data.nodes : [];
  const uniquePackages = new Map();

  for (const node of nodes) {
    const name = node?.versionKey?.name;
    const nodeVersion = node?.versionKey?.version;

    if (!name || !nodeVersion) {
      continue;
    }

    uniquePackages.set(`${name}@${nodeVersion}`, {
      name,
      version: nodeVersion
    });
  }

  return Array.from(uniquePackages.values());
}

function buildOsvBatchBody(packages, ecosystemConfig) {
  return {
    queries: packages.map((dependency) => ({
      package: {
        name: dependency.name,
        ecosystem: ecosystemConfig.osvEcosystem
      },
      version: dependency.version
    }))
  };
}

async function fetchVulnerabilitiesBatch(packages, ecosystemConfig) {
  const response = await fetch(OSV_QUERY_BATCH_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(buildOsvBatchBody(packages, ecosystemConfig))
  });

  if (!response.ok) {
    throw new Error(`Erreur API OSV (${response.status})`);
  }

  const data = await response.json();
  const results = Array.isArray(data.results) ? data.results : [];

  return packages.map((dependency, index) => ({
    ...dependency,
    vulns: Array.isArray(results[index]?.vulns) ? results[index].vulns : []
  }));
}

function extractCvssVector(vulnDetails) {
  const severityEntries = Array.isArray(vulnDetails?.severity) ? vulnDetails.severity : [];
  const cvssV3Entry = severityEntries.find((entry) => typeof entry?.type === "string" && entry.type.toUpperCase().startsWith("CVSS_V3"));

  if (cvssV3Entry?.score && typeof cvssV3Entry.score === "string") {
    return cvssV3Entry.score;
  }

  const genericCvssEntry = severityEntries.find((entry) => typeof entry?.type === "string" && entry.type.toUpperCase().startsWith("CVSS"));

  if (genericCvssEntry?.score && typeof genericCvssEntry.score === "string") {
    return genericCvssEntry.score;
  }

  const databaseCvss = vulnDetails?.database_specific?.cvss;

  if (typeof databaseCvss === "string" && databaseCvss.trim()) {
    return databaseCvss;
  }

  return "";
}

function normalizeCvssLevel(rawLevel) {
  if (typeof rawLevel !== "string" || !rawLevel.trim()) {
    return "N/A";
  }

  const level = rawLevel.trim().toLowerCase();

  if (level === "none") {
    return "None";
  }

  if (level === "low") {
    return "Low";
  }

  if (level === "medium") {
    return "Medium";
  }

  if (level === "high") {
    return "High";
  }

  if (level === "critical") {
    return "Critical";
  }

  return "N/A";
}

function normalizeVectorForScoring(vector) {
  if (typeof vector !== "string") {
    return "";
  }

  if (vector.startsWith("CVSS:3.1/")) {
    return vector.replace("CVSS:3.1/", "CVSS:3.0/");
  }

  return vector;
}

function extractDirectCvssScore(vector) {
  if (typeof vector !== "string") {
    return Number.NaN;
  }

  const trimmed = vector.trim();

  if (/^\d+(\.\d+)?$/.test(trimmed)) {
    return Number(trimmed);
  }

  const cvssV4Match = trimmed.match(/^CVSS:(\d+(?:\.\d+)?)\//i);

  if (cvssV4Match && trimmed.toUpperCase().startsWith("CVSS:4.0/")) {
    return Number(cvssV4Match[1]);
  }

  return Number.NaN;
}

function cvssLevelFromNumericScore(score) {
  if (!Number.isFinite(score) || score < 0) {
    return "N/A";
  }

  if (score === 0) {
    return "None";
  }

  if (score <= 3.9) {
    return "Low";
  }

  if (score <= 6.9) {
    return "Medium";
  }

  if (score <= 8.9) {
    return "High";
  }

  if (score <= 10) {
    return "Critical";
  }

  return "N/A";
}

function computeCvssScoreAndLevel(vulnDetails) {
  const vector = extractCvssVector(vulnDetails);

  if (!vector) {
    return {
      score: "N/A",
      level: normalizeCvssLevel(vulnDetails?.database_specific?.severity)
    };
  }

  const directScore = extractDirectCvssScore(vector);

  if (Number.isFinite(directScore)) {
    return {
      score: directScore.toFixed(1),
      level: cvssLevelFromNumericScore(directScore)
    };
  }

  try {
    const normalizedVector = normalizeVectorForScoring(vector);
    const numericScore = Number(cvss.getScore(normalizedVector));

    if (Number.isFinite(numericScore)) {
      return {
        score: numericScore.toFixed(1),
        level: String(cvss.getRating(numericScore) ?? "N/A")
      };
    }
  } catch {
    return {
      score: "N/A",
      level: normalizeCvssLevel(vulnDetails?.database_specific?.severity)
    };
  }

  return {
    score: "N/A",
    level: normalizeCvssLevel(vulnDetails?.database_specific?.severity)
  };
}

async function fetchCvssDataByGhsa(scannedPackages) {
  const ghsaIds = new Set();

  for (const item of scannedPackages) {
    for (const vuln of item.vulns) {
      const id = typeof vuln?.id === "string" ? vuln.id : "";

      if (id.startsWith("GHSA-")) {
        ghsaIds.add(id);
      }
    }
  }

  const scoreMap = new Map();

  await Promise.all(
    Array.from(ghsaIds).map(async (ghsaId) => {
      try {
        const detailsUrl = `${OSV_VULN_DETAILS_BASE_URL}/${encodeURIComponent(ghsaId)}`;
        const details = await fetchJson(detailsUrl);
        scoreMap.set(ghsaId, computeCvssScoreAndLevel(details));
      } catch {
        scoreMap.set(ghsaId, {
          score: "N/A",
          level: "N/A"
        });
      }
    })
  );

  return scoreMap;
}

function escapeMarkdownCell(value) {
  return String(value ?? "")
    .replace(/\|/g, "\\|")
    .replace(/\s+/g, " ")
    .trim();
}

function buildMarkdownTable(scannedPackages, cvssScoreByGhsa) {
  const rows = [];

  for (const item of scannedPackages) {
    for (const vuln of item.vulns) {
      const ghsaId = typeof vuln?.id === "string" ? vuln.id : "ID inconnu";
      const cvssData = cvssScoreByGhsa.get(ghsaId) ?? {
        score: "N/A",
        level: "N/A"
      };

      rows.push([
        escapeMarkdownCell(item.name),
        escapeMarkdownCell(item.version),
        escapeMarkdownCell(ghsaId),
        escapeMarkdownCell(cvssData.score),
        escapeMarkdownCell(cvssData.level)
      ]);
    }
  }

  const header = "| nom du package | version du package | identifiant GHSA | Score CVSS | Niveau CVSS |";
  const separator = "| --- | --- | --- | --- | --- |";

  if (rows.length === 0) {
    return [header, separator, "| - | - | Aucune vulnérabilité | N/A | N/A |"].join("\n");
  }

  const body = rows.map((columns) => `| ${columns.join(" | ")} |`).join("\n");
  return [header, separator, body].join("\n");
}

function buildEmojiSummary(scannedPackages, cvssScoreByGhsa) {
  const levelOrder = ["Critical", "High", "Medium", "Low", "None", "N/A"];
  const levelEmoji = {
    Critical: "🛑",
    High: "🔴",
    Medium: "🟠",
    Low: "🟡",
    None: "🟢",
    "N/A": "⚪"
  };

  const levelCount = {
    Critical: 0,
    High: 0,
    Medium: 0,
    Low: 0,
    None: 0,
    "N/A": 0
  };

  let totalVulnerabilities = 0;

  for (const item of scannedPackages) {
    for (const vuln of item.vulns) {
      totalVulnerabilities += 1;
      const ghsaId = typeof vuln?.id === "string" ? vuln.id : "";
      const cvssData = cvssScoreByGhsa.get(ghsaId) ?? { level: "N/A" };
      const level = levelOrder.includes(cvssData.level) ? cvssData.level : "N/A";
      levelCount[level] += 1;
    }
  }

  const lines = [`📊 Vulnérabilités totales: ${totalVulnerabilities}`];

  for (const level of levelOrder) {
    lines.push(`${levelEmoji[level]} ${level}: ${levelCount[level]}`);
  }

  return lines.join("\n");
}

function formatSummary(scannedPackages = [], rootName, rootVersion) {
  const vulnerablePackages = scannedPackages.filter((item) => item.vulns.length > 0);
  const vulnerabilitiesCount = vulnerablePackages.reduce((total, item) => total + item.vulns.length, 0);

  const headerLines = [
    `Package: ${rootName}@${rootVersion}`,
    `Packages analysés (racine + transitifs): ${scannedPackages.length}`
  ];

  if (vulnerablePackages.length === 0) {
    return [...headerLines, "✅ Aucune vulnérabilité connue trouvée."].join("\n");
  }

  const lines = vulnerablePackages.map((item, index) => {
    const ids = item.vulns.map((vuln) => vuln.id ?? "ID inconnu").join(", ");
    return `${index + 1}. ${item.name}@${item.version} (${item.vulns.length}) — ${ids}`;
  });

  return [
    ...headerLines,
    `⚠️  ${vulnerabilitiesCount} vulnérabilité(s) sur ${vulnerablePackages.length} package(s):`,
    ...lines
  ].join("\n");
}

async function runVulnerabilityCheck(inputName, inputVersion, inputEcosystem) {
  const name = normalizeInput(inputName);
  const requestedVersion = normalizeInput(inputVersion);
  const ecosystemConfig = resolveEcosystemConfig(inputEcosystem);

  if (!name) {
    console.error("❌ Nom de package manquant.");
    process.exitCode = 1;
    return;
  }

  if (!ecosystemConfig) {
    console.error("❌ Écosystème invalide. Valeurs autorisées: npm, java, pypi.");
    process.exitCode = 1;
    return;
  }

  try {
    const rootVersion = await resolveRootVersion(name, requestedVersion, ecosystemConfig);
    const dependencies = await fetchDependencyGraph(name, rootVersion, ecosystemConfig);
    const scannedPackages = await fetchVulnerabilitiesBatch(dependencies, ecosystemConfig);
    const cvssScoreByGhsa = await fetchCvssDataByGhsa(scannedPackages);

    console.log(buildEmojiSummary(scannedPackages, cvssScoreByGhsa));
    console.log("");
    console.log(buildMarkdownTable(scannedPackages, cvssScoreByGhsa));

    const hasVulnerabilities = scannedPackages.some((item) => item.vulns.length > 0);

    if (hasVulnerabilities) {
      process.exitCode = 2;
    }
  } catch (error) {
    console.error("❌ Impossible d'interroger deps.dev/OSV.");
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}

const program = new Command();

program
  .name("vulnerability")
  .description("Vérifie les vulnérabilités connues d'un package et ses dépendances via deps.dev + OSV")
  .argument("<package-name>", "Nom du package à analyser")
  .option("-v, --version <version>", "Version du package à analyser")
  .option("-e, --ecosystem <ecosystem>", "Écosystème du package (npm, java, pypi)", DEFAULT_ECOSYSTEM)
  .action(async (packageName, options) => {
    await runVulnerabilityCheck(packageName, options.version, options.ecosystem);
  });

program.parseAsync(process.argv);
