import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const cvss = require("cvss");

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

  if (level === "moderate") {
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

function isCvssV4Vector(vector) {
  if (typeof vector !== "string") {
    return false;
  }

  return vector.trim().toUpperCase().startsWith("CVSS:4.0/");
}

function extractDirectCvssScore(vector) {
  if (typeof vector !== "string") {
    return Number.NaN;
  }

  const trimmed = vector.trim();

  if (/^\d+(\.\d+)?$/.test(trimmed)) {
    return Number(trimmed);
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

export function computeCvssScoreAndLevel(vulnDetails) {
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

  if (isCvssV4Vector(vector)) {
    return {
      score: "N/A",
      level: normalizeCvssLevel(vulnDetails?.database_specific?.severity)
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
