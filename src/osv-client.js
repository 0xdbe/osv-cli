const OSV_QUERY_BATCH_URL = "https://api.osv.dev/v1/querybatch";
const OSV_VULN_DETAILS_BASE_URL = "https://api.osv.dev/v1/vulns";

async function fetchJson(url) {
  const response = await fetch(url);

  if (!response.ok) {
    throw new Error(`Erreur HTTP ${response.status} sur ${url}`);
  }

  return response.json();
}

function buildOsvBatchBody(packages, ecosystem) {
  return {
    queries: packages.map((dependency) => ({
      package: {
        name: dependency.name,
        ecosystem
      },
      version: dependency.version
    }))
  };
}

export async function queryVulnerabilitiesBatch(packages, ecosystem) {
  const response = await fetch(OSV_QUERY_BATCH_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(buildOsvBatchBody(packages, ecosystem))
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

export async function fetchVulnerabilityDetails(ghsaId) {
  const detailsUrl = `${OSV_VULN_DETAILS_BASE_URL}/${encodeURIComponent(ghsaId)}`;
  return fetchJson(detailsUrl);
}
