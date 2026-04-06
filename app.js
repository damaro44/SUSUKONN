const STORAGE_KEY = "eclair-tech-assistance-v2";
const DEFAULT_API_BASE_URL = "http://localhost:4100/v1";

const appState = {
  apiBaseUrl: DEFAULT_API_BASE_URL,
  auth: {
    token: "",
    user: null
  },
  profile: null,
  audits: [],
  trainings: [],
  dashboard: null,
  services: [
    {
      key: "compliance",
      title: "Compliance Audits",
      detail:
        "Assess legal, regulatory, and policy controls against PARAE requirements and national digital standards.",
      progress: 20,
      risk: 72
    },
    {
      key: "automation",
      title: "Process Automation",
      detail:
        "Map high-friction manual procedures and prioritize automation candidates with measurable ROI.",
      progress: 30,
      risk: 62
    },
    {
      key: "ai-workflow",
      title: "AI-driven Workflow Solutions",
      detail:
        "Deploy responsible AI workflows for citizen services, case handling, and internal approvals.",
      progress: 15,
      risk: 66
    },
    {
      key: "change",
      title: "Change Management",
      detail:
        "Coordinate executive sponsorship, communication cadence, and adoption KPIs across departments.",
      progress: 25,
      risk: 58
    },
    {
      key: "cyber",
      title: "Cybersecurity Governance",
      detail:
        "Implement control ownership, risk treatment workflows, and security accountability frameworks.",
      progress: 35,
      risk: 69
    },
    {
      key: "training",
      title: "PARAE-aligned Staff Training",
      detail:
        "Build competency pathways for policy, technical, and operational teams with outcome tracking.",
      progress: 18,
      risk: 60
    }
  ]
};

const sectorTags = [
  "Government Agencies",
  "Ministries",
  "Public Institutions",
  "Regulated Private Sector",
  "National Digital Standards",
  "PARAE Alignment"
];

const el = {
  connectionForm: document.getElementById("connection-form"),
  apiBaseUrl: document.getElementById("api-base-url"),
  loginForm: document.getElementById("login-form"),
  logoutBtn: document.getElementById("logout-btn"),
  authStatus: document.getElementById("auth-status"),
  refreshLiveData: document.getElementById("refresh-live-data"),
  downloadCsv: document.getElementById("download-csv"),
  downloadPdf: document.getElementById("download-pdf"),
  kpiGrid: document.getElementById("kpi-grid"),
  serviceCards: document.getElementById("service-cards"),
  actionQueue: document.getElementById("action-queue"),
  auditList: document.getElementById("audit-list"),
  trainingList: document.getElementById("training-list"),
  indicatorGrid: document.getElementById("indicator-grid"),
  profileForm: document.getElementById("profile-form"),
  auditForm: document.getElementById("audit-form"),
  trainingForm: document.getElementById("training-form"),
  readinessScore: document.getElementById("readiness-score"),
  readinessCaption: document.getElementById("readiness-caption"),
  toastRoot: document.getElementById("toast-root"),
  sectorTags: document.getElementById("sector-tags")
};

function init() {
  hydrateState();
  renderTags();
  syncConnectionFields();
  renderAll();
  updateAuthUi();
  bindEvents();
  registerServiceWorker();
  if (appState.auth.token) {
    refreshLiveData().catch(() => {
      logoutLocal("Session expired. Please sign in again.");
    });
  }
}

function bindEvents() {
  el.connectionForm.addEventListener("submit", handleConnectionSubmit);
  el.loginForm.addEventListener("submit", handleLoginSubmit);
  el.logoutBtn.addEventListener("click", () => logoutLocal("Signed out."));
  el.refreshLiveData.addEventListener("click", () => {
    refreshLiveData().catch(handleError);
  });
  el.downloadCsv.addEventListener("click", () => {
    downloadReport("csv").catch(handleError);
  });
  el.downloadPdf.addEventListener("click", () => {
    downloadReport("pdf").catch(handleError);
  });

  el.profileForm.addEventListener("submit", handleProfileSubmit);
  el.auditForm.addEventListener("submit", handleAuditSubmit);
  el.trainingForm.addEventListener("submit", handleTrainingSubmit);
}

function hydrateState() {
  const saved = localStorage.getItem(STORAGE_KEY);
  if (!saved) {
    return;
  }

  try {
    const parsed = JSON.parse(saved);
    if (typeof parsed.apiBaseUrl === "string" && parsed.apiBaseUrl.trim()) {
      appState.apiBaseUrl = parsed.apiBaseUrl;
    }
    if (parsed.auth?.token && parsed.auth?.user) {
      appState.auth = parsed.auth;
    }
    if (parsed.profile) {
      appState.profile = parsed.profile;
    }
    if (Array.isArray(parsed.audits)) {
      appState.audits = parsed.audits;
    }
    if (Array.isArray(parsed.trainings)) {
      appState.trainings = parsed.trainings;
    }
    if (parsed.dashboard) {
      appState.dashboard = parsed.dashboard;
    }
    if (Array.isArray(parsed.services) && parsed.services.length === 6) {
      appState.services = parsed.services;
    }
  } catch (error) {
    console.error("Failed to restore local state", error);
  }
}

function persistState() {
  localStorage.setItem(
    STORAGE_KEY,
    JSON.stringify({
      apiBaseUrl: appState.apiBaseUrl,
      auth: appState.auth,
      profile: appState.profile,
      audits: appState.audits,
      trainings: appState.trainings,
      dashboard: appState.dashboard,
      services: appState.services
    })
  );
}

function syncConnectionFields() {
  el.apiBaseUrl.value = appState.apiBaseUrl;
}

function handleConnectionSubmit(event) {
  event.preventDefault();
  const formData = new FormData(event.currentTarget);
  const raw = formData.get("apiBaseUrl")?.toString().trim();
  if (!raw) {
    toast("API base URL cannot be empty.", "error");
    return;
  }

  appState.apiBaseUrl = raw.replace(/\/+$/, "");
  persistState();
  toast("API base URL updated.", "success");
}

async function handleLoginSubmit(event) {
  event.preventDefault();
  const formData = new FormData(event.currentTarget);
  const email = formData.get("email")?.toString().trim() || "";
  const password = formData.get("password")?.toString() || "";

  if (!email || !password) {
    toast("Provide email and password.", "error");
    return;
  }

  try {
    const login = await apiFetch("/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password })
    });

    appState.auth.token = login.data.accessToken;
    appState.auth.user = login.data.user;
    persistState();
    updateAuthUi();
    event.currentTarget.reset();
    toast(`Welcome, ${login.data.user.fullName}.`, "success");

    await refreshLiveData();
  } catch (error) {
    handleError(error);
  }
}

function logoutLocal(message) {
  appState.auth = { token: "", user: null };
  appState.dashboard = null;
  persistState();
  updateAuthUi();
  if (message) {
    toast(message, "success");
  }
}

async function refreshLiveData() {
  ensureAuthed();

  const [dashboardResult, auditsResult, trainingsResult] = await Promise.all([
    apiFetch("/dashboard"),
    apiFetch("/compliance/audits"),
    apiFetch("/training/plans")
  ]);

  appState.dashboard = dashboardResult.data;
  appState.audits = auditsResult.data;
  appState.trainings = trainingsResult.data;

  mapServicesFromLiveData();
  persistState();
  renderAll();
  toast("Live data refreshed.", "success");
}

function updateAuthUi() {
  const authed = Boolean(appState.auth.token && appState.auth.user);
  el.logoutBtn.disabled = !authed;
  el.refreshLiveData.disabled = !authed;
  el.downloadCsv.disabled = !authed;
  el.downloadPdf.disabled = !authed;

  if (!authed) {
    el.authStatus.textContent = "Not authenticated.";
    return;
  }

  el.authStatus.textContent = `Authenticated as ${appState.auth.user.fullName} (${appState.auth.user.role}).`;
}

function ensureAuthed() {
  if (!appState.auth.token) {
    throw new Error("Please sign in to call the live API.");
  }
}

async function apiFetch(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (!headers.has("Content-Type") && options.body) {
    headers.set("Content-Type", "application/json");
  }
  if (appState.auth.token) {
    headers.set("Authorization", `Bearer ${appState.auth.token}`);
  }

  const response = await fetch(`${appState.apiBaseUrl}${path}`, {
    ...options,
    headers
  });

  if (!response.ok) {
    let message = `Request failed (${response.status})`;
    try {
      const payload = await response.json();
      message = payload?.error?.message || message;
    } catch {
      // ignore parse errors
    }

    if (response.status === 401) {
      logoutLocal("Session expired. Please sign in again.");
    }

    throw new Error(message);
  }

  return response.json();
}

async function downloadReport(format) {
  ensureAuthed();

  const response = await fetch(`${appState.apiBaseUrl}/reports/compliance?format=${format}`, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${appState.auth.token}`
    }
  });

  if (!response.ok) {
    let message = `Failed to download ${format.toUpperCase()} report.`;
    try {
      const payload = await response.json();
      message = payload?.error?.message || message;
    } catch {
      // ignore parse errors
    }
    throw new Error(message);
  }

  const blob = await response.blob();
  const extension = format === "pdf" ? "pdf" : "csv";
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `eclair-compliance-report.${extension}`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);

  toast(`${format.toUpperCase()} report downloaded.`, "success");
}

function mapServicesFromLiveData() {
  const dashboard = appState.dashboard;
  if (!dashboard) {
    return;
  }

  const risk = clamp(Number(dashboard.riskScore || 0), 0, 100);
  const readiness = clamp(Number(dashboard.readinessScore || 0), 0, 100);

  appState.services = appState.services.map(service => {
    if (service.key === "compliance") {
      return {
        ...service,
        risk,
        progress: clamp(readiness - 8, 5, 99)
      };
    }
    if (service.key === "training") {
      return {
        ...service,
        risk: clamp(100 - readiness, 10, 90),
        progress: clamp(readiness - 2, 5, 99)
      };
    }

    return {
      ...service,
      risk: clamp(Math.round((service.risk + risk) / 2), 10, 95),
      progress: clamp(Math.round((service.progress + readiness) / 2), 5, 99)
    };
  });
}

function handleProfileSubmit(event) {
  event.preventDefault();
  const form = new FormData(event.currentTarget);

  appState.profile = {
    institutionName: form.get("institutionName")?.toString().trim(),
    institutionType: form.get("institutionType")?.toString(),
    region: form.get("region")?.toString().trim(),
    digitalMaturity: Number(form.get("digitalMaturity")),
    paraePreparedness: Number(form.get("paraePreparedness")),
    budget: Number(form.get("budget")),
    objectives: form.get("objectives")?.toString().trim()
  };

  tuneServiceModelFromProfile();
  persistState();
  renderAll();
  toast("Institution profile saved locally.", "success");
}

async function handleAuditSubmit(event) {
  event.preventDefault();
  ensureAuthed();

  const form = new FormData(event.currentTarget);
  const payload = {
    standard: form.get("standard")?.toString().trim(),
    severity: form.get("severity")?.toString(),
    owner: form.get("owner")?.toString().trim(),
    dueDate: form.get("dueDate")?.toString(),
    finding: form.get("finding")?.toString().trim()
  };

  try {
    await apiFetch("/compliance/audits", {
      method: "POST",
      body: JSON.stringify(payload)
    });

    event.currentTarget.reset();
    toast("Audit finding created in live backend.", "success");
    await refreshLiveData();
  } catch (error) {
    handleError(error);
  }
}

async function handleTrainingSubmit(event) {
  event.preventDefault();
  ensureAuthed();

  const form = new FormData(event.currentTarget);
  const payload = {
    program: form.get("program")?.toString().trim(),
    audience: form.get("audience")?.toString().trim(),
    mode: form.get("mode")?.toString(),
    targetCompletion: Number(form.get("target")),
    objective: form.get("objective")?.toString().trim()
  };

  try {
    await apiFetch("/training/plans", {
      method: "POST",
      body: JSON.stringify(payload)
    });

    event.currentTarget.reset();
    toast("Training plan created in live backend.", "success");
    await refreshLiveData();
  } catch (error) {
    handleError(error);
  }
}

function tuneServiceModelFromProfile() {
  if (!appState.profile) {
    return;
  }

  const maturityGap = 6 - appState.profile.digitalMaturity;
  const paraeGap = 6 - appState.profile.paraePreparedness;

  appState.services = appState.services.map(service => {
    const riskOffset = maturityGap * 3 + paraeGap * 4;
    const progressBase = 55 - maturityGap * 6 - paraeGap * 5;

    return {
      ...service,
      risk: clamp(Math.round(riskOffset + service.risk * 0.45), 20, 95),
      progress: clamp(Math.round(progressBase + service.progress * 0.25), 5, 90)
    };
  });
}

function computeReadiness() {
  if (appState.dashboard?.readinessScore) {
    return clamp(Number(appState.dashboard.readinessScore), 5, 98);
  }

  const base = appState.profile
    ? appState.profile.digitalMaturity * 9 + appState.profile.paraePreparedness * 11
    : 15;

  const serviceContribution =
    appState.services.reduce((sum, service) => sum + service.progress - service.risk * 0.32, 0) /
    appState.services.length;

  const auditPenalty = appState.audits.length * 1.2;
  const trainingBonus = appState.trainings.length * 1.7;

  return clamp(Math.round(base + serviceContribution - auditPenalty + trainingBonus), 5, 98);
}

function buildKpis() {
  const readiness = computeReadiness();
  const avgRisk = Math.round(
    appState.services.reduce((sum, service) => sum + service.risk, 0) / appState.services.length
  );
  const avgProgress = Math.round(
    appState.services.reduce((sum, service) => sum + service.progress, 0) / appState.services.length
  );

  return [
    { label: "Readiness Score", value: `${readiness}%` },
    { label: "Average Service Progress", value: `${avgProgress}%` },
    {
      label: "Governance Risk Index",
      value: appState.dashboard ? `${appState.dashboard.riskScore}/100` : `${avgRisk}/100`
    },
    {
      label: "Open Audit Findings",
      value: appState.dashboard ? String(appState.dashboard.openAuditFindings) : String(appState.audits.length)
    }
  ];
}

function buildIndicators() {
  const openCritical = appState.audits.filter(item => item.severity === "Critical").length;
  const openHigh = appState.audits.filter(item => item.severity === "High").length;
  const trainingCoverage = appState.trainings.length
    ? Math.round(
        appState.trainings.reduce(
          (sum, training) => sum + (training.targetCompletion ?? training.target ?? 0),
          0
        ) / appState.trainings.length
      )
    : 0;

  const automationService = appState.services.find(service => service.key === "automation");
  const aiService = appState.services.find(service => service.key === "ai-workflow");

  return [
    {
      title: "Critical Findings",
      value: String(openCritical),
      note: "Immediate executive escalation threshold"
    },
    {
      title: "High Findings",
      value: String(openHigh),
      note: "Close within governance sprint cycle"
    },
    {
      title: "Training Target Coverage",
      value: `${trainingCoverage}%`,
      note: "PARAE competency target"
    },
    {
      title: "Automation Progress",
      value: `${automationService?.progress || 0}%`,
      note: "Public service processing optimization"
    },
    {
      title: "AI Workflow Maturity",
      value: `${aiService?.progress || 0}%`,
      note: "Responsible AI deployment readiness"
    },
    {
      title: "Cyber Governance Risk",
      value: `${appState.services.find(service => service.key === "cyber")?.risk || 0}/100`,
      note: "Control ownership and risk treatment posture"
    }
  ];
}

function buildActionQueue() {
  const topRiskServices = [...appState.services]
    .sort((a, b) => b.risk - a.risk)
    .slice(0, 3)
    .map(service => `Reduce ${service.title.toLowerCase()} risk via targeted 30-day controls.`);

  const actions = [
    appState.audits.length
      ? `Close ${Math.min(3, appState.audits.length)} highest-severity audit findings and attach evidence packs.`
      : "Launch initial PARAE and national standards compliance diagnostic.",
    appState.trainings.length
      ? `Increase completion rates across ${appState.trainings.length} training initiatives through role-based sessions.`
      : "Start mandatory baseline training on compliance, AI ethics, and cybersecurity governance.",
    ...topRiskServices,
    "Publish monthly steering report with readiness trend, risk heatmap, and mitigation accountability."
  ];

  return actions.slice(0, 6);
}

function renderAll() {
  const readiness = computeReadiness();
  el.readinessScore.textContent = `${readiness}%`;
  el.readinessCaption.textContent =
    readiness >= 70
      ? "Institution is on a strong trajectory for scaled digital transformation."
      : "Focus on high-risk controls, training, and governance acceleration.";

  renderKpis();
  renderServices();
  renderActionQueue();
  renderAudits();
  renderTrainings();
  renderIndicators();
}

function renderTags() {
  el.sectorTags.innerHTML = sectorTags.map(tag => `<span class="tag">${tag}</span>`).join("");
}

function renderKpis() {
  const cards = buildKpis()
    .map(
      item => `
        <article class="kpi">
          <h3>${item.label}</h3>
          <div class="value">${item.value}</div>
        </article>
      `
    )
    .join("");

  el.kpiGrid.innerHTML = cards;
}

function renderServices() {
  const cards = appState.services
    .map(service => {
      const badgeClass = service.risk > 70 ? "badge--high" : service.risk > 45 ? "badge--medium" : "badge--low";
      const badgeLabel = service.risk > 70 ? "High Risk" : service.risk > 45 ? "Medium Risk" : "Low Risk";

      return `
        <article class="service-card">
          <div class="service-head">
            <h3>${service.title}</h3>
            <span class="badge ${badgeClass}">${badgeLabel}</span>
          </div>
          <p class="muted">${service.detail}</p>
          <p><strong>Progress:</strong> ${service.progress}% &nbsp; | &nbsp; <strong>Risk:</strong> ${service.risk}/100</p>
        </article>
      `;
    })
    .join("");

  el.serviceCards.innerHTML = cards;
}

function renderActionQueue() {
  el.actionQueue.innerHTML = buildActionQueue().map(action => `<li>${action}</li>`).join("");
}

function renderAudits() {
  if (!appState.audits.length) {
    el.auditList.innerHTML = `<p class="muted">No findings available.</p>`;
    return;
  }

  el.auditList.innerHTML = appState.audits
    .map(
      item => `
      <article class="list-item">
        <div class="item-head">
          <strong>${item.standard}</strong>
          <span class="badge ${severityToBadge(item.severity)}">${item.severity}</span>
        </div>
        <p>${item.finding}</p>
        <p class="muted">Owner: ${item.owner} | Due: ${item.dueDate} | Status: ${item.status}</p>
      </article>
    `
    )
    .join("");
}

function renderTrainings() {
  if (!appState.trainings.length) {
    el.trainingList.innerHTML = `<p class="muted">No training plans available.</p>`;
    return;
  }

  el.trainingList.innerHTML = appState.trainings
    .map(
      item => {
        const target = item.targetCompletion ?? item.target;
        return `
      <article class="list-item">
        <div class="item-head">
          <strong>${item.program}</strong>
          <span class="badge badge--low">${item.mode}</span>
        </div>
        <p>${item.objective}</p>
        <p class="muted">Audience: ${item.audience} | Target: ${target}% completion</p>
      </article>
    `;
      }
    )
    .join("");
}

function renderIndicators() {
  el.indicatorGrid.innerHTML = buildIndicators()
    .map(
      item => `
      <article class="indicator">
        <h3>${item.title}</h3>
        <div class="value">${item.value}</div>
        <p class="muted">${item.note}</p>
      </article>
    `
    )
    .join("");
}

function severityToBadge(severity) {
  if (severity === "Critical" || severity === "High") {
    return "badge--high";
  }
  if (severity === "Medium") {
    return "badge--medium";
  }
  return "badge--low";
}

function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value));
}

function toast(message, level = "info") {
  const notice = document.createElement("div");
  notice.className = `toast toast--${level}`;
  notice.textContent = message;
  el.toastRoot.appendChild(notice);

  window.setTimeout(() => {
    notice.remove();
  }, 3200);
}

function handleError(error) {
  const message = error instanceof Error ? error.message : "Unexpected error";
  toast(message, "error");
}

function registerServiceWorker() {
  if (!("serviceWorker" in navigator)) {
    return;
  }

  window.addEventListener("load", () => {
    navigator.serviceWorker.register("./service-worker.js").catch(error => {
      console.error("Service worker registration failed", error);
    });
  });
}

init();
