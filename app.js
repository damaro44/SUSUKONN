const STORAGE_KEY = "eclair-tech-assistance-v1";

const appState = {
  profile: null,
  audits: [],
  trainings: [],
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
  seedDemo: document.getElementById("seed-demo"),
  resetData: document.getElementById("reset-data"),
  sectorTags: document.getElementById("sector-tags")
};

function init() {
  hydrateState();
  renderTags();
  renderAll();
  bindEvents();
  registerServiceWorker();
}

function bindEvents() {
  el.profileForm.addEventListener("submit", handleProfileSubmit);
  el.auditForm.addEventListener("submit", handleAuditSubmit);
  el.trainingForm.addEventListener("submit", handleTrainingSubmit);

  el.seedDemo.addEventListener("click", seedDemoData);
  el.resetData.addEventListener("click", () => {
    localStorage.removeItem(STORAGE_KEY);
    location.reload();
  });
}

function hydrateState() {
  const saved = localStorage.getItem(STORAGE_KEY);
  if (!saved) {
    return;
  }

  try {
    const parsed = JSON.parse(saved);
    if (parsed.profile) {
      appState.profile = parsed.profile;
    }
    if (Array.isArray(parsed.audits)) {
      appState.audits = parsed.audits;
    }
    if (Array.isArray(parsed.trainings)) {
      appState.trainings = parsed.trainings;
    }
    if (Array.isArray(parsed.services) && parsed.services.length === 6) {
      appState.services = parsed.services;
    }
  } catch (err) {
    console.error("Failed to load saved workspace state", err);
  }
}

function persistState() {
  localStorage.setItem(
    STORAGE_KEY,
    JSON.stringify({
      profile: appState.profile,
      audits: appState.audits,
      trainings: appState.trainings,
      services: appState.services
    })
  );
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
  toast("Institution profile updated.");
}

function handleAuditSubmit(event) {
  event.preventDefault();
  const form = new FormData(event.currentTarget);

  appState.audits.unshift({
    id: crypto.randomUUID(),
    standard: form.get("standard")?.toString().trim(),
    severity: form.get("severity")?.toString(),
    owner: form.get("owner")?.toString().trim(),
    dueDate: form.get("dueDate")?.toString(),
    finding: form.get("finding")?.toString().trim(),
    status: "Open"
  });

  adjustRiskFromAudit();
  persistState();
  renderAll();
  event.currentTarget.reset();
  toast("Audit finding logged.");
}

function handleTrainingSubmit(event) {
  event.preventDefault();
  const form = new FormData(event.currentTarget);

  appState.trainings.unshift({
    id: crypto.randomUUID(),
    program: form.get("program")?.toString().trim(),
    audience: form.get("audience")?.toString().trim(),
    mode: form.get("mode")?.toString(),
    target: Number(form.get("target")),
    objective: form.get("objective")?.toString().trim(),
    completion: 0
  });

  boostReadinessFromTraining();
  persistState();
  renderAll();
  event.currentTarget.reset();
  toast("Training initiative added.");
}

function seedDemoData() {
  appState.profile = {
    institutionName: "Ministry of Digital Governance",
    institutionType: "Ministry",
    region: "Rwanda",
    digitalMaturity: 3,
    paraePreparedness: 2,
    budget: 900000,
    objectives:
      "Accelerate citizen e-services, reduce approval cycle time by 40%, and strengthen policy compliance evidence trails."
  };

  appState.audits = [
    {
      id: crypto.randomUUID(),
      standard: "PARAE Control P-07",
      severity: "High",
      owner: "Internal Audit Unit",
      dueDate: "2026-06-15",
      finding: "No centralized evidence repository for AI-assisted decisions.",
      status: "Open"
    },
    {
      id: crypto.randomUUID(),
      standard: "National Digital Standard NDS-12",
      severity: "Medium",
      owner: "ICT Directorate",
      dueDate: "2026-07-01",
      finding: "Inconsistent SLA monitoring across service portals.",
      status: "Open"
    }
  ];

  appState.trainings = [
    {
      id: crypto.randomUUID(),
      program: "Responsible AI Operations",
      audience: "Policy, ICT, and service delivery teams",
      mode: "Hybrid",
      target: 90,
      objective: "Enable compliant AI decision support workflows in 4 departments.",
      completion: 35
    }
  ];

  appState.services = appState.services.map((service, index) => ({
    ...service,
    progress: 30 + index * 7,
    risk: 68 - index * 5
  }));

  persistState();
  renderAll();
  syncProfileForm();
  toast("Demo scenario loaded.");
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

  syncProfileForm();
}

function adjustRiskFromAudit() {
  const severityWeight = {
    Critical: 7,
    High: 5,
    Medium: 3,
    Low: 1
  };

  const openRisk = appState.audits.reduce((score, audit) => {
    return score + (severityWeight[audit.severity] || 0);
  }, 0);

  appState.services = appState.services.map(service => {
    if (service.key === "compliance" || service.key === "cyber") {
      return {
        ...service,
        risk: clamp(service.risk + openRisk * 0.15, 20, 97),
        progress: clamp(service.progress - openRisk * 0.08, 5, 95)
      };
    }
    return service;
  });
}

function boostReadinessFromTraining() {
  const leverage = Math.min(appState.trainings.length * 2, 10);
  appState.services = appState.services.map(service => {
    if (service.key === "training" || service.key === "change") {
      return {
        ...service,
        progress: clamp(service.progress + leverage, 5, 98),
        risk: clamp(service.risk - leverage * 0.8, 10, 95)
      };
    }
    return service;
  });
}

function computeReadiness() {
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
    { label: "Governance Risk Index", value: `${avgRisk}/100` },
    { label: "Open Audit Findings", value: String(appState.audits.length) }
  ];
}

function buildIndicators() {
  const openCritical = appState.audits.filter(item => item.severity === "Critical").length;
  const openHigh = appState.audits.filter(item => item.severity === "High").length;
  const trainingCoverage = appState.trainings.length
    ? Math.round(
        appState.trainings.reduce((sum, training) => sum + training.target, 0) /
          appState.trainings.length
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
    el.auditList.innerHTML = `<p class="muted">No findings logged yet.</p>`;
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
    el.trainingList.innerHTML = `<p class="muted">No training plans yet.</p>`;
    return;
  }

  el.trainingList.innerHTML = appState.trainings
    .map(
      item => `
      <article class="list-item">
        <div class="item-head">
          <strong>${item.program}</strong>
          <span class="badge badge--low">${item.mode}</span>
        </div>
        <p>${item.objective}</p>
        <p class="muted">Audience: ${item.audience} | Target: ${item.target}% completion</p>
      </article>
    `
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

function syncProfileForm() {
  if (!appState.profile) {
    return;
  }

  Object.entries(appState.profile).forEach(([key, value]) => {
    const input = el.profileForm.elements.namedItem(key);
    if (input) {
      input.value = value;
    }
  });
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

function toast(message) {
  const notice = document.createElement("div");
  notice.className = "toast";
  notice.textContent = message;
  el.toastRoot.appendChild(notice);

  window.setTimeout(() => {
    notice.remove();
  }, 2600);
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
