import { I18N, PERMISSION_KEYS, SECTOR_TAG_KEYS } from "./i18n.js";

const STORAGE_KEY = "eclair-tech-assistance-v5";
const DEFAULT_API_BASE_URL = "http://localhost:4100/v1";

const ROLE_PERMISSIONS = {
  super_admin: [
    "refresh",
    "createAudit",
    "createTraining",
    "downloadReports",
    "uploadDocuments",
    "processDocuments",
    "manageWorkflows",
    "collaborate",
    "viewAnalytics"
  ],
  compliance_officer: [
    "refresh",
    "createAudit",
    "createTraining",
    "downloadReports",
    "uploadDocuments",
    "processDocuments",
    "manageWorkflows",
    "collaborate",
    "viewAnalytics"
  ],
  auditor: ["refresh", "downloadReports", "processDocuments", "collaborate", "viewAnalytics"],
  training_manager: [
    "refresh",
    "createTraining",
    "uploadDocuments",
    "manageWorkflows",
    "collaborate",
    "viewAnalytics"
  ]
};

const DOC_OP_DEPARTMENTS = {
  compliance: "docOps.department.compliance",
  legal: "docOps.department.legal",
  finance: "docOps.department.finance",
  it_security: "docOps.department.it_security",
  hr: "docOps.department.hr",
  operations: "docOps.department.operations"
};

const appState = {
  language: "en",
  languageManualOverride: false,
  apiBaseUrl: DEFAULT_API_BASE_URL,
  auth: { token: "", user: null },
  profile: null,
  audits: [],
  trainings: [],
  documents: [],
  documentProcessing: [],
  workflowTemplates: [],
  workflowRuns: [],
  comments: [],
  auditTrail: [],
  analytics: null,
  latestOcrResult: null,
  selectedDocId: "",
  dashboard: null,
  services: [
    { key: "compliance", progress: 20, risk: 72 },
    { key: "automation", progress: 30, risk: 62 },
    { key: "ai-workflow", progress: 15, risk: 66 },
    { key: "change", progress: 25, risk: 58 },
    { key: "cyber", progress: 35, risk: 69 },
    { key: "training", progress: 18, risk: 60 }
  ]
};

const el = {
  languageSelect: document.getElementById("language-select"),
  connectionForm: document.getElementById("connection-form"),
  apiBaseUrl: document.getElementById("api-base-url"),
  loginForm: document.getElementById("login-form"),
  registerForm: document.getElementById("register-form"),
  logoutBtn: document.getElementById("logout-btn"),
  authStatus: document.getElementById("auth-status"),
  refreshLiveData: document.getElementById("refresh-live-data"),
  downloadCsv: document.getElementById("download-csv"),
  downloadPdf: document.getElementById("download-pdf"),
  reportActions: document.getElementById("report-actions"),
  reportRbacNote: document.getElementById("report-rbac-note"),
  capabilitiesPanel: document.getElementById("capabilities-panel"),
  capabilitiesRole: document.getElementById("capabilities-role"),
  capabilitiesAllowed: document.getElementById("capabilities-allowed"),
  capabilitiesRestricted: document.getElementById("capabilities-restricted"),
  kpiGrid: document.getElementById("kpi-grid"),
  serviceCards: document.getElementById("service-cards"),
  actionQueue: document.getElementById("action-queue"),
  auditList: document.getElementById("audit-list"),
  trainingList: document.getElementById("training-list"),
  indicatorGrid: document.getElementById("indicator-grid"),
  profileForm: document.getElementById("profile-form"),
  auditForm: document.getElementById("audit-form"),
  trainingForm: document.getElementById("training-form"),
  documentUploadForm: document.getElementById("document-upload-form"),
  documentsRbacNote: document.getElementById("documents-rbac-note"),
  documentsList: document.getElementById("documents-list"),
  versionUploadForm: document.getElementById("document-version-form"),
  ocrRunBtn: document.getElementById("run-ocr-btn"),
  commentForm: document.getElementById("collaboration-form"),
  workflowTemplateForm: document.getElementById("workflow-template-form"),
  workflowStartForm: document.getElementById("workflow-start-form"),
  workflowAdvanceForm: document.getElementById("workflow-advance-form"),
  refreshAnalyticsBtn: document.getElementById("refresh-analytics-btn"),
  workflowRbacNote: document.getElementById("workflow-rbac-note"),
  opsDocumentSelect: document.getElementById("ops-document-select"),
  ocrResult: document.getElementById("ocr-result"),
  processingList: document.getElementById("processing-list"),
  workflowTemplatesList: document.getElementById("workflow-templates-list"),
  workflowRunsList: document.getElementById("workflow-runs-list"),
  versionsList: document.getElementById("document-versions-list"),
  commentsList: document.getElementById("collaboration-comments-list"),
  auditTrailList: document.getElementById("audit-trail-list"),
  analyticsGrid: document.getElementById("analytics-grid"),
  templateSelect: document.getElementById("workflow-template-select"),
  runSelect: document.getElementById("workflow-run-select"),
  auditRbacNote: document.getElementById("audit-rbac-note"),
  trainingRbacNote: document.getElementById("training-rbac-note"),
  readinessScore: document.getElementById("readiness-score"),
  readinessCaption: document.getElementById("readiness-caption"),
  toastRoot: document.getElementById("toast-root"),
  sectorTags: document.getElementById("sector-tags")
};

function t(key, vars = {}) {
  const dictionary = I18N[appState.language] || I18N.en;
  let text = dictionary[key] || I18N.en[key] || key;
  for (const [name, value] of Object.entries(vars)) {
    text = text.replaceAll(`{${name}}`, String(value));
  }
  return text;
}

function hasPermission(permission) {
  const role = appState.auth.user?.role;
  return Boolean(role && ROLE_PERMISSIONS[role]?.includes(permission));
}

function roleLabel(role) {
  return t(`role.${role}`);
}

function permissionLabel(permission) {
  return t(`permission.${permission}`);
}

function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value));
}

function formatBytes(sizeBytes) {
  const size = Number(sizeBytes) || 0;
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  return `${(size / (1024 * 1024)).toFixed(1)} MB`;
}

function localeTag() {
  return appState.language === "fr" ? "fr-FR" : "en-US";
}

function formatNumber(value, options = {}) {
  const number = Number(value);
  if (!Number.isFinite(number)) return "0";
  return new Intl.NumberFormat(localeTag(), options).format(number);
}

function formatPercent(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) return "0%";
  return `${formatNumber(number, { maximumFractionDigits: 1 })}%`;
}

function formatDateTime(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value ?? "");
  return date.toLocaleString(localeTag());
}

function formatDate(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value ?? "");
  return date.toLocaleDateString(localeTag());
}

function translateWorkflowRunStatus(status) {
  return t(`workflowStatus.${status}`);
}

function translateWorkflowStepStatus(status) {
  return t(`workflowStepStatus.${status}`);
}

function translateEventAction(action) {
  return t(`eventAction.${action}`);
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function toast(message, level = "info") {
  const notice = document.createElement("div");
  notice.className = `toast toast--${level}`;
  notice.textContent = message;
  el.toastRoot.appendChild(notice);
  window.setTimeout(() => notice.remove(), 3200);
}

function handleError(error) {
  const message = error instanceof Error ? error.message : "Unexpected error";
  toast(message, "error");
}

function hydrateState() {
  const saved = localStorage.getItem(STORAGE_KEY);
  if (!saved) {
    autoDetectLanguageOnFirstLoad();
    return;
  }

  try {
    const parsed = JSON.parse(saved);
    if (parsed.language === "fr" || parsed.language === "en") appState.language = parsed.language;
    if (typeof parsed.languageManualOverride === "boolean") appState.languageManualOverride = parsed.languageManualOverride;
    if (typeof parsed.apiBaseUrl === "string" && parsed.apiBaseUrl.trim()) appState.apiBaseUrl = parsed.apiBaseUrl;
    if (parsed.auth?.token && parsed.auth?.user) appState.auth = parsed.auth;
    if (parsed.profile) appState.profile = parsed.profile;
    if (Array.isArray(parsed.audits)) appState.audits = parsed.audits;
    if (Array.isArray(parsed.trainings)) appState.trainings = parsed.trainings;
    if (Array.isArray(parsed.documents)) appState.documents = parsed.documents;
    if (parsed.dashboard) appState.dashboard = parsed.dashboard;
    if (Array.isArray(parsed.services) && parsed.services.length === 6) appState.services = parsed.services;
  } catch (error) {
    console.error("Failed to restore local state", error);
  }
}

function persistState() {
  localStorage.setItem(
    STORAGE_KEY,
    JSON.stringify({
      language: appState.language,
      languageManualOverride: appState.languageManualOverride,
      apiBaseUrl: appState.apiBaseUrl,
      auth: appState.auth,
      profile: appState.profile,
      audits: appState.audits,
      trainings: appState.trainings,
      documents: appState.documents,
      dashboard: appState.dashboard,
      services: appState.services
    })
  );
}

function applyI18n() {
  document.documentElement.lang = appState.language;
  document.title = t("meta.title");

  const descriptionMeta = document.querySelector('meta[name="description"]');
  if (descriptionMeta) descriptionMeta.setAttribute("content", t("meta.description"));

  document.querySelectorAll("[data-i18n]").forEach(node => {
    const key = node.getAttribute("data-i18n");
    if (key) node.textContent = t(key);
  });

  document.querySelectorAll("[data-i18n-placeholder]").forEach(node => {
    const key = node.getAttribute("data-i18n-placeholder");
    if (key) node.setAttribute("placeholder", t(key));
  });

  if (el.languageSelect) {
    const options = Array.from(el.languageSelect.options);
    if (options[0]) options[0].textContent = t("language.english");
    if (options[1]) options[1].textContent = t("language.french");
    el.languageSelect.value = appState.language;
  }
}

function renderCapabilities() {
  const authed = Boolean(appState.auth.user);
  el.capabilitiesPanel.classList.toggle("hidden", !authed);
  if (!authed) return;

  const role = appState.auth.user.role;
  const allowed = ROLE_PERMISSIONS[role] || [];
  const restricted = PERMISSION_KEYS.filter(permission => !allowed.includes(permission));

  el.capabilitiesRole.textContent = `${t("capabilities.rolePrefix")} ${roleLabel(role)}`;
  el.capabilitiesAllowed.innerHTML = allowed.map(permission => `<li>${permissionLabel(permission)}</li>`).join("");
  el.capabilitiesRestricted.innerHTML = restricted.map(permission => `<li>${permissionLabel(permission)}</li>`).join("");
}

function renderTags() {
  el.sectorTags.innerHTML = SECTOR_TAG_KEYS.map(key => `<span class="tag">${t(key)}</span>`).join("");
}

function syncConnectionFields() {
  el.apiBaseUrl.value = appState.apiBaseUrl;
}

function setSectionPermission(formElement, noteElement, isAllowed, message, showNote = true) {
  if (!formElement || !noteElement) return;
  const inputs = formElement.querySelectorAll("input, select, textarea, button");
  inputs.forEach(input => {
    input.disabled = !isAllowed;
  });
  formElement.classList.toggle("rbac-disabled", !isAllowed);
  noteElement.textContent = !isAllowed && showNote ? message : "";
  noteElement.classList.toggle("hidden", isAllowed || !showNote);
}

function toggleReportPermission(isAllowed, message, showNote = true) {
  el.reportActions.classList.toggle("hidden", !isAllowed);
  el.reportRbacNote.textContent = !isAllowed && showNote ? message : "";
  el.reportRbacNote.classList.toggle("hidden", isAllowed || !showNote);
}

function updateAuthUi() {
  const authed = Boolean(appState.auth.token && appState.auth.user);
  el.logoutBtn.disabled = !authed;

  if (!authed) {
    el.refreshLiveData.disabled = true;
    el.downloadCsv.disabled = true;
    el.downloadPdf.disabled = true;
    setSectionPermission(el.auditForm, el.auditRbacNote, false, t("rbac.signInCreateAudit"), false);
    setSectionPermission(el.trainingForm, el.trainingRbacNote, false, t("rbac.signInCreateTraining"), false);
    setSectionPermission(el.documentUploadForm, el.documentsRbacNote, false, t("rbac.signInUploadDocuments"), false);
    setSectionPermission(el.workflowTemplateForm, el.workflowRbacNote, false, t("rbac.signInManageWorkflows"), false);
    toggleReportPermission(false, t("rbac.signInExport"), false);
    el.authStatus.textContent = t("status.notAuthenticated");
    renderCapabilities();
    return;
  }

  const canRefresh = hasPermission("refresh");
  const canDownloadReports = hasPermission("downloadReports");
  const canCreateAudit = hasPermission("createAudit");
  const canCreateTraining = hasPermission("createTraining");
  const canUploadDocuments = hasPermission("uploadDocuments");
  const canManageWorkflows = hasPermission("manageWorkflows");
  const canProcessDocuments = hasPermission("processDocuments");
  const canCollaborate = hasPermission("collaborate");
  const canViewAnalytics = hasPermission("viewAnalytics");

  el.refreshLiveData.disabled = !canRefresh;
  el.downloadCsv.disabled = !canDownloadReports;
  el.downloadPdf.disabled = !canDownloadReports;
  if (el.ocrRunBtn) el.ocrRunBtn.disabled = !canProcessDocuments;
  if (el.refreshAnalyticsBtn) el.refreshAnalyticsBtn.disabled = !canViewAnalytics;
  if (el.commentForm) setSectionPermission(el.commentForm, el.workflowRbacNote, canCollaborate, t("rbac.noCollaborate"), false);
  if (el.workflowStartForm) setSectionPermission(el.workflowStartForm, el.workflowRbacNote, canManageWorkflows, t("rbac.noManageWorkflows"), true);
  if (el.workflowAdvanceForm)
    setSectionPermission(el.workflowAdvanceForm, el.workflowRbacNote, canManageWorkflows, t("rbac.noManageWorkflows"), true);

  setSectionPermission(el.auditForm, el.auditRbacNote, canCreateAudit, t("rbac.noCreateAudit"));
  setSectionPermission(el.trainingForm, el.trainingRbacNote, canCreateTraining, t("rbac.noCreateTraining"));
  setSectionPermission(el.documentUploadForm, el.documentsRbacNote, canUploadDocuments, t("rbac.noUploadDocuments"));
  setSectionPermission(el.workflowTemplateForm, el.workflowRbacNote, canManageWorkflows, t("rbac.noManageWorkflows"));
  toggleReportPermission(canDownloadReports, t("rbac.noExport"));

  el.authStatus.textContent = t("status.authenticated", {
    name: appState.auth.user.fullName,
    role: roleLabel(appState.auth.user.role)
  });
  renderCapabilities();
}

function ensureAuthed() {
  if (!appState.auth.token) throw new Error(t("error.signInRequired"));
}

async function apiFetch(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (!headers.has("Content-Type") && options.body) headers.set("Content-Type", "application/json");
  if (appState.auth.token) headers.set("Authorization", `Bearer ${appState.auth.token}`);

  const response = await fetch(`${appState.apiBaseUrl}${path}`, { ...options, headers });
  if (!response.ok) {
    let message = `Request failed (${response.status})`;
    try {
      const payload = await response.json();
      message = payload?.error?.message || message;
    } catch {
      // ignore
    }
    if (response.status === 401) logoutLocal(t("toast.sessionExpired"));
    throw new Error(message);
  }
  return response.json();
}

async function toBase64(file) {
  const buffer = await file.arrayBuffer();
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let index = 0; index < bytes.length; index += 1) binary += String.fromCharCode(bytes[index]);
  return btoa(binary);
}

function parseWorkflowSteps(raw) {
  return raw
    .split(/[\n,]/g)
    .map(step => step.trim())
    .filter(Boolean);
}

async function refreshLiveData(showToast = true) {
  ensureAuthed();
  const [dashboardResult, auditsResult, trainingsResult, documentsResult] = await Promise.all([
    apiFetch("/dashboard"),
    apiFetch("/compliance/audits"),
    apiFetch("/training/plans"),
    apiFetch("/documents")
  ]);

  appState.dashboard = dashboardResult.data;
  appState.audits = auditsResult.data;
  appState.trainings = trainingsResult.data;
  appState.documents = documentsResult.data;
  if (!appState.selectedDocId && appState.documents.length) {
    appState.selectedDocId = appState.documents[0].id;
  }

  mapServicesFromLiveData();
  persistState();
  await refreshIntelligenceData(false);
  renderAll();
  if (showToast) toast(t("toast.liveRefreshed"), "success");
}

async function refreshIntelligenceData(showToast = false) {
  if (!appState.auth.token) return;
  const [processingResult, templateResult, runsResult, trailResult, analyticsResult] = await Promise.all([
    apiFetch("/documents/processing"),
    apiFetch("/workflows/templates"),
    apiFetch("/workflows/runs"),
    apiFetch("/collaboration/audit-trail"),
    apiFetch("/analytics/documents")
  ]);
  appState.documentProcessing = processingResult.data;
  appState.workflowTemplates = templateResult.data;
  appState.workflowRuns = runsResult.data;
  appState.auditTrail = trailResult.data;
  appState.analytics = analyticsResult.data;

  if (appState.selectedDocId) {
    const commentsResult = await apiFetch(`/collaboration/comments/${appState.selectedDocId}`);
    appState.comments = commentsResult.data;
  } else {
    appState.comments = [];
  }

  populateDocSelects();
  populateWorkflowSelects();
  renderIntelligencePanel();
  if (showToast) toast(t("toast.intelligenceRefreshed"), "success");
}

function mapServicesFromLiveData() {
  const dashboard = appState.dashboard;
  if (!dashboard) return;
  const risk = clamp(Number(dashboard.riskScore || 0), 0, 100);
  const readiness = clamp(Number(dashboard.readinessScore || 0), 0, 100);
  appState.services = appState.services.map(service => {
    if (service.key === "compliance") return { ...service, risk, progress: clamp(readiness - 8, 5, 99) };
    if (service.key === "training") {
      return { ...service, risk: clamp(100 - readiness, 10, 90), progress: clamp(readiness - 2, 5, 99) };
    }
    return {
      ...service,
      risk: clamp(Math.round((service.risk + risk) / 2), 10, 95),
      progress: clamp(Math.round((service.progress + readiness) / 2), 5, 99)
    };
  });
}

function buildKpis() {
  const readiness = computeReadiness();
  const avgRisk = Math.round(appState.services.reduce((sum, service) => sum + service.risk, 0) / appState.services.length);
  const avgProgress = Math.round(
    appState.services.reduce((sum, service) => sum + service.progress, 0) / appState.services.length
  );
  return [
    { label: t("kpi.readiness"), value: formatPercent(readiness) },
    { label: t("kpi.avgProgress"), value: formatPercent(avgProgress) },
    {
      label: t("kpi.risk"),
      value: appState.dashboard ? `${formatNumber(appState.dashboard.riskScore)}/100` : `${formatNumber(avgRisk)}/100`
    },
    {
      label: t("kpi.openFindings"),
      value: appState.dashboard ? formatNumber(appState.dashboard.openAuditFindings) : formatNumber(appState.audits.length)
    }
  ];
}

function computeReadiness() {
  if (appState.dashboard?.readinessScore) return clamp(Number(appState.dashboard.readinessScore), 5, 98);
  const base = appState.profile ? appState.profile.digitalMaturity * 9 + appState.profile.paraePreparedness * 11 : 15;
  const serviceContribution =
    appState.services.reduce((sum, service) => sum + service.progress - service.risk * 0.32, 0) / appState.services.length;
  return clamp(Math.round(base + serviceContribution), 5, 98);
}

function buildIndicators() {
  const openCritical = appState.audits.filter(item => item.severity === "Critical").length;
  const openHigh = appState.audits.filter(item => item.severity === "High").length;
  const trainingCoverage = appState.trainings.length
    ? Math.round(
        appState.trainings.reduce((sum, training) => sum + (training.targetCompletion ?? training.target ?? 0), 0) /
          appState.trainings.length
      )
    : 0;
  const automationService = appState.services.find(service => service.key === "automation");
  const aiService = appState.services.find(service => service.key === "ai-workflow");
  return [
    { title: t("indicator.critical"), value: formatNumber(openCritical), note: t("indicator.note.critical") },
    { title: t("indicator.high"), value: formatNumber(openHigh), note: t("indicator.note.high") },
    { title: t("indicator.coverage"), value: formatPercent(trainingCoverage), note: t("indicator.note.coverage") },
    {
      title: t("indicator.automation"),
      value: formatPercent(automationService?.progress || 0),
      note: t("indicator.note.automation")
    },
    { title: t("indicator.ai"), value: formatPercent(aiService?.progress || 0), note: t("indicator.note.ai") },
    {
      title: t("indicator.cyber"),
      value: `${formatNumber(appState.services.find(service => service.key === "cyber")?.risk || 0)}/100`,
      note: t("indicator.note.cyber")
    }
  ];
}

function buildActionQueue() {
  const topRiskServices = [...appState.services]
    .sort((a, b) => b.risk - a.risk)
    .slice(0, 3)
    .map(service => t("queue.action.reduceRisk", { service: t(`service.${service.key}`).toLowerCase() }));

  const actions = [
    appState.audits.length
      ? t("queue.action.close", { count: formatNumber(Math.min(3, appState.audits.length)) })
      : t("queue.action.launch"),
    appState.trainings.length
      ? t("queue.action.increase", { count: formatNumber(appState.trainings.length) })
      : t("queue.action.startTraining"),
    ...topRiskServices,
    t("queue.action.publish")
  ];
  return actions.slice(0, 6);
}

function renderAll() {
  const readiness = computeReadiness();
  el.readinessScore.textContent = formatPercent(readiness);
  el.readinessCaption.textContent = readiness >= 70 ? t("status.readyHigh") : t("status.readyLow");
  renderKpis();
  renderServices();
  renderActionQueue();
  renderAudits();
  renderTrainings();
  renderDocuments();
  renderIndicators();
  renderIntelligencePanel();
  renderTags();
}

function renderKpis() {
  el.kpiGrid.innerHTML = buildKpis()
    .map(
      item => `
        <article class="kpi">
          <h3>${item.label}</h3>
          <div class="value">${item.value}</div>
        </article>
      `
    )
    .join("");
}

function renderServices() {
  el.serviceCards.innerHTML = appState.services
    .map(service => {
      const badgeClass = service.risk > 70 ? "badge--high" : service.risk > 45 ? "badge--medium" : "badge--low";
      const badgeLabel = service.risk > 70 ? t("severity.high") : service.risk > 45 ? t("severity.medium") : t("severity.low");
      return `
        <article class="service-card">
          <div class="service-head">
            <h3>${t(`service.${service.key}`)}</h3>
            <span class="badge ${badgeClass}">${badgeLabel}</span>
          </div>
          <p class="muted">${t(`service.detail.${service.key}`)}</p>
          <p><strong>${t("list.progress")}:</strong> ${formatPercent(service.progress)} &nbsp; | &nbsp; <strong>${t("list.risk")}:</strong> ${formatNumber(service.risk)}/100</p>
        </article>
      `;
    })
    .join("");
}

function renderActionQueue() {
  el.actionQueue.innerHTML = buildActionQueue().map(action => `<li>${action}</li>`).join("");
}

function renderAudits() {
  if (!appState.audits.length) {
    el.auditList.innerHTML = `<p class="muted">${t("list.noFindings")}</p>`;
    return;
  }
  el.auditList.innerHTML = appState.audits
    .map(
      item => `
      <article class="list-item">
        <div class="item-head">
          <strong>${item.standard}</strong>
          <span class="badge ${severityToBadge(item.severity)}">${translateSeverity(item.severity)}</span>
        </div>
        <p>${item.finding}</p>
        <p class="muted">${t("list.owner")}: ${item.owner} | ${t("list.due")}: ${formatDate(item.dueDate)} | ${t("list.status")}: ${translateAuditStatus(item.status)}</p>
      </article>
    `
    )
    .join("");
}

function renderTrainings() {
  if (!appState.trainings.length) {
    el.trainingList.innerHTML = `<p class="muted">${t("list.noTraining")}</p>`;
    return;
  }
  el.trainingList.innerHTML = appState.trainings
    .map(item => {
      const target = item.targetCompletion ?? item.target;
      return `
      <article class="list-item">
        <div class="item-head">
          <strong>${item.program}</strong>
          <span class="badge badge--low">${translateTrainingMode(item.mode)}</span>
        </div>
        <p>${item.objective}</p>
        <p class="muted">${t("list.audience")}: ${item.audience} | ${t("list.target")}: ${formatPercent(target)}</p>
      </article>
    `;
    })
    .join("");
}

function renderDocuments() {
  if (!appState.documents.length) {
    el.documentsList.innerHTML = `<p class="muted">${t("list.noDocuments")}</p>`;
    return;
  }
  el.documentsList.innerHTML = appState.documents
    .map(
      item => `
      <article class="list-item">
        <div class="item-head">
          <strong>${escapeHtml(item.title)}</strong>
          <button class="btn btn--secondary document-download-btn" data-document-id="${escapeHtml(item.id)}" data-file-name="${escapeHtml(item.fileName)}">${t("list.download")}</button>
        </div>
        <p class="muted">${escapeHtml(item.fileName)}</p>
        <p class="muted">${t("list.documentCategory")}: ${escapeHtml(item.category)} | ${t("list.documentSize")}: ${formatBytes(item.sizeBytes)} | ${t("list.documentDate")}: ${formatDateTime(item.uploadedAt)}</p>
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

function populateDocSelects() {
  if (!el.opsDocumentSelect) return;
  const options = appState.documents
    .map(
      doc =>
        `<option value="${escapeHtml(doc.id)}"${doc.id === appState.selectedDocId ? " selected" : ""}>${escapeHtml(doc.title)} (${escapeHtml(doc.fileName)})</option>`
    )
    .join("");
  el.opsDocumentSelect.innerHTML = options || `<option value="">${t("docOps.common.noDocumentOption")}</option>`;
}

function populateWorkflowSelects() {
  if (el.templateSelect) {
    el.templateSelect.innerHTML =
      appState.workflowTemplates
        .map(template => `<option value="${escapeHtml(template.id)}">${escapeHtml(template.name)}</option>`)
        .join("") || `<option value="">${t("docOps.workflow.noTemplate")}</option>`;
  }
  if (el.runSelect) {
    el.runSelect.innerHTML =
      appState.workflowRuns
        .map(
          run =>
            `<option value="${escapeHtml(run.id)}">${escapeHtml(run.id)} - ${translateWorkflowRunStatus(run.status)}</option>`
        )
        .join("") || `<option value="">${t("docOps.workflow.noRun")}</option>`;
  }
}

function renderIntelligencePanel() {
  renderOcrResults();
  renderWorkflowTemplates();
  renderWorkflowRuns();
  renderVersions();
  renderComments();
  renderAuditTrail();
  renderAnalytics();
}

function renderOcrResults() {
  if (!el.ocrResult || !el.processingList) return;
  if (!appState.latestOcrResult) {
    el.ocrResult.innerHTML = `<p class="muted">${t("docOps.ocr.empty")}</p>`;
  } else {
    const result = appState.latestOcrResult;
    el.ocrResult.innerHTML = `
      <article class="list-item">
        <div class="item-head">
          <strong>${t("docOps.ocr.resultTitle")}</strong>
          <span class="badge badge--low">${formatPercent(result.ocr.confidence)}</span>
        </div>
        <p><strong>${t("docOps.ocr.engine")}:</strong> ${escapeHtml(result.ocr.engine)}</p>
        <p><strong>${t("docOps.ocr.route")}:</strong> ${t(DOC_OP_DEPARTMENTS[result.routing.department] || result.routing.department)}</p>
        <p class="muted">${escapeHtml(result.routing.reason)}</p>
        <p>${escapeHtml(result.ocr.extractedText.slice(0, 280))}</p>
      </article>
    `;
  }

  if (!appState.documentProcessing.length) {
    el.processingList.innerHTML = `<p class="muted">${t("docOps.ocr.historyEmpty")}</p>`;
    return;
  }

  el.processingList.innerHTML = appState.documentProcessing
    .slice(0, 6)
    .map(
      record => `
      <article class="list-item">
        <p><strong>${t("docOps.common.document")}:</strong> ${escapeHtml(record.documentId)} | <strong>${t("docOps.ocr.route")}:</strong> ${t(DOC_OP_DEPARTMENTS[record.routedDepartment] || record.routedDepartment)}</p>
        <p class="muted">${formatDateTime(record.processedAt)} | ${formatPercent(record.ocrConfidence)}</p>
      </article>
    `
    )
    .join("");
}

function renderWorkflowTemplates() {
  if (!el.workflowTemplatesList) return;
  if (!appState.workflowTemplates.length) {
    el.workflowTemplatesList.innerHTML = `<p class="muted">${t("docOps.workflow.noTemplate")}</p>`;
    return;
  }
  el.workflowTemplatesList.innerHTML = appState.workflowTemplates
    .map(
      template => `
      <article class="list-item">
        <div class="item-head">
          <strong>${escapeHtml(template.name)}</strong>
          <span class="badge badge--medium">${t(DOC_OP_DEPARTMENTS[template.department] || template.department)}</span>
        </div>
        <p>${template.steps.map(step => escapeHtml(step)).join(" -> ")}</p>
      </article>
    `
    )
    .join("");
}

function renderWorkflowRuns() {
  if (!el.workflowRunsList) return;
  if (!appState.workflowRuns.length) {
    el.workflowRunsList.innerHTML = `<p class="muted">${t("docOps.workflow.noRun")}</p>`;
    return;
  }
  el.workflowRunsList.innerHTML = appState.workflowRuns
    .map(
      run => `
      <article class="list-item">
        <div class="item-head">
          <strong>${escapeHtml(run.id)}</strong>
          <span class="badge ${run.status === "Approved" ? "badge--low" : run.status === "Rejected" ? "badge--high" : "badge--medium"}">${translateWorkflowRunStatus(run.status)}</span>
        </div>
        <p>${t("docOps.workflow.stepProgress", { index: run.currentStepIndex + 1, total: run.steps.length })}</p>
        <p class="muted">${run.steps.map(step => `${escapeHtml(step.name)}: ${translateWorkflowStepStatus(step.status)}`).join(" | ")}</p>
      </article>
    `
    )
    .join("");
}

function renderVersions() {
  if (!el.versionsList) return;
  const selected = appState.selectedDocId;
  if (!selected) {
    el.versionsList.innerHTML = `<p class="muted">${t("docOps.collab.noVersion")}</p>`;
    return;
  }
  apiFetch(`/documents/${selected}/versions`)
    .then(result => {
      const versions = result.data || [];
      if (!versions.length) {
        el.versionsList.innerHTML = `<p class="muted">${t("docOps.collab.noVersion")}</p>`;
        return;
      }
      el.versionsList.innerHTML = versions
        .map(
          version => `
        <article class="list-item">
          <div class="item-head">
            <strong>${t("docOps.collab.versionLabel", { number: version.versionNumber })}</strong>
            <span class="badge badge--low">${escapeHtml(version.encryption?.algorithm || "AES-256-GCM")}</span>
          </div>
          <p>${escapeHtml(version.fileName)} (${formatBytes(version.sizeBytes)})</p>
        </article>
      `
        )
        .join("");
    })
    .catch(() => {
      el.versionsList.innerHTML = `<p class="muted">${t("docOps.collab.noVersion")}</p>`;
    });
}

function renderComments() {
  if (!el.commentsList) return;
  if (!appState.comments.length) {
    el.commentsList.innerHTML = `<p class="muted">${t("docOps.collab.noComments")}</p>`;
    return;
  }
  el.commentsList.innerHTML = appState.comments
    .map(
      comment => `
      <article class="list-item">
        <p>${escapeHtml(comment.message)}</p>
        <p class="muted">${formatDateTime(comment.createdAt)}</p>
      </article>
    `
    )
    .join("");
}

function renderAuditTrail() {
  if (!el.auditTrailList) return;
  if (!appState.auditTrail.length) {
    el.auditTrailList.innerHTML = `<p class="muted">${t("docOps.collab.noAuditTrail")}</p>`;
    return;
  }
  el.auditTrailList.innerHTML = appState.auditTrail
    .slice(0, 8)
    .map(
      event => `
      <article class="list-item">
        <div class="item-head">
          <strong>${translateEventAction(event.action)}</strong>
          <span class="badge badge--medium">${escapeHtml(event.actorId)}</span>
        </div>
        <p class="muted">${formatDateTime(event.createdAt)}</p>
      </article>
    `
    )
    .join("");
}

function renderAnalytics() {
  if (!el.analyticsGrid) return;
  if (!appState.analytics) {
    el.analyticsGrid.innerHTML = `<p class="muted">${t("docOps.analytics.empty")}</p>`;
    return;
  }
  const cards = [
    { label: t("docOps.analytics.ocr"), value: formatPercent(appState.analytics.ocr.averageConfidence) },
    { label: t("docOps.analytics.routed"), value: formatNumber(appState.analytics.routing.totalRouted) },
    { label: t("docOps.analytics.workflow"), value: formatPercent(appState.analytics.workflow.automationRatePercent) },
    { label: t("docOps.analytics.collab"), value: formatNumber(appState.analytics.collaboration.comments) },
    { label: t("docOps.analytics.efficiency"), value: `${formatDecimal(appState.analytics.efficiency.averageProcessingTimeSeconds)}s` },
    { label: t("docOps.analytics.security"), value: appState.analytics.security.encryptionAtRest }
  ];
  el.analyticsGrid.innerHTML = cards
    .map(
      card => `
      <article class="kpi">
        <h3>${card.label}</h3>
        <div class="value">${escapeHtml(card.value)}</div>
      </article>
    `
    )
    .join("");
}

async function downloadReport(format) {
  ensureAuthed();
  if (!hasPermission("downloadReports")) throw new Error(t("error.noReportPermission"));
  const response = await fetch(`${appState.apiBaseUrl}/reports/compliance?format=${format}`, {
    method: "GET",
    headers: { Authorization: `Bearer ${appState.auth.token}` }
  });
  if (!response.ok) throw new Error(`Failed to download ${format.toUpperCase()} report.`);
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
  toast(format === "pdf" ? t("toast.pdfDownloaded") : t("toast.csvDownloaded"), "success");
}

async function downloadDocument(documentId, fileName) {
  ensureAuthed();
  const response = await fetch(`${appState.apiBaseUrl}/documents/${documentId}/download`, {
    method: "GET",
    headers: { Authorization: `Bearer ${appState.auth.token}` }
  });
  if (!response.ok) throw new Error(`Failed to download document (${response.status}).`);
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = fileName || `document-${documentId}`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
  toast(t("toast.documentDownloaded"), "success");
}

function handleConnectionSubmit(event) {
  event.preventDefault();
  const formData = new FormData(event.currentTarget);
  const raw = formData.get("apiBaseUrl")?.toString().trim();
  if (!raw) {
    toast(t("toast.apiEmpty"), "error");
    return;
  }
  appState.apiBaseUrl = raw.replace(/\/+$/, "");
  persistState();
  toast(t("toast.apiSaved"), "success");
}

async function handleLoginSubmit(event) {
  event.preventDefault();
  const formData = new FormData(event.currentTarget);
  const email = formData.get("email")?.toString().trim() || "";
  const password = formData.get("password")?.toString() || "";
  if (!email || !password) {
    toast(t("toast.credentialsMissing"), "error");
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
    toast(t("toast.welcome", { name: login.data.user.fullName }), "success");
    await refreshLiveData(false);
    toast(t("toast.liveRefreshed"), "success");
  } catch (error) {
    handleError(error);
  }
}

async function handleRegisterSubmit(event) {
  event.preventDefault();
  const formData = new FormData(event.currentTarget);
  const fullName = formData.get("fullName")?.toString().trim() || "";
  const email = formData.get("email")?.toString().trim() || "";
  const role = formData.get("role")?.toString() || "";
  const password = formData.get("password")?.toString() || "";
  const confirmPassword = formData.get("confirmPassword")?.toString() || "";
  if (!fullName || !email || !role || !password || !confirmPassword) {
    toast(t("toast.registrationMissing"), "error");
    return;
  }
  if (password !== confirmPassword) {
    toast(t("toast.registrationPasswordMismatch"), "error");
    return;
  }
  try {
    const register = await apiFetch("/auth/register", {
      method: "POST",
      body: JSON.stringify({ fullName, email, password, role })
    });
    appState.auth.token = register.data.accessToken;
    appState.auth.user = register.data.user;
    persistState();
    updateAuthUi();
    event.currentTarget.reset();
    toast(t("toast.registrationSuccess", { name: register.data.user.fullName }), "success");
    await refreshLiveData(false);
    toast(t("toast.liveRefreshed"), "success");
  } catch (error) {
    handleError(error);
  }
}

function logoutLocal(message) {
  appState.auth = { token: "", user: null };
  appState.dashboard = null;
  appState.audits = [];
  appState.trainings = [];
  appState.documents = [];
  appState.documentProcessing = [];
  appState.workflowTemplates = [];
  appState.workflowRuns = [];
  appState.comments = [];
  appState.auditTrail = [];
  appState.analytics = null;
  appState.latestOcrResult = null;
  appState.selectedDocId = "";
  persistState();
  updateAuthUi();
  renderAll();
  if (message) toast(message, "success");
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
  toast(t("toast.profileSaved"), "success");
}

async function handleAuditSubmit(event) {
  event.preventDefault();
  ensureAuthed();
  if (!hasPermission("createAudit")) throw new Error(t("error.noAuditPermission"));
  const form = new FormData(event.currentTarget);
  const payload = {
    standard: form.get("standard")?.toString().trim(),
    severity: form.get("severity")?.toString(),
    owner: form.get("owner")?.toString().trim(),
    dueDate: form.get("dueDate")?.toString(),
    finding: form.get("finding")?.toString().trim()
  };
  try {
    await apiFetch("/compliance/audits", { method: "POST", body: JSON.stringify(payload) });
    event.currentTarget.reset();
    toast(t("toast.auditCreated"), "success");
    await refreshLiveData(false);
  } catch (error) {
    handleError(error);
  }
}

async function handleTrainingSubmit(event) {
  event.preventDefault();
  ensureAuthed();
  if (!hasPermission("createTraining")) throw new Error(t("error.noTrainingPermission"));
  const form = new FormData(event.currentTarget);
  const payload = {
    program: form.get("program")?.toString().trim(),
    audience: form.get("audience")?.toString().trim(),
    mode: form.get("mode")?.toString(),
    targetCompletion: Number(form.get("target")),
    objective: form.get("objective")?.toString().trim()
  };
  try {
    await apiFetch("/training/plans", { method: "POST", body: JSON.stringify(payload) });
    event.currentTarget.reset();
    toast(t("toast.trainingCreated"), "success");
    await refreshLiveData(false);
  } catch (error) {
    handleError(error);
  }
}

async function handleDocumentUploadSubmit(event) {
  event.preventDefault();
  ensureAuthed();
  if (!hasPermission("uploadDocuments")) throw new Error(t("error.noDocumentPermission"));
  const form = event.currentTarget;
  const formData = new FormData(form);
  const title = formData.get("title")?.toString().trim() || "";
  const category = formData.get("category")?.toString().trim() || "";
  const file = formData.get("documentFile");
  if (!(file instanceof File) || !file.name) throw new Error(t("documents.fileRequired"));
  try {
    const contentBase64 = await toBase64(file);
    await apiFetch("/documents/upload", {
      method: "POST",
      body: JSON.stringify({
        title,
        category,
        fileName: file.name,
        mimeType: file.type || "application/octet-stream",
        contentBase64
      })
    });
    form.reset();
    toast(t("toast.documentUploaded"), "success");
    await refreshLiveData(false);
  } catch (error) {
    handleError(error);
  }
}

async function runOcrForSelectedDocument() {
  ensureAuthed();
  if (!hasPermission("processDocuments")) throw new Error(t("error.noProcessPermission"));
  if (!appState.selectedDocId) throw new Error(t("error.selectDocument"));
  const result = await apiFetch(`/documents/${appState.selectedDocId}/process`, { method: "POST" });
  appState.latestOcrResult = result.data;
  await refreshIntelligenceData(false);
  renderIntelligencePanel();
  toast(t("toast.ocrProcessed"), "success");
}

async function handleDocumentVersionSubmit(event) {
  event.preventDefault();
  ensureAuthed();
  if (!hasPermission("collaborate")) throw new Error(t("error.noCollaborate"));
  if (!appState.selectedDocId) throw new Error(t("error.selectDocument"));
  const formData = new FormData(event.currentTarget);
  const file = formData.get("versionFile");
  if (!(file instanceof File) || !file.name) throw new Error(t("documents.fileRequired"));
  try {
    const contentBase64 = await toBase64(file);
    await apiFetch("/documents/version", {
      method: "POST",
      body: JSON.stringify({
        documentId: appState.selectedDocId,
        fileName: file.name,
        mimeType: file.type || "application/octet-stream",
        contentBase64
      })
    });
    event.currentTarget.reset();
    await refreshLiveData(false);
    toast(t("toast.versionUploaded"), "success");
  } catch (error) {
    handleError(error);
  }
}

async function handleCommentSubmit(event) {
  event.preventDefault();
  ensureAuthed();
  if (!hasPermission("collaborate")) throw new Error(t("error.noCollaborate"));
  if (!appState.selectedDocId) throw new Error(t("error.selectDocument"));
  const formData = new FormData(event.currentTarget);
  const message = formData.get("message")?.toString().trim() || "";
  if (!message) return;
  try {
    await apiFetch("/collaboration/comments", {
      method: "POST",
      body: JSON.stringify({ documentId: appState.selectedDocId, message })
    });
    event.currentTarget.reset();
    await refreshIntelligenceData(false);
    toast(t("toast.commentAdded"), "success");
  } catch (error) {
    handleError(error);
  }
}

async function handleWorkflowTemplateSubmit(event) {
  event.preventDefault();
  ensureAuthed();
  if (!hasPermission("manageWorkflows")) throw new Error(t("error.noManageWorkflows"));
  const formData = new FormData(event.currentTarget);
  const name = formData.get("name")?.toString().trim() || "";
  const department = formData.get("department")?.toString() || "operations";
  const steps = parseWorkflowSteps(formData.get("steps")?.toString() || "");
  if (steps.length < 2) throw new Error(t("error.stepsMin"));
  try {
    await apiFetch("/workflows/templates", {
      method: "POST",
      body: JSON.stringify({ name, department, steps })
    });
    event.currentTarget.reset();
    await refreshIntelligenceData(false);
    toast(t("toast.workflowTemplateCreated"), "success");
  } catch (error) {
    handleError(error);
  }
}

async function handleWorkflowStartSubmit(event) {
  event.preventDefault();
  ensureAuthed();
  if (!hasPermission("manageWorkflows")) throw new Error(t("error.noManageWorkflows"));
  if (!appState.selectedDocId) throw new Error(t("error.selectDocument"));
  const formData = new FormData(event.currentTarget);
  const templateId = formData.get("templateId")?.toString() || "";
  if (!templateId) throw new Error(t("error.selectTemplate"));
  try {
    await apiFetch("/workflows/runs/start", {
      method: "POST",
      body: JSON.stringify({ templateId, documentId: appState.selectedDocId })
    });
    await refreshIntelligenceData(false);
    toast(t("toast.workflowRunStarted"), "success");
  } catch (error) {
    handleError(error);
  }
}

async function handleWorkflowAdvanceSubmit(event) {
  event.preventDefault();
  ensureAuthed();
  if (!hasPermission("manageWorkflows")) throw new Error(t("error.noManageWorkflows"));
  const formData = new FormData(event.currentTarget);
  const runId = formData.get("runId")?.toString() || "";
  const action = formData.get("action")?.toString() || "approve";
  const comment = formData.get("comment")?.toString().trim() || "";
  if (!runId) throw new Error(t("error.selectRun"));
  try {
    await apiFetch("/workflows/runs/advance", {
      method: "POST",
      body: JSON.stringify({ runId, action, comment })
    });
    event.currentTarget.reset();
    await refreshIntelligenceData(false);
    toast(t("toast.workflowRunAdvanced"), "success");
  } catch (error) {
    handleError(error);
  }
}

function translateSeverity(severity) {
  if (severity === "Critical") return t("severity.critical");
  if (severity === "High") return t("severity.high");
  if (severity === "Medium") return t("severity.medium");
  return t("severity.low");
}

function translateAuditStatus(status) {
  return t(`auditStatus.${status}`);
}

function translateTrainingMode(mode) {
  if (mode === "In-person") return t("training.mode.inperson");
  if (mode === "Hybrid") return t("training.mode.hybrid");
  if (mode === "Virtual") return t("training.mode.virtual");
  return mode;
}

function severityToBadge(severity) {
  if (severity === "Critical" || severity === "High") return "badge--high";
  if (severity === "Medium") return "badge--medium";
  return "badge--low";
}

function tuneServiceModelFromProfile() {
  if (!appState.profile) return;
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

function bindEvents() {
  el.languageSelect?.addEventListener("change", event => {
    appState.language = event.currentTarget.value === "fr" ? "fr" : "en";
    appState.languageManualOverride = true;
    persistState();
    applyI18n();
    renderAll();
    updateAuthUi();
  });

  el.connectionForm.addEventListener("submit", handleConnectionSubmit);
  el.loginForm.addEventListener("submit", handleLoginSubmit);
  el.registerForm.addEventListener("submit", handleRegisterSubmit);
  el.logoutBtn.addEventListener("click", () => logoutLocal(t("toast.signedOut")));
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
  el.documentUploadForm.addEventListener("submit", handleDocumentUploadSubmit);
  el.versionUploadForm?.addEventListener("submit", handleDocumentVersionSubmit);
  el.commentForm?.addEventListener("submit", handleCommentSubmit);
  el.workflowTemplateForm?.addEventListener("submit", handleWorkflowTemplateSubmit);
  el.workflowStartForm?.addEventListener("submit", handleWorkflowStartSubmit);
  el.workflowAdvanceForm?.addEventListener("submit", handleWorkflowAdvanceSubmit);
  el.refreshAnalyticsBtn?.addEventListener("click", () => {
    refreshIntelligenceData(true).catch(handleError);
  });
  el.ocrRunBtn?.addEventListener("click", () => {
    runOcrForSelectedDocument().catch(handleError);
  });
  el.opsDocumentSelect?.addEventListener("change", async event => {
    appState.selectedDocId = event.currentTarget.value || "";
    if (appState.selectedDocId) {
      const commentsResult = await apiFetch(`/collaboration/comments/${appState.selectedDocId}`);
      appState.comments = commentsResult.data;
    } else {
      appState.comments = [];
    }
    renderIntelligencePanel();
  });

  el.documentsList.addEventListener("click", event => {
    const button = event.target.closest(".document-download-btn");
    if (!button) return;
    const documentId = button.getAttribute("data-document-id") || "";
    const fileName = button.getAttribute("data-file-name") || "";
    downloadDocument(documentId, fileName).catch(handleError);
  });
}

function registerServiceWorker() {
  if (!("serviceWorker" in navigator)) return;
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("./service-worker.js").catch(error => {
      console.error("Service worker registration failed", error);
    });
  });
}

function autoDetectLanguageOnFirstLoad() {
  const browserLanguage = navigator.language?.toLowerCase() || "";
  appState.language = browserLanguage.startsWith("fr") ? "fr" : "en";
}

function init() {
  hydrateState();
  applyI18n();
  syncConnectionFields();
  renderAll();
  updateAuthUi();
  bindEvents();
  registerServiceWorker();
  if (appState.auth.token) {
    refreshLiveData(false).catch(() => {
      logoutLocal(t("toast.sessionExpired"));
    });
  }
}

init();
