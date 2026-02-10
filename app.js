const STORAGE_KEY = "susukonnect_mvp_data_v1";
const SESSION_KEY = "susukonnect_mvp_session_v1";
const DEVICE_KEY = "susukonnect_device_fingerprint_v1";
const SESSION_TIMEOUT_MINUTES = 30;
const PLATFORM_FEE_RATE = 0.015;
const ADMIN_PAYOUT_APPROVAL_THRESHOLD = 2000;
const RUNTIME_ERROR_TOAST_COOLDOWN_MS = 3000;

let storageWarningShown = false;
let lastRuntimeErrorToastAt = 0;

const PAYOUT_REASONS = [
  "College tuition",
  "Wedding",
  "Rent / Housing",
  "Medical procedure",
  "Family vacation",
  "Business investment",
  "Emergency",
  "Custom reason",
];

const CURRENCIES = ["USD", "GHS", "NGN", "XOF", "EUR", "GBP", "CFA"];

const PRIORITY_WEIGHTS = {
  Emergency: 100,
  "Medical procedure": 90,
  "Rent / Housing": 80,
  "College tuition": 70,
  "Business investment": 60,
  Wedding: 50,
  "Custom reason": 45,
  "Family vacation": 40,
};

const TAB_CONFIG = [
  { id: "dashboard", label: "Dashboard", roles: ["member", "leader", "admin"] },
  { id: "groups", label: "Groups", roles: ["member", "leader", "admin"] },
  {
    id: "contributions",
    label: "Contributions",
    roles: ["member", "leader", "admin"],
  },
  { id: "payouts", label: "Payouts", roles: ["member", "leader", "admin"] },
  { id: "chat", label: "Chat", roles: ["member", "leader", "admin"] },
  { id: "calendar", label: "Calendar", roles: ["member", "leader", "admin"] },
  {
    id: "notifications",
    label: "Notifications",
    roles: ["member", "leader", "admin"],
  },
  { id: "security", label: "Security", roles: ["member", "leader", "admin"] },
  { id: "admin", label: "Admin", roles: ["admin"] },
];

const state = {
  data: loadData(),
  session: loadSession(),
  activeTab: "dashboard",
  pendingMfa: null,
  groupFilters: {
    query: "",
    community: "",
    location: "",
    maxContribution: "",
    startDate: "",
  },
  selectedChatGroupId: null,
};

init();

function init() {
  try {
    state.data = ensureDataShape(state.data);
  } catch (error) {
    notifyRuntimeError("State migration failure", error);
    state.data = ensureDataShape(createSeedData());
    persistData();
  }
  if (state.session && !findUserById(state.session.userId)) {
    clearSession();
    state.session = null;
  }

  attachGlobalHandlers();
  withUiGuard("Initial data sync", () => synchronizeData());
  registerServiceWorker();
  render();

  setInterval(() => {
    withUiGuard("Background refresh", () => {
      enforceSessionTimeout();
      synchronizeData();
      render();
    });
  }, 30_000);
}

function attachGlobalHandlers() {
  document.addEventListener("submit", handleSubmit);
  document.addEventListener("click", handleClick);
  document.addEventListener("change", handleChange);
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && state.pendingMfa) {
      closeMfaModal();
    }
  });

  window.addEventListener("error", (event) => {
    notifyRuntimeError("Runtime error", event.error || event.message);
  });
  window.addEventListener("unhandledrejection", (event) => {
    notifyRuntimeError("Unhandled promise rejection", event.reason);
  });

  const mfaForm = document.getElementById("mfa-form");
  const mfaCancel = document.getElementById("mfa-cancel");
  if (mfaForm) {
    mfaForm.addEventListener("submit", handleMfaSubmit);
  }
  if (mfaCancel) {
    mfaCancel.addEventListener("click", () => closeMfaModal(true));
  }
}

function render() {
  try {
    enforceSessionTimeout();
    const user = getCurrentUser();

    if (user && !canAccessTab(user, state.activeTab)) {
      state.activeTab = "dashboard";
    }

    const appMain = document.getElementById("app-main");
    if (!appMain) {
      return;
    }
    appMain.innerHTML = user ? renderApp(user) : renderAuth();
    updateMfaModal();
  } catch (error) {
    notifyRuntimeError("Render failure", error);
    const appMain = document.getElementById("app-main");
    if (appMain) {
      appMain.innerHTML = `
        <section class="card">
          <h2>Something went wrong</h2>
          <p class="muted">
            SusuKonnect hit an unexpected error while rendering this screen.
            Please refresh and try again.
          </p>
          <div class="button-row">
            <button class="btn-primary" onclick="window.location.reload()">Reload app</button>
          </div>
        </section>
      `;
    }
  }
}

function renderAuth() {
  return `
    <section class="card">
      <h2>Collective savings, modernized for trust and security</h2>
      <p class="muted">
        SusuKonnect delivers a complete fintech MVP for traditional rotating savings circles:
        onboarding + KYC, verified groups, contributions, payouts, chat, reminders, and admin compliance.
      </p>
      <div class="auth-grid">
        <article class="card">
          <h3>Sign In</h3>
          <p class="small muted">MFA is enforced for new-device and sensitive activity.</p>
          <form id="login-form" class="form-grid">
            <div class="form-field full">
              <label for="login-email">Email</label>
              <input id="login-email" name="email" type="email" required />
            </div>
            <div class="form-field full">
              <label for="login-password">Password</label>
              <input id="login-password" name="password" type="password" required />
            </div>
            <div class="form-field full button-row">
              <button type="submit" class="btn-primary">Log in securely</button>
              <button type="button" data-action="biometric-login" class="btn-secondary">
                Biometric login
              </button>
            </div>
          </form>
          <div class="timeline small">
            <div class="timeline-item"><strong>Admin:</strong> admin@susukonnect.app / Admin@2026</div>
            <div class="timeline-item"><strong>Leader:</strong> leader@susukonnect.app / Leader@2026</div>
            <div class="timeline-item"><strong>Member:</strong> member@susukonnect.app / Member@2026</div>
          </div>
        </article>

        <article class="card">
          <h3>Create Account</h3>
          <p class="small muted">
            Terms acceptance is mandatory before account creation.
          </p>
          <form id="register-form" class="form-grid">
            <div class="form-field">
              <label for="register-name">Full name</label>
              <input id="register-name" name="fullName" required />
            </div>
            <div class="form-field">
              <label for="register-phone">Phone number</label>
              <input id="register-phone" name="phone" required />
            </div>
            <div class="form-field">
              <label for="register-email">Email</label>
              <input id="register-email" name="email" type="email" required />
            </div>
            <div class="form-field">
              <label for="register-password">Password</label>
              <input id="register-password" name="password" type="password" minlength="8" required />
            </div>
            <div class="form-field full">
              <label for="register-role">Role</label>
              <select id="register-role" name="role">
                <option value="member">Member</option>
                <option value="leader">Group Creator / Leader</option>
              </select>
            </div>
            <div class="form-field full checkbox-row">
              <input id="register-terms" name="acceptTerms" type="checkbox" />
              <label for="register-terms">
                I accept the Terms and Savings Agreement.
              </label>
            </div>
            <div class="form-field full">
              <button type="submit" class="btn-primary">Create trusted account</button>
            </div>
          </form>
        </article>
      </div>
    </section>
  `;
}

function renderApp(user) {
  const tabs = TAB_CONFIG.filter((tab) => tab.roles.includes(user.role));
  const activePanelHtml = safeRenderActivePanel(user);
  return `
    <div class="top-shell">
      <aside class="card profile-card">
        <h2>${escapeHtml(user.fullName)}</h2>
        <p class="muted">${escapeHtml(user.email)}</p>
        <div class="button-row">
          ${renderRoleBadge(user.role)}
          ${renderKycBadge(user.kyc.status)}
          ${user.verifiedBadge ? '<span class="status-badge status-success">Verified badge</span>' : ""}
        </div>
        <p class="small muted">
          Device fingerprint: <span class="chip">${escapeHtml(getDeviceFingerprint().slice(-12))}</span>
        </p>
        <p class="small muted">
          Session timeout: ${SESSION_TIMEOUT_MINUTES} minutes inactivity
        </p>
        <div class="button-row">
          <button class="btn-secondary" data-action="switch-tab" data-tab="security">Complete KYC / Security</button>
          <button class="btn-secondary" data-action="switch-tab" data-tab="notifications">View alerts</button>
          <button class="btn-danger" data-action="logout">Sign out</button>
        </div>
      </aside>

      <section>
        <nav class="nav-tabs">
          ${tabs
            .map(
              (tab) => `
                <button
                  class="nav-tab ${tab.id === state.activeTab ? "active" : ""}"
                  data-action="switch-tab"
                  data-tab="${tab.id}"
                >${tab.label}</button>
              `
            )
            .join("")}
        </nav>
        <div class="panel">${activePanelHtml}</div>
      </section>
    </div>
  `;
}

function safeRenderActivePanel(user) {
  try {
    return renderActivePanel(user);
  } catch (error) {
    notifyRuntimeError(`Panel render failure: ${state.activeTab}`, error);
    return `
      <section class="card">
        <h3>Feature temporarily unavailable</h3>
        <p class="muted">
          This screen hit an unexpected error. Try refreshing data or switching tabs.
        </p>
        <div class="button-row">
          <button class="btn-secondary" data-action="switch-tab" data-tab="dashboard">Go to Dashboard</button>
          <button class="btn-secondary" data-action="switch-tab" data-tab="notifications">Open Notifications</button>
        </div>
      </section>
    `;
  }
}

function renderActivePanel(user) {
  switch (state.activeTab) {
    case "dashboard":
      return renderDashboardPanel(user);
    case "groups":
      return renderGroupsPanel(user);
    case "contributions":
      return renderContributionsPanel(user);
    case "payouts":
      return renderPayoutsPanel(user);
    case "chat":
      return renderChatPanel(user);
    case "calendar":
      return renderCalendarPanel(user);
    case "notifications":
      return renderNotificationsPanel(user);
    case "security":
      return renderSecurityPanel(user);
    case "admin":
      return renderAdminPanel(user);
    default:
      return renderDashboardPanel(user);
  }
}

function renderDashboardPanel(user) {
  const memberGroups = getGroupsForUser(user.id);
  const pendingContributions = state.data.contributions.filter(
    (entry) =>
      entry.userId === user.id &&
      (entry.status === "pending" || entry.status === "late") &&
      isGroupMember(entry.groupId, user.id) &&
      isCurrentCycleContribution(entry)
  );
  const receivedPayouts = state.data.payouts.filter(
    (payout) => payout.recipientId === user.id && payout.status === "released"
  );
  const unreadCount = getUserNotifications(user.id).filter((item) => !item.read).length;
  const upcomingEvents = getCalendarEventsForUser(user.id).slice(0, 6);
  const recentTimeline = state.data.auditLogs
    .filter((log) => log.actorId === user.id || log.metadata?.targetUserId === user.id)
    .slice(-6)
    .reverse();

  return `
    <h2>Operational Dashboard</h2>
    <p class="muted">
      Trust and transparency status for your savings activity.
    </p>
    <div class="summary-grid">
      <article class="summary-item">
        <h4>Active groups</h4>
        <div class="value">${memberGroups.filter((group) => group.status === "active").length}</div>
      </article>
      <article class="summary-item">
        <h4>Pending contributions</h4>
        <div class="value">${pendingContributions.length}</div>
      </article>
      <article class="summary-item">
        <h4>Payouts received</h4>
        <div class="value">${receivedPayouts.length}</div>
      </article>
      <article class="summary-item">
        <h4>Unread alerts</h4>
        <div class="value">${unreadCount}</div>
      </article>
    </div>

    <section class="layout-columns" style="margin-top: 0.9rem;">
      <article class="card">
        <h3>Upcoming schedule</h3>
        ${
          upcomingEvents.length
            ? upcomingEvents
                .map(
                  (event) => `
                    <div class="event-item">
                      <strong>${escapeHtml(event.title)}</strong>
                      <div class="small muted">${formatDate(event.date)} • ${escapeHtml(event.groupName)}</div>
                      <div class="small">${escapeHtml(event.typeLabel)}</div>
                    </div>
                  `
                )
                .join("")
            : '<p class="muted">No upcoming events.</p>'
        }
      </article>
      <article class="card">
        <h3>Account timeline</h3>
        <div class="timeline">
          ${
            recentTimeline.length
              ? recentTimeline
                  .map(
                    (log) => `
                      <div class="timeline-item">
                        <strong>${escapeHtml(log.action)}</strong><br />
                        <span class="small muted">${formatDateTime(log.timestamp)}</span>
                      </div>
                    `
                  )
                  .join("")
              : '<p class="muted">Your secure activity timeline will appear here.</p>'
          }
        </div>
      </article>
    </section>
  `;
}

function renderGroupsPanel(user) {
  const filteredGroups = applyGroupFilters(state.data.groups);

  return `
    <h2>Savings Groups</h2>
    <p class="muted">
      Create circles, review transparent ledgers, and manage trusted membership.
    </p>
    <section class="layout-columns">
      <article class="card">
        <h3>Create a Group</h3>
        <p class="small muted">
          Includes payout order logic, contribution amount, grace period, and invite link generation.
        </p>
        <form id="create-group-form" class="form-grid">
          <div class="form-field">
            <label for="group-name">Group name</label>
            <input id="group-name" name="name" required />
          </div>
          <div class="form-field">
            <label for="group-community">Community type</label>
            <input id="group-community" name="communityType" placeholder="West African Diaspora" />
          </div>
          <div class="form-field full">
            <label for="group-description">Description</label>
            <textarea id="group-description" name="description" required></textarea>
          </div>
          <div class="form-field">
            <label for="group-location">Location</label>
            <input id="group-location" name="location" required />
          </div>
          <div class="form-field">
            <label for="group-start">Start date</label>
            <input id="group-start" name="startDate" type="date" required />
          </div>
          <div class="form-field">
            <label for="group-amount">Monthly contribution</label>
            <input id="group-amount" name="contributionAmount" type="number" min="1" step="0.01" required />
          </div>
          <div class="form-field">
            <label for="group-currency">Currency</label>
            <select id="group-currency" name="currency">
              ${CURRENCIES.map((currency) => `<option value="${currency}">${currency}</option>`).join("")}
            </select>
          </div>
          <div class="form-field">
            <label for="group-members">Total members</label>
            <input id="group-members" name="totalMembers" type="number" min="2" required />
          </div>
          <div class="form-field">
            <label for="group-grace">Grace period (days)</label>
            <input id="group-grace" name="gracePeriodDays" type="number" min="0" value="3" />
          </div>
          <div class="form-field">
            <label for="group-logic">Payout order logic</label>
            <select id="group-logic" name="payoutOrderLogic">
              <option value="fixed">Fixed rotation</option>
              <option value="voting">Voting-based</option>
              <option value="priority">Priority-based (reason scoring)</option>
            </select>
          </div>
          <div class="form-field full checkbox-row">
            <input id="group-approval" name="requiresLeaderApproval" type="checkbox" checked />
            <label for="group-approval">Require leader approval for joins</label>
          </div>
          <div class="form-field full">
            <label for="group-rules">Group rules</label>
            <textarea id="group-rules" name="rules" required></textarea>
          </div>
          <div class="form-field full">
            <button type="submit" class="btn-primary">Create secure group</button>
          </div>
        </form>
      </article>

      <article class="card">
        <h3>Search groups</h3>
        <form id="group-filter-form" class="form-grid">
          <div class="form-field full">
            <label for="filter-query">Search by name</label>
            <input id="filter-query" name="query" value="${escapeHtml(state.groupFilters.query)}" />
          </div>
          <div class="form-field">
            <label for="filter-community">Community</label>
            <input id="filter-community" name="community" value="${escapeHtml(state.groupFilters.community)}" />
          </div>
          <div class="form-field">
            <label for="filter-location">Location</label>
            <input id="filter-location" name="location" value="${escapeHtml(state.groupFilters.location)}" />
          </div>
          <div class="form-field">
            <label for="filter-contribution">Max contribution</label>
            <input
              id="filter-contribution"
              name="maxContribution"
              type="number"
              value="${escapeHtml(String(state.groupFilters.maxContribution || ""))}"
            />
          </div>
          <div class="form-field">
            <label for="filter-start">Starts after</label>
            <input id="filter-start" name="startDate" type="date" value="${escapeHtml(state.groupFilters.startDate)}" />
          </div>
          <div class="form-field full button-row">
            <button type="submit" class="btn-secondary">Apply filters</button>
            <button type="button" class="btn-secondary" data-action="clear-group-filters">Reset</button>
          </div>
        </form>
      </article>
    </section>

    <section style="margin-top: 0.9rem;">
      <h3>Available circles (${filteredGroups.length})</h3>
      ${filteredGroups.map((group) => renderGroupCard(group, user)).join("")}
      ${filteredGroups.length ? "" : '<p class="muted">No groups match your filters.</p>'}
    </section>
  `;
}

function renderGroupCard(group, user) {
  const leader = findUserById(group.leaderId);
  const memberEntries = group.memberIds.map((memberId) => findUserById(memberId)).filter(Boolean);
  const isMember = group.memberIds.includes(user.id);
  const canManage = isGroupLeader(group, user.id) || user.role === "admin";
  const joinRequested = group.joinRequests.includes(user.id);
  const currentContributions = getCycleContributions(group.id, group.cycle);
  const inviteLink = `susukonnect://join/${group.inviteCode}`;
  const payoutOrderLabels = group.payoutOrder
    .map((memberId) => findUserById(memberId))
    .filter(Boolean)
    .map((member) => member.fullName);

  return `
    <article class="group-card">
      <div class="group-head">
        <div>
          <h4 style="margin: 0 0 0.35rem;">${escapeHtml(group.name)}</h4>
          <span class="chip">${escapeHtml(group.communityType || "General community")}</span>
          <span class="chip">${escapeHtml(group.location)}</span>
          <span class="chip">${escapeHtml(group.payoutOrderLogic)}</span>
          <span class="chip">${formatCurrency(group.contributionAmount, group.currency)} monthly</span>
        </div>
        <div class="button-row">
          ${renderGroupStatusBadge(group.status)}
          ${leader?.verifiedBadge ? '<span class="status-badge status-success">Leader verified</span>' : ""}
          ${
            group.memberIds.length >= group.totalMembers
              ? '<span class="status-badge status-warning">Group full</span>'
              : '<span class="status-badge status-neutral">Open slots</span>'
          }
        </div>
      </div>

      <p class="small muted">${escapeHtml(group.description)}</p>
      <p class="small">
        <strong>Leader:</strong> ${escapeHtml(leader ? leader.fullName : "Unknown")} •
        <strong>Start:</strong> ${formatDate(group.startDate)} •
        <strong>Grace:</strong> ${group.gracePeriodDays} day(s)
      </p>
      <p class="small">
        <strong>Payout order:</strong> ${escapeHtml(payoutOrderLabels.join(" -> ") || "Pending members")}
      </p>
      <p class="small">
        <strong>Private invite:</strong>
        <code>${escapeHtml(inviteLink)}</code>
        <button class="btn-secondary" data-action="copy-invite" data-link="${escapeHtml(inviteLink)}">Copy</button>
      </p>

      <div class="entry-card">
        <h5 style="margin-top: 0;">Cycle ${group.cycle} contribution transparency</h5>
        <table>
          <thead>
            <tr>
              <th>Member</th>
              <th>KYC</th>
              <th>History</th>
              <th>Current status</th>
            </tr>
          </thead>
          <tbody>
            ${memberEntries
              .map((member) => {
                const record = currentContributions.find((item) => item.userId === member.id);
                return `
                  <tr>
                    <td>${escapeHtml(member.fullName)}</td>
                    <td>${renderKycBadge(member.kyc.status)}</td>
                    <td>
                      <span class="small">${member.metrics.paidContributions} paid cycles</span><br />
                      <span class="small">${member.metrics.completedGroups} completed groups</span>
                    </td>
                    <td>${renderContributionStatusBadge(record?.status || "pending")}</td>
                  </tr>
                `;
              })
              .join("")}
          </tbody>
        </table>
      </div>

      <div class="button-row">
        ${
          !isMember && group.status === "active"
            ? joinRequested
              ? '<span class="status-badge status-warning">Join request pending approval</span>'
              : group.memberIds.length >= group.totalMembers
                ? '<span class="status-badge status-neutral">No open slots</span>'
                : hasVerifiedKyc(user)
                  ? `<button class="btn-primary" data-action="join-group" data-group-id="${group.id}">Join this group</button>`
                  : '<span class="status-badge status-danger">KYC verification required before joining</span>'
            : ""
        }
        ${
          canManage
            ? `<button class="btn-secondary" data-action="notify-pending-group" data-group-id="${group.id}">
                Send payment reminders
              </button>`
            : ""
        }
        ${
          user.role === "admin"
            ? group.status === "suspended"
              ? `<button class="btn-secondary" data-action="toggle-group-status" data-group-id="${group.id}" data-status="active">Reactivate</button>`
              : `<button class="btn-warning" data-action="toggle-group-status" data-group-id="${group.id}" data-status="suspended">Suspend</button>`
            : ""
        }
      </div>

      ${
        canManage && group.joinRequests.length
          ? `
            <div class="entry-card">
              <h5 style="margin-top: 0;">Pending join approvals</h5>
              <table>
                <thead>
                  <tr>
                    <th>Applicant</th>
                    <th>KYC</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  ${group.joinRequests
                    .map((requestUserId) => {
                      const requestUser = findUserById(requestUserId);
                      if (!requestUser) {
                        return "";
                      }
                      return `
                        <tr>
                          <td>${escapeHtml(requestUser.fullName)}</td>
                          <td>${renderKycBadge(requestUser.kyc.status)}</td>
                          <td class="button-row">
                            <button class="btn-primary" data-action="approve-join" data-group-id="${group.id}" data-user-id="${requestUser.id}">Approve</button>
                            <button class="btn-danger" data-action="reject-join" data-group-id="${group.id}" data-user-id="${requestUser.id}">Reject</button>
                          </td>
                        </tr>
                      `;
                    })
                    .join("")}
                </tbody>
              </table>
            </div>
          `
          : ""
      }

      ${
        isMember
          ? `
            <form class="dispute-form form-grid" data-group-id="${group.id}">
              <div class="form-field full">
                <label>Raise dispute (admin + leader visibility)</label>
                <textarea name="summary" placeholder="Describe issue, transaction, or policy concern." required></textarea>
              </div>
              <div class="form-field full">
                <button type="submit" class="btn-secondary">Submit dispute</button>
              </div>
            </form>
          `
          : ""
      }
    </article>
  `;
}

function renderContributionsPanel(user) {
  const groups = getGroupsForUser(user.id);
  if (!groups.length) {
    return `<h2>Contributions</h2><p class="muted">Join a group to start contribution tracking.</p>`;
  }

  return `
    <h2>Contribution Engine</h2>
    <p class="muted">
      Monthly due tracking, manual / auto-debit options, grace periods, and late alerts.
    </p>
    ${groups.map((group) => renderContributionGroup(group, user)).join("")}
  `;
}

function renderContributionGroup(group, user) {
  const userContribution = getContributionRecord(group.id, group.cycle, user.id);
  const cycleEntries = getCycleContributions(group.id, group.cycle);
  const methods = user.paymentMethods;
  const pendingMembers = cycleEntries.filter(
    (entry) => entry.status === "pending" || entry.status === "late"
  );

  return `
    <article class="entry-card">
      <div class="entry-head">
        <div>
          <h3 style="margin: 0;">${escapeHtml(group.name)} • Cycle ${group.cycle}</h3>
          <p class="small muted">
            Due: ${formatDate(getCycleDueDate(group, group.cycle))} •
            Grace deadline: ${formatDate(getGraceDeadline(group, group.cycle))}
          </p>
        </div>
        <div class="button-row">
          ${renderGroupStatusBadge(group.status)}
          ${renderContributionStatusBadge(userContribution?.status || "pending")}
        </div>
      </div>

      <table>
        <thead>
          <tr>
            <th>Member</th>
            <th>Contribution amount</th>
            <th>Status</th>
            <th>Updated</th>
          </tr>
        </thead>
        <tbody>
          ${cycleEntries
            .map((entry) => {
              const member = findUserById(entry.userId);
              return `
                <tr>
                  <td>${escapeHtml(member ? member.fullName : entry.userId)}</td>
                  <td>${formatCurrency(entry.amount, group.currency)}</td>
                  <td>${renderContributionStatusBadge(entry.status)}</td>
                  <td class="small">${entry.paidAt ? formatDateTime(entry.paidAt) : "--"}</td>
                </tr>
              `;
            })
            .join("")}
        </tbody>
      </table>

      <div class="button-row">
        ${
          (isGroupLeader(group, user.id) || user.role === "admin") && pendingMembers.length
            ? `<button class="btn-secondary" data-action="notify-pending-group" data-group-id="${group.id}">
                 Notify pending members (${pendingMembers.length})
               </button>`
            : ""
        }
      </div>

      ${
        group.status !== "active"
          ? '<p class="small muted">This group is not active. Contribution actions are disabled.</p>'
          : userContribution && (userContribution.status === "pending" || userContribution.status === "late")
            ? methods.length
              ? `
                <form class="pay-contribution-form form-grid" data-group-id="${group.id}" data-contribution-id="${userContribution.id}">
                  <div class="form-field">
                    <label>Payment method</label>
                    <select name="methodId" required>
                      <option value="">Select method</option>
                      ${methods
                        .map(
                          (method) =>
                            `<option value="${method.id}">${escapeHtml(
                              `${method.type.toUpperCase()} • ${method.label} • ${method.last4}`
                            )}</option>`
                        )
                        .join("")}
                    </select>
                  </div>
                  <div class="form-field checkbox-row">
                    <input id="auto-${userContribution.id}" name="autoDebit" type="checkbox" />
                    <label for="auto-${userContribution.id}">Enable auto-debit for future cycles</label>
                  </div>
                  <div class="form-field full">
                    <button type="submit" class="btn-primary">
                      Pay ${formatCurrency(userContribution.amount, group.currency)}
                    </button>
                  </div>
                </form>
              `
              : `
                <p class="small muted">
                  Add a payment method in Security tab before contributing.
                  <button class="btn-secondary" data-action="switch-tab" data-tab="security">Open Security</button>
                </p>
              `
            : '<p class="small muted">Your contribution for this cycle is complete.</p>'
      }
    </article>
  `;
}

function renderPayoutsPanel(user) {
  const groups = getGroupsForUser(user.id);
  if (!groups.length) {
    return `<h2>Payouts</h2><p class="muted">Join a group to unlock payout scheduling and approvals.</p>`;
  }

  return `
    <h2>Payout Workflow</h2>
    <p class="muted">
      Funds release only after contributions are complete, approvals are satisfied, and recipient MFA is confirmed.
    </p>
    ${groups.map((group) => renderPayoutGroup(group, user)).join("")}
  `;
}

function renderPayoutGroup(group, user) {
  const cycleEntries = getCycleContributions(group.id, group.cycle);
  const allPaid = cycleEntries.length > 0 && cycleEntries.every((entry) => entry.status === "paid");
  const payout = getCurrentPayout(group.id, group.cycle);
  const recipientId = getEligibleRecipient(group, group.cycle);
  const recipient = recipientId ? findUserById(recipientId) : null;
  const voteSummary = summarizeVotes(group.id, group.cycle);
  const prioritySummary = summarizePriorityClaims(group.id, group.cycle);
  const pool = cycleEntries
    .filter((entry) => entry.status === "paid")
    .reduce((sum, entry) => sum + Number(entry.amount), 0);
  const expectedFee = calculatePlatformFee(pool);

  return `
    <article class="entry-card">
      <div class="entry-head">
        <div>
          <h3 style="margin: 0;">${escapeHtml(group.name)} • Cycle ${group.cycle}</h3>
          <p class="small muted">
            Payout logic: ${escapeHtml(group.payoutOrderLogic)} •
            Total paid pool: ${formatCurrency(pool, group.currency)} •
            Platform fee (1.5%): ${formatCurrency(expectedFee, group.currency)}
          </p>
        </div>
        <div class="button-row">
          ${renderGroupStatusBadge(group.status)}
          ${allPaid ? '<span class="status-badge status-success">All contributions received</span>' : '<span class="status-badge status-warning">Waiting on contributions</span>'}
        </div>
      </div>

      ${
        group.payoutOrderLogic === "voting"
          ? renderVotingModule(group, user, voteSummary)
          : group.payoutOrderLogic === "priority"
            ? renderPriorityModule(group, user, prioritySummary)
            : ""
      }

      <div class="entry-card">
        <h4 style="margin-top: 0;">Current cycle payout status</h4>
        ${
          recipient
            ? `<p class="small"><strong>Eligible recipient:</strong> ${escapeHtml(recipient.fullName)}</p>`
            : '<p class="small muted">Recipient will be resolved once selection data is complete.</p>'
        }

        ${
          !payout
            ? allPaid
              ? recipient && user.id === recipient.id
                ? hasVerifiedKyc(user)
                  ? `
                      <form class="request-payout-form form-grid" data-group-id="${group.id}">
                        <div class="form-field">
                          <label>Payout reason</label>
                          <select name="reason" required>
                            ${PAYOUT_REASONS.map((reason) => `<option value="${reason}">${escapeHtml(reason)}</option>`).join("")}
                          </select>
                        </div>
                        <div class="form-field full">
                          <label>Custom reason (optional)</label>
                          <input name="customReason" />
                        </div>
                        <div class="form-field full">
                          <button type="submit" class="btn-primary">Request payout</button>
                        </div>
                      </form>
                    `
                  : '<span class="status-badge status-danger">KYC verification required before receiving payout.</span>'
                : '<p class="small muted">Waiting for eligible recipient to request payout.</p>'
              : '<p class="small muted">Complete all contributions before payout can be requested.</p>'
            : renderPayoutRecord(payout, group, user)
        }
      </div>
    </article>
  `;
}

function renderPayoutRecord(payout, group, user) {
  const recipient = findUserById(payout.recipientId);
  const adminRequired = isAdminApprovalRequired(payout.amount);
  const canApprove = isGroupLeader(group, user.id) || user.role === "admin";
  const canRelease = canApprove && payout.status === "approved" && payout.recipientMfaConfirmed;
  const leaderApproved = Boolean(payout.leaderApprovedBy);
  const adminApproved = Boolean(payout.adminApprovedBy);

  return `
    <div class="entry-card">
      <p class="small">
        <strong>Recipient:</strong> ${escapeHtml(recipient ? recipient.fullName : payout.recipientId)}<br />
        <strong>Reason:</strong> ${escapeHtml(payout.reason)}${payout.customReason ? ` (${escapeHtml(payout.customReason)})` : ""}<br />
        <strong>Requested:</strong> ${formatDateTime(payout.requestedAt)}<br />
        <strong>Status:</strong> ${renderPayoutStatusBadge(payout.status)}
      </p>

      <div class="button-row">
        ${leaderApproved ? '<span class="status-badge status-success">Leader approved</span>' : '<span class="status-badge status-warning">Leader approval pending</span>'}
        ${
          adminRequired
            ? adminApproved
              ? '<span class="status-badge status-success">Admin approved</span>'
              : '<span class="status-badge status-warning">Admin approval pending</span>'
            : '<span class="status-badge status-neutral">Admin approval optional</span>'
        }
        ${
          payout.recipientMfaConfirmed
            ? '<span class="status-badge status-success">Recipient MFA confirmed</span>'
            : '<span class="status-badge status-warning">Recipient MFA pending</span>'
        }
      </div>

      <div class="button-row">
        ${
          canApprove &&
          payout.status !== "released" &&
          payout.status !== "rejected" &&
          ((isGroupLeader(group, user.id) && !leaderApproved) || (user.role === "admin" && adminRequired && !adminApproved) || (user.role === "admin" && !adminRequired && !adminApproved))
            ? `<button class="btn-primary" data-action="approve-payout" data-group-id="${group.id}" data-payout-id="${payout.id}">
                 ${user.role === "admin" ? "Admin approve (MFA)" : "Leader approve (MFA)"}
               </button>`
            : ""
        }
        ${
          user.id === payout.recipientId && !payout.recipientMfaConfirmed
            ? `<button class="btn-secondary" data-action="confirm-payout-mfa" data-payout-id="${payout.id}">
                 Confirm payout identity (MFA)
               </button>`
            : ""
        }
        ${
          canRelease
            ? `<button class="btn-primary" data-action="release-payout" data-group-id="${group.id}" data-payout-id="${payout.id}">
                 Release payout (MFA)
               </button>`
            : ""
        }
      </div>
    </div>
  `;
}

function renderVotingModule(group, user, voteSummary) {
  const existingVote = state.data.payoutVotes.find(
    (vote) => vote.groupId === group.id && vote.cycle === group.cycle && vote.voterId === user.id
  );
  const members = group.memberIds.map((memberId) => findUserById(memberId)).filter(Boolean);

  return `
    <div class="entry-card">
      <h4 style="margin-top: 0;">Voting-based recipient selection</h4>
      <p class="small muted">One vote per cycle. Highest vote count determines eligible recipient.</p>
      <ul class="list-compact">
        ${
          voteSummary.length
            ? voteSummary
                .map(
                  (item) =>
                    `<li>${escapeHtml(item.name)} - ${item.count} vote(s)</li>`
                )
                .join("")
            : "<li>No votes submitted yet.</li>"
        }
      </ul>
      ${
        existingVote
          ? `<p class="small muted">You voted for ${escapeHtml(findUserById(existingVote.candidateId)?.fullName || existingVote.candidateId)}.</p>`
          : `
            <form class="vote-form form-grid" data-group-id="${group.id}">
              <div class="form-field">
                <label>Vote recipient</label>
                <select name="candidateId" required>
                  <option value="">Select member</option>
                  ${members.map((member) => `<option value="${member.id}">${escapeHtml(member.fullName)}</option>`).join("")}
                </select>
              </div>
              <div class="form-field full">
                <label>Vote note (optional)</label>
                <input name="note" />
              </div>
              <div class="form-field full">
                <button type="submit" class="btn-secondary">Submit vote</button>
              </div>
            </form>
          `
      }
    </div>
  `;
}

function renderPriorityModule(group, user, prioritySummary) {
  const existingClaim = state.data.priorityClaims.find(
    (claim) => claim.groupId === group.id && claim.cycle === group.cycle && claim.userId === user.id
  );

  return `
    <div class="entry-card">
      <h4 style="margin-top: 0;">Priority-based recipient selection</h4>
      <p class="small muted">
        Priority reasons are scored for transparent emergency-sensitive ordering.
      </p>
      <ul class="list-compact">
        ${
          prioritySummary.length
            ? prioritySummary
                .map(
                  (item) =>
                    `<li>${escapeHtml(item.name)} - ${escapeHtml(item.reason)} (score ${item.weight})</li>`
                )
                .join("")
            : "<li>No priority claims submitted for this cycle.</li>"
        }
      </ul>

      ${
        existingClaim
          ? `<p class="small muted">You already submitted: ${escapeHtml(existingClaim.reason)}.</p>`
          : `
            <form class="priority-claim-form form-grid" data-group-id="${group.id}">
              <div class="form-field">
                <label>Priority reason</label>
                <select name="reason" required>
                  ${PAYOUT_REASONS.map((reason) => `<option value="${reason}">${escapeHtml(reason)}</option>`).join("")}
                </select>
              </div>
              <div class="form-field full">
                <label>Context (optional)</label>
                <input name="customReason" />
              </div>
              <div class="form-field full">
                <button type="submit" class="btn-secondary">Submit priority claim</button>
              </div>
            </form>
          `
      }
    </div>
  `;
}

function renderChatPanel(user) {
  const groups = getGroupsForUser(user.id);
  if (!groups.length) {
    return `<h2>Group Chat</h2><p class="muted">Join a group to enable secure in-app communication.</p>`;
  }

  if (!state.selectedChatGroupId || !groups.some((group) => group.id === state.selectedChatGroupId)) {
    state.selectedChatGroupId = groups[0].id;
  }

  const selectedGroup = groups.find((group) => group.id === state.selectedChatGroupId);
  const messages = state.data.chats
    .filter((message) => message.groupId === selectedGroup.id)
    .sort((a, b) => {
      if (a.pinned !== b.pinned) {
        return a.pinned ? -1 : 1;
      }
      return new Date(a.createdAt) - new Date(b.createdAt);
    });

  const canModerate = isGroupLeader(selectedGroup, user.id) || user.role === "admin";
  const archived = selectedGroup.chatArchived || selectedGroup.status === "completed";

  return `
    <h2>Secure Group Communication</h2>
    <p class="muted">Phone numbers stay private. Announcements and message pins are fully in-app.</p>

    <div class="form-field" style="max-width: 420px;">
      <label for="chat-group-select">Active chat group</label>
      <select id="chat-group-select">
        ${groups
          .map(
            (group) =>
              `<option value="${group.id}" ${group.id === selectedGroup.id ? "selected" : ""}>${escapeHtml(group.name)}</option>`
          )
          .join("")}
      </select>
    </div>

    <div class="chat-card">
      <div class="chat-feed">
        ${
          messages.length
            ? messages
                .map((message) => {
                  const sender = findUserById(message.userId);
                  return `
                    <div class="chat-message ${message.type === "announcement" ? "announcement" : ""} ${message.pinned ? "pinned" : ""}">
                      <div class="small">
                        <strong>${escapeHtml(sender ? sender.fullName : message.userId)}</strong>
                        • ${formatDateTime(message.createdAt)}
                      </div>
                      <div>${escapeHtml(message.content)}</div>
                      ${
                        canModerate
                          ? `<div class="button-row">
                              <button class="btn-secondary" data-action="toggle-pin-message" data-message-id="${message.id}">
                                ${message.pinned ? "Unpin" : "Pin"}
                              </button>
                            </div>`
                          : ""
                      }
                    </div>
                  `;
                })
                .join("")
            : '<p class="muted">No messages yet for this group.</p>'
        }
      </div>
    </div>

    ${
      archived
        ? '<p class="small muted">This group is archived; chat is read-only.</p>'
        : `
          <form id="chat-form" class="form-grid" data-group-id="${selectedGroup.id}">
            <div class="form-field full">
              <label for="chat-message">Message</label>
              <textarea id="chat-message" name="content" required></textarea>
            </div>
            ${
              canModerate
                ? `
                  <div class="form-field checkbox-row">
                    <input id="chat-announcement" type="checkbox" name="announcement" />
                    <label for="chat-announcement">Send as announcement</label>
                  </div>
                  <div class="form-field checkbox-row">
                    <input id="chat-pin" type="checkbox" name="pin" />
                    <label for="chat-pin">Pin this message</label>
                  </div>
                `
                : ""
            }
            <div class="form-field full">
              <button type="submit" class="btn-primary">Send message</button>
            </div>
          </form>
        `
    }
  `;
}

function renderCalendarPanel(user) {
  const events = getCalendarEventsForUser(user.id);
  const groupedByMonth = events.reduce((acc, event) => {
    const monthLabel = monthKey(event.date);
    if (!acc[monthLabel]) {
      acc[monthLabel] = [];
    }
    acc[monthLabel].push(event);
    return acc;
  }, {});

  return `
    <h2>Calendar & Reminders</h2>
    <p class="muted">
      Contribution due dates, payout checkpoints, grace deadlines, and group milestones.
    </p>
    <div class="calendar-grid">
      <article class="card">
        <h3>Upcoming events</h3>
        ${
          events.length
            ? events
                .slice(0, 14)
                .map(
                  (event) => `
                    <div class="event-item">
                      <strong>${escapeHtml(event.title)}</strong>
                      <div class="small muted">${formatDate(event.date)} • ${escapeHtml(event.groupName)}</div>
                      <div class="small">${escapeHtml(event.typeLabel)}</div>
                    </div>
                  `
                )
                .join("")
            : '<p class="muted">No scheduled events found.</p>'
        }
      </article>
      <article class="card">
        <h3>Month view breakdown</h3>
        ${
          Object.keys(groupedByMonth).length
            ? Object.entries(groupedByMonth)
                .map(
                  ([month, monthEvents]) => `
                    <div class="event-item">
                      <strong>${escapeHtml(month)}</strong>
                      <ul class="list-compact">
                        ${monthEvents
                          .slice(0, 6)
                          .map(
                            (event) =>
                              `<li>${formatDate(event.date)} - ${escapeHtml(event.title)}</li>`
                          )
                          .join("")}
                      </ul>
                    </div>
                  `
                )
                .join("")
            : '<p class="muted">No monthly events available.</p>'
        }
      </article>
    </div>
  `;
}

function renderNotificationsPanel(user) {
  const notifications = getUserNotifications(user.id);

  return `
    <h2>Smart Notifications</h2>
    <div class="button-row">
      <button class="btn-secondary" data-action="mark-all-read">Mark all read</button>
    </div>
    ${
      notifications.length
        ? `
          <table>
            <thead>
              <tr>
                <th>Type</th>
                <th>Message</th>
                <th>Created</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              ${notifications
                .map(
                  (note) => `
                    <tr class="${note.read ? "" : "notification-unread"}">
                      <td>${escapeHtml(note.type)}</td>
                      <td>${escapeHtml(note.title)}<br /><span class="small muted">${escapeHtml(note.body)}</span></td>
                      <td class="small">${formatDateTime(note.createdAt)}</td>
                      <td>
                        ${
                          note.read
                            ? '<span class="status-badge status-neutral">Read</span>'
                            : `<button class="btn-secondary" data-action="mark-read" data-notification-id="${note.id}">Mark read</button>`
                        }
                      </td>
                    </tr>
                  `
                )
                .join("")}
            </tbody>
          </table>
        `
        : '<p class="muted">No notifications yet.</p>'
    }
  `;
}

function renderSecurityPanel(user) {
  const currentDeviceId = getDeviceFingerprint();

  return `
    <h2>Security, KYC & Payments</h2>
    <section class="layout-columns">
      <article class="card">
        <h3>Identity verification (KYC)</h3>
        <p class="small">
          Status: ${renderKycBadge(user.kyc.status)}
        </p>
        <form id="kyc-form" class="form-grid">
          <div class="form-field">
            <label for="kyc-id-type">Government ID type</label>
            <select id="kyc-id-type" name="idType" required>
              <option value="Passport">Passport</option>
              <option value="National ID">National ID</option>
              <option value="Driver's License">Driver's License</option>
            </select>
          </div>
          <div class="form-field">
            <label for="kyc-id-number">ID number</label>
            <input id="kyc-id-number" name="idNumber" required />
          </div>
          <div class="form-field">
            <label for="kyc-dob">Date of birth</label>
            <input id="kyc-dob" type="date" name="dob" required />
          </div>
          <div class="form-field">
            <label for="kyc-selfie">Liveness selfie token</label>
            <input id="kyc-selfie" name="selfieToken" placeholder="selfie_capture_01" required />
          </div>
          <div class="form-field full">
            <label for="kyc-address">Address (optional)</label>
            <input id="kyc-address" name="address" />
          </div>
          <div class="form-field full">
            <button type="submit" class="btn-primary">Submit KYC package</button>
          </div>
        </form>
      </article>

      <article class="card">
        <h3>Authentication controls</h3>
        <form id="security-settings-form" class="form-grid">
          <div class="form-field checkbox-row">
            <input id="security-mfa" type="checkbox" name="mfaEnabled" ${user.mfaEnabled ? "checked" : ""} />
            <label for="security-mfa">Enable MFA by default</label>
          </div>
          <div class="form-field checkbox-row">
            <input id="security-biometric" type="checkbox" name="biometricEnabled" ${user.biometricEnabled ? "checked" : ""} />
            <label for="security-biometric">Enable biometric login on trusted devices</label>
          </div>
          <div class="form-field full">
            <button type="submit" class="btn-secondary">Save auth preferences</button>
          </div>
        </form>

        <h4>Trusted devices</h4>
        <table>
          <thead>
            <tr>
              <th>Device ID</th>
              <th>Last seen</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            ${
              user.knownDevices.length
                ? user.knownDevices
                    .map(
                      (device) => `
                        <tr>
                          <td><code>${escapeHtml(device.id.slice(-12))}</code>${device.id === currentDeviceId ? " (current)" : ""}</td>
                          <td class="small">${formatDateTime(device.lastSeenAt)}</td>
                          <td>
                            ${
                              device.id === currentDeviceId
                                ? '<span class="chip">Active</span>'
                                : `<button class="btn-danger" data-action="remove-device" data-device-id="${device.id}">Remove</button>`
                            }
                          </td>
                        </tr>
                      `
                    )
                    .join("")
                : '<tr><td colspan="3" class="small muted">No trusted devices yet.</td></tr>'
            }
          </tbody>
        </table>
      </article>
    </section>

    <section class="card" style="margin-top: 0.9rem;">
      <h3>Integrated payment methods (tokenized)</h3>
      <p class="small muted">Supported: bank ACH, debit card, PayPal, Cash App. Raw account data is not stored.</p>

      <table>
        <thead>
          <tr>
            <th>Type</th>
            <th>Label</th>
            <th>Identifier</th>
            <th>Auto-debit</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          ${
            user.paymentMethods.length
              ? user.paymentMethods
                  .map(
                    (method) => `
                      <tr>
                        <td>${escapeHtml(method.type.toUpperCase())}</td>
                        <td>${escapeHtml(method.label)}</td>
                        <td><code>${escapeHtml(method.last4)}</code></td>
                        <td>${method.autoDebit ? "Enabled" : "Disabled"}</td>
                        <td>
                          <button class="btn-danger" data-action="remove-payment-method" data-method-id="${method.id}">
                            Remove (MFA)
                          </button>
                        </td>
                      </tr>
                    `
                  )
                  .join("")
              : '<tr><td colspan="5" class="small muted">No payment methods added.</td></tr>'
          }
        </tbody>
      </table>

      <form id="payment-method-form" class="form-grid" style="margin-top: 0.8rem;">
        <div class="form-field">
          <label for="payment-type">Type</label>
          <select id="payment-type" name="type" required>
            <option value="bank">Bank (ACH)</option>
            <option value="debit">Debit card</option>
            <option value="paypal">PayPal</option>
            <option value="cashapp">Cash App</option>
          </select>
        </div>
        <div class="form-field">
          <label for="payment-label">Label</label>
          <input id="payment-label" name="label" placeholder="Main debit card" required />
        </div>
        <div class="form-field">
          <label for="payment-identifier">Account/card tail (last 4)</label>
          <input id="payment-identifier" name="identifier" maxlength="4" required />
        </div>
        <div class="form-field checkbox-row">
          <input id="payment-autodebit" type="checkbox" name="autoDebit" />
          <label for="payment-autodebit">Enable auto-debit</label>
        </div>
        <div class="form-field full">
          <button type="submit" class="btn-primary">Add payment method (MFA)</button>
        </div>
      </form>
    </section>
  `;
}

function renderAdminPanel(user) {
  if (user.role !== "admin") {
    return "<h2>Admin</h2><p class='muted'>Role-based access denied.</p>";
  }

  const pendingKyc = state.data.users.filter((member) => member.kyc.status === "pending");
  const lateContributions = state.data.contributions.filter((entry) => entry.status === "late");
  const openDisputes = state.data.disputes.filter((dispute) => dispute.status !== "resolved");
  const recentAudit = [...state.data.auditLogs].slice(-25).reverse();

  return `
    <h2>Admin & Compliance Dashboard</h2>
    <p class="muted">
      KYC review, transaction monitoring, fraud flags, dispute controls, immutable audit logs, and exports.
    </p>

    <section class="layout-columns">
      <article class="card">
        <h3>Pending KYC reviews (${pendingKyc.length})</h3>
        <table>
          <thead>
            <tr>
              <th>User</th>
              <th>ID type</th>
              <th>Submitted</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            ${
              pendingKyc.length
                ? pendingKyc
                    .map(
                      (member) => `
                        <tr>
                          <td>${escapeHtml(member.fullName)}<br /><span class="small muted">${escapeHtml(member.email)}</span></td>
                          <td>${escapeHtml(member.kyc.idType || "--")}</td>
                          <td class="small">${member.kyc.submittedAt ? formatDateTime(member.kyc.submittedAt) : "--"}</td>
                          <td class="button-row">
                            <button class="btn-primary" data-action="review-kyc" data-user-id="${member.id}" data-status="verified">Approve</button>
                            <button class="btn-danger" data-action="review-kyc" data-user-id="${member.id}" data-status="rejected">Reject</button>
                          </td>
                        </tr>
                      `
                    )
                    .join("")
                : '<tr><td colspan="4" class="small muted">No pending KYC requests.</td></tr>'
            }
          </tbody>
        </table>
      </article>

      <article class="card">
        <h3>Transaction monitoring</h3>
        <p class="small muted">Late payments trigger leader alerts and can be flagged for review.</p>
        <ul class="list-compact">
          <li>Late contributions: ${lateContributions.length}</li>
          <li>Requested payouts: ${state.data.payouts.filter((payout) => payout.status === "requested").length}</li>
          <li>Released payouts: ${state.data.payouts.filter((payout) => payout.status === "released").length}</li>
        </ul>
        <form id="fraud-flag-form" class="form-grid">
          <div class="form-field">
            <label for="flag-target-type">Target type</label>
            <select id="flag-target-type" name="targetType">
              <option value="user">User</option>
              <option value="group">Group</option>
              <option value="transaction">Transaction</option>
            </select>
          </div>
          <div class="form-field">
            <label for="flag-target-id">Target ID</label>
            <input id="flag-target-id" name="targetId" required />
          </div>
          <div class="form-field full">
            <label for="flag-reason">Reason</label>
            <textarea id="flag-reason" name="reason" required></textarea>
          </div>
          <div class="form-field full">
            <button type="submit" class="btn-warning">Create fraud flag</button>
          </div>
        </form>
      </article>
    </section>

    <section class="layout-columns" style="margin-top: 0.9rem;">
      <article class="card">
        <h3>Dispute resolution (${openDisputes.length} open)</h3>
        <table>
          <thead>
            <tr>
              <th>Group</th>
              <th>Reporter</th>
              <th>Summary</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            ${
              state.data.disputes.length
                ? state.data.disputes
                    .slice()
                    .reverse()
                    .map((dispute) => {
                      const group = findGroupById(dispute.groupId);
                      const reporter = findUserById(dispute.reporterId);
                      return `
                        <tr>
                          <td>${escapeHtml(group ? group.name : dispute.groupId)}</td>
                          <td>${escapeHtml(reporter ? reporter.fullName : dispute.reporterId)}</td>
                          <td>${escapeHtml(dispute.summary)}</td>
                          <td>
                            ${
                              dispute.status === "resolved"
                                ? '<span class="status-badge status-success">Resolved</span>'
                                : `<button class="btn-secondary" data-action="resolve-dispute" data-dispute-id="${dispute.id}">Mark resolved</button>`
                            }
                          </td>
                        </tr>
                      `;
                    })
                    .join("")
                : '<tr><td colspan="4" class="small muted">No disputes filed.</td></tr>'
            }
          </tbody>
        </table>
      </article>

      <article class="card">
        <h3>Group controls</h3>
        <table>
          <thead>
            <tr>
              <th>Group</th>
              <th>Status</th>
              <th>Members</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            ${state.data.groups
              .map(
                (group) => `
                  <tr>
                    <td>${escapeHtml(group.name)}</td>
                    <td>${renderGroupStatusBadge(group.status)}</td>
                    <td>${group.memberIds.length}/${group.totalMembers}</td>
                    <td>
                      ${
                        group.status === "suspended"
                          ? `<button class="btn-secondary" data-action="toggle-group-status" data-group-id="${group.id}" data-status="active">Reactivate</button>`
                          : `<button class="btn-warning" data-action="toggle-group-status" data-group-id="${group.id}" data-status="suspended">Suspend</button>`
                      }
                    </td>
                  </tr>
                `
              )
              .join("")}
          </tbody>
        </table>
      </article>
    </section>

    <section class="card" style="margin-top: 0.9rem;">
      <h3>Immutable audit logs</h3>
      <div class="button-row">
        <button class="btn-secondary" data-action="export-report" data-format="json">Export report (JSON)</button>
        <button class="btn-secondary" data-action="export-report" data-format="csv">Export report (CSV)</button>
        <button class="btn-secondary" data-action="export-audit">Export audit chain</button>
      </div>
      <table>
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>Actor</th>
            <th>Action</th>
            <th>Entity</th>
            <th>Hash</th>
          </tr>
        </thead>
        <tbody>
          ${
            recentAudit.length
              ? recentAudit
                  .map((log) => {
                    const actor = findUserById(log.actorId);
                    return `
                      <tr>
                        <td class="small">${formatDateTime(log.timestamp)}</td>
                        <td>${escapeHtml(actor ? actor.fullName : "System")}</td>
                        <td>${escapeHtml(log.action)}</td>
                        <td>${escapeHtml(log.targetType)}:${escapeHtml(log.targetId)}</td>
                        <td><code>${escapeHtml(log.entryHash.slice(0, 14))}...</code></td>
                      </tr>
                    `;
                  })
                  .join("")
              : '<tr><td colspan="5" class="small muted">No audit entries.</td></tr>'
          }
        </tbody>
      </table>
    </section>
  `;
}

function handleSubmit(event) {
  const form = event.target;

  if (!(form instanceof HTMLFormElement)) {
    return;
  }

  if (form.id === "mfa-form") {
    return;
  }

  event.preventDefault();
  touchSession();
  withUiGuard(`Form submit: ${form.id || "unknown"}`, () => {
    switch (form.id) {
      case "login-form":
        handleLogin(form);
        return;
      case "register-form":
        handleRegister(form);
        return;
      case "create-group-form":
        handleCreateGroup(form);
        return;
      case "group-filter-form":
        handleGroupFilters(form);
        return;
      case "chat-form":
        handleSendChat(form);
        return;
      case "kyc-form":
        handleKycSubmit(form);
        return;
      case "security-settings-form":
        handleSecuritySettings(form);
        return;
      case "payment-method-form":
        handlePaymentMethod(form);
        return;
      case "fraud-flag-form":
        handleFraudFlag(form);
        return;
      default:
        break;
    }

    if (form.classList.contains("pay-contribution-form")) {
      handlePayContribution(form);
      return;
    }

    if (form.classList.contains("request-payout-form")) {
      handleRequestPayout(form);
      return;
    }

    if (form.classList.contains("vote-form")) {
      handleVote(form);
      return;
    }

    if (form.classList.contains("priority-claim-form")) {
      handlePriorityClaim(form);
      return;
    }

    if (form.classList.contains("dispute-form")) {
      handleDispute(form);
    }
  });
}

function handleClick(event) {
  const target = event.target;
  if (!(target instanceof Element)) {
    return;
  }
  const button = target.closest("[data-action]");
  if (!(button instanceof HTMLElement)) {
    return;
  }

  const { action } = button.dataset;
  touchSession();
  withUiGuard(`Click action: ${action || "unknown"}`, () => {
    switch (action) {
      case "switch-tab":
        state.activeTab = button.dataset.tab;
        render();
        return;
      case "logout":
        logoutCurrentUser();
        return;
      case "clear-group-filters":
        state.groupFilters = {
          query: "",
          community: "",
          location: "",
          maxContribution: "",
          startDate: "",
        };
        render();
        return;
      case "join-group":
        joinGroup(button.dataset.groupId);
        return;
      case "approve-join":
        reviewJoinRequest(button.dataset.groupId, button.dataset.userId, "approve");
        return;
      case "reject-join":
        reviewJoinRequest(button.dataset.groupId, button.dataset.userId, "reject");
        return;
      case "notify-pending-group":
        sendManualReminders(button.dataset.groupId);
        return;
      case "approve-payout":
        approvePayout(button.dataset.groupId, button.dataset.payoutId);
        return;
      case "confirm-payout-mfa":
        confirmPayoutIdentity(button.dataset.payoutId);
        return;
      case "release-payout":
        releasePayout(button.dataset.groupId, button.dataset.payoutId);
        return;
      case "toggle-pin-message":
        togglePinnedMessage(button.dataset.messageId);
        return;
      case "mark-read":
        markNotificationRead(button.dataset.notificationId);
        return;
      case "mark-all-read":
        markAllNotificationsRead();
        return;
      case "remove-payment-method":
        removePaymentMethod(button.dataset.methodId);
        return;
      case "remove-device":
        removeTrustedDevice(button.dataset.deviceId);
        return;
      case "review-kyc":
        reviewKyc(button.dataset.userId, button.dataset.status);
        return;
      case "resolve-dispute":
        resolveDispute(button.dataset.disputeId);
        return;
      case "toggle-group-status":
        toggleGroupStatus(button.dataset.groupId, button.dataset.status);
        return;
      case "copy-invite":
        copyInviteLink(button.dataset.link);
        return;
      case "export-report":
        exportReport(button.dataset.format);
        return;
      case "export-audit":
        exportAuditLog();
        return;
      case "biometric-login":
        biometricLogin();
        return;
      default:
        break;
    }
  });
}

function handleChange(event) {
  const target = event.target;
  if (!(target instanceof Element)) {
    return;
  }
  withUiGuard(`Change event: ${target.id || "unknown"}`, () => {
    if (target.id === "chat-group-select" && target instanceof HTMLSelectElement) {
      state.selectedChatGroupId = target.value;
      render();
    }
  });
}

function handleLogin(form) {
  const formData = new FormData(form);
  const email = normalizeEmail(formData.get("email"));
  const password = String(formData.get("password") || "");

  if (!email || !password) {
    showToast("Email and password are required.", "error");
    return;
  }

  const loginControl = state.data.authControls.loginAttempts[email] || {
    count: 0,
    lockedUntil: null,
  };

  if (loginControl.lockedUntil && new Date(loginControl.lockedUntil) > new Date()) {
    showToast("Account temporarily locked due to repeated failed attempts.", "error");
    return;
  }

  const user = state.data.users.find((candidate) => candidate.email === email);
  if (!user || user.passwordHash !== hashPassword(password, user.salt)) {
    loginControl.count += 1;
    if (loginControl.count >= 5) {
      loginControl.lockedUntil = new Date(Date.now() + 15 * 60 * 1000).toISOString();
      loginControl.count = 0;
    }
    state.data.authControls.loginAttempts[email] = loginControl;
    persistData();
    showToast("Invalid credentials.", "error");
    return;
  }

  if (user.status === "suspended") {
    showToast("Your account is currently suspended. Contact admin support.", "error");
    return;
  }

  state.data.authControls.loginAttempts[email] = { count: 0, lockedUntil: null };
  const deviceId = getDeviceFingerprint();
  const knownDevice = user.knownDevices.some((device) => device.id === deviceId);

  const finalizeLogin = () => {
    upsertKnownDevice(user, deviceId);
    user.lastLoginAt = new Date().toISOString();
    state.session = {
      userId: user.id,
      deviceId,
      createdAt: new Date().toISOString(),
      lastActivityAt: new Date().toISOString(),
    };
    saveSession(state.session);
    logAudit(user.id, "LOGIN_SUCCESS", "user", user.id, { deviceId });
    persistData();
    state.activeTab = "dashboard";
    showToast(`Welcome back, ${user.fullName}.`, "success");
    render();
  };

  if (!knownDevice || user.mfaEnabled) {
    openMfaModal(
      !knownDevice
        ? "New device sign-in detected. Confirm MFA to continue."
        : "MFA confirmation required for login.",
      finalizeLogin
    );
    return;
  }

  finalizeLogin();
}

function biometricLogin() {
  const emailInput = document.getElementById("login-email");
  const email = normalizeEmail(emailInput?.value || "");
  if (!email) {
    showToast("Enter your email first for biometric login.", "warning");
    return;
  }
  const user = state.data.users.find((candidate) => candidate.email === email);
  if (!user) {
    showToast("Account not found.", "error");
    return;
  }
  if (!user.biometricEnabled) {
    showToast("Biometric login is not enabled on this account.", "warning");
    return;
  }
  const deviceId = getDeviceFingerprint();
  const knownDevice = user.knownDevices.some((device) => device.id === deviceId);
  if (!knownDevice) {
    showToast("Biometric login only works on trusted devices.", "warning");
    return;
  }

  const simulatedBiometricSuccess = window.confirm(
    "Simulate biometric verification (Face ID / Fingerprint)?"
  );
  if (!simulatedBiometricSuccess) {
    showToast("Biometric verification cancelled.", "warning");
    return;
  }

  state.session = {
    userId: user.id,
    deviceId,
    createdAt: new Date().toISOString(),
    lastActivityAt: new Date().toISOString(),
  };
  saveSession(state.session);
  upsertKnownDevice(user, deviceId);
  logAudit(user.id, "BIOMETRIC_LOGIN_SUCCESS", "user", user.id, { deviceId });
  persistData();
  state.activeTab = "dashboard";
  showToast("Biometric login successful.", "success");
  render();
}

function handleRegister(form) {
  const formData = new FormData(form);
  const fullName = String(formData.get("fullName") || "").trim();
  const email = normalizeEmail(formData.get("email"));
  const phone = normalizePhone(formData.get("phone"));
  const password = String(formData.get("password") || "");
  const role = String(formData.get("role") || "member");
  const acceptedTerms = formData.get("acceptTerms") === "on";

  if (!acceptedTerms) {
    showToast("Terms and Savings Agreement must be accepted.", "error");
    return;
  }
  if (!fullName || !email || !phone || password.length < 8) {
    showToast("Complete all required fields with a strong password.", "error");
    return;
  }
  if (!/\d/.test(password) || !/[A-Za-z]/.test(password)) {
    showToast("Password must include letters and numbers.", "error");
    return;
  }
  if (state.data.users.some((user) => user.email === email)) {
    showToast("Email is already registered.", "error");
    return;
  }
  if (state.data.users.some((user) => user.phone === phone)) {
    showToast("Phone number is already registered.", "error");
    return;
  }

  const salt = uid("salt");
  const user = {
    id: uid("usr"),
    fullName,
    email,
    phone,
    role: role === "leader" ? "leader" : "member",
    salt,
    passwordHash: hashPassword(password, salt),
    acceptedTerms: true,
    verifiedBadge: false,
    biometricEnabled: false,
    mfaEnabled: true,
    status: "active",
    knownDevices: [],
    paymentMethods: [],
    kyc: {
      status: "unverified",
      idType: "",
      idNumberToken: "",
      dob: "",
      selfieToken: "",
      address: "",
      submittedAt: null,
    },
    metrics: {
      paidContributions: 0,
      completedGroups: 0,
      internalTrustScore: 50,
    },
    createdAt: new Date().toISOString(),
    lastLoginAt: null,
  };

  state.data.users.push(user);
  logAudit(user.id, "REGISTER_ACCOUNT", "user", user.id, {});
  notifyUser(
    user.id,
    "Welcome to SusuKonnect",
    "Complete KYC verification to join groups and receive payouts.",
    "onboarding",
    `welcome-${user.id}`
  );
  persistData();
  form.reset();
  showToast("Account created. Sign in to continue.", "success");
  render();
}

function handleCreateGroup(form) {
  const currentUser = getCurrentUser();
  if (!currentUser) {
    return;
  }
  if (!hasVerifiedKyc(currentUser)) {
    showToast("KYC verification is required before creating a group.", "error");
    return;
  }

  const formData = new FormData(form);
  const contributionAmount = Number(formData.get("contributionAmount"));
  const totalMembers = Number(formData.get("totalMembers"));
  const gracePeriodDays = Number(formData.get("gracePeriodDays") || 0);
  const startDate = String(formData.get("startDate") || "");

  if (!startDate || Number.isNaN(contributionAmount) || contributionAmount <= 0) {
    showToast("Group start date and contribution amount are required.", "error");
    return;
  }
  if (Number.isNaN(totalMembers) || totalMembers < 2) {
    showToast("Group requires at least 2 members.", "error");
    return;
  }

  if (currentUser.role === "member") {
    currentUser.role = "leader";
  }

  const group = {
    id: uid("grp"),
    inviteCode: uid("join"),
    name: String(formData.get("name") || "").trim(),
    description: String(formData.get("description") || "").trim(),
    communityType: String(formData.get("communityType") || "").trim(),
    location: String(formData.get("location") || "").trim(),
    startDate,
    contributionAmount,
    currency: String(formData.get("currency") || "USD"),
    totalMembers,
    payoutFrequency: "monthly",
    payoutOrderLogic: String(formData.get("payoutOrderLogic") || "fixed"),
    gracePeriodDays,
    requiresLeaderApproval: formData.get("requiresLeaderApproval") === "on",
    rules: String(formData.get("rules") || "").trim(),
    leaderId: currentUser.id,
    memberIds: [currentUser.id],
    joinRequests: [],
    payoutOrder: [currentUser.id],
    cycle: 1,
    status: "active",
    chatArchived: false,
    createdAt: new Date().toISOString(),
  };

  state.data.groups.push(group);
  ensureCycleContributionRecords(group);
  logAudit(currentUser.id, "CREATE_GROUP", "group", group.id, {
    contributionAmount: group.contributionAmount,
    currency: group.currency,
  });
  notifyUser(
    currentUser.id,
    "Group created",
    `${group.name} is active. Share your private invite link to onboard members.`,
    "group",
    `group-created-${group.id}`
  );
  persistData();
  form.reset();
  showToast("Group created successfully.", "success");
  render();
}

function handleGroupFilters(form) {
  const formData = new FormData(form);
  state.groupFilters = {
    query: String(formData.get("query") || "").trim(),
    community: String(formData.get("community") || "").trim(),
    location: String(formData.get("location") || "").trim(),
    maxContribution: String(formData.get("maxContribution") || "").trim(),
    startDate: String(formData.get("startDate") || "").trim(),
  };
  render();
}

function joinGroup(groupId) {
  const user = getCurrentUser();
  const group = findGroupById(groupId);
  if (!user || !group) {
    return;
  }
  if (!hasVerifiedKyc(user)) {
    showToast("KYC verification is required before joining.", "error");
    return;
  }
  if (group.status !== "active") {
    showToast("Group is not currently active.", "warning");
    return;
  }
  if (group.memberIds.includes(user.id)) {
    showToast("You are already a member.", "warning");
    return;
  }
  if (group.memberIds.length >= group.totalMembers) {
    showToast("Group is full.", "error");
    return;
  }
  if (group.joinRequests.includes(user.id)) {
    showToast("Join request already pending.", "warning");
    return;
  }

  if (group.requiresLeaderApproval) {
    group.joinRequests.push(user.id);
    notifyUser(
      group.leaderId,
      "Group join request pending",
      `${user.fullName} requested to join ${group.name}.`,
      "group",
      `join-request-${group.id}-${user.id}`
    );
    logAudit(user.id, "REQUEST_JOIN_GROUP", "group", group.id, { targetUserId: user.id });
    showToast("Join request sent to group leader.", "success");
  } else {
    addMemberToGroup(group, user.id);
    logAudit(user.id, "JOIN_GROUP", "group", group.id, { targetUserId: user.id });
    showToast("Successfully joined group.", "success");
  }
  persistData();
  render();
}

function reviewJoinRequest(groupId, userId, decision) {
  const actor = getCurrentUser();
  const group = findGroupById(groupId);
  const applicant = findUserById(userId);
  if (!actor || !group || !applicant) {
    return;
  }
  if (!canManageGroup(actor, group)) {
    showToast("Only group leaders/admin can review requests.", "error");
    return;
  }
  if (!group.joinRequests.includes(userId)) {
    showToast("Request no longer pending.", "warning");
    return;
  }

  group.joinRequests = group.joinRequests.filter((id) => id !== userId);
  if (decision === "approve") {
    addMemberToGroup(group, userId);
    notifyUser(
      applicant.id,
      "Join request approved",
      `You were added to ${group.name}.`,
      "group",
      `join-approved-${group.id}-${applicant.id}`
    );
    logAudit(actor.id, "APPROVE_JOIN_REQUEST", "group", group.id, {
      targetUserId: applicant.id,
    });
    showToast("Member approved and added to group.", "success");
  } else {
    notifyUser(
      applicant.id,
      "Join request declined",
      `Your join request for ${group.name} was declined.`,
      "group",
      `join-rejected-${group.id}-${applicant.id}`
    );
    logAudit(actor.id, "REJECT_JOIN_REQUEST", "group", group.id, {
      targetUserId: applicant.id,
    });
    showToast("Join request declined.", "warning");
  }
  persistData();
  render();
}

function handlePayContribution(form) {
  const user = getCurrentUser();
  if (!user) {
    return;
  }
  const group = findGroupById(form.dataset.groupId);
  const contribution = findContributionById(form.dataset.contributionId);
  if (!group || !contribution) {
    return;
  }
  if (group.status !== "active") {
    showToast("Group is not active. Payments are disabled.", "error");
    return;
  }
  if (contribution.userId !== user.id) {
    showToast("You can only pay your own contribution.", "error");
    return;
  }

  const formData = new FormData(form);
  const methodId = String(formData.get("methodId") || "");
  const autoDebit = formData.get("autoDebit") === "on";
  const method = user.paymentMethods.find((entry) => entry.id === methodId);

  if (!method) {
    showToast("Select a valid payment method.", "error");
    return;
  }

  requireMfa("Contribution payment confirmation", () => {
    contribution.status = "paid";
    contribution.methodId = method.id;
    contribution.methodType = method.type;
    contribution.autoDebit = autoDebit;
    contribution.paidAt = new Date().toISOString();
    method.autoDebit = autoDebit ? true : method.autoDebit;

    logAudit(user.id, "PAY_CONTRIBUTION", "contribution", contribution.id, {
      groupId: group.id,
      amount: contribution.amount,
      currency: group.currency,
    });
    notifyUser(
      group.leaderId,
      "Contribution paid",
      `${user.fullName} paid ${formatCurrency(contribution.amount, group.currency)} in ${group.name}.`,
      "payment",
      `contribution-paid-${contribution.id}`
    );

    if (areAllContributionsPaid(group.id, group.cycle)) {
      group.memberIds.forEach((memberId) => {
        notifyUser(
          memberId,
          "Payout cycle ready",
          `All contributions for ${group.name} cycle ${group.cycle} are complete.`,
          "payout",
          `payout-ready-${group.id}-${group.cycle}-${memberId}`
        );
      });
    }

    persistData();
    showToast("Contribution recorded successfully.", "success");
    render();
  });
}

function sendManualReminders(groupId) {
  const actor = getCurrentUser();
  const group = findGroupById(groupId);
  if (!actor || !group) {
    return;
  }
  if (!canManageGroup(actor, group)) {
    showToast("Only leaders/admin can send reminders.", "error");
    return;
  }
  const pendingContributions = getCycleContributions(group.id, group.cycle).filter(
    (entry) => entry.status === "pending" || entry.status === "late"
  );
  if (!pendingContributions.length) {
    showToast("No pending members to remind.", "warning");
    return;
  }
  pendingContributions.forEach((entry) => {
    notifyUser(
      entry.userId,
      "Contribution reminder",
      `Your ${formatCurrency(entry.amount, group.currency)} contribution for ${group.name} is due.`,
      "reminder",
      `manual-reminder-${group.id}-${group.cycle}-${entry.userId}-${new Date().toISOString().slice(0, 10)}`
    );
  });
  logAudit(actor.id, "SEND_GROUP_REMINDER", "group", group.id, {
    pendingCount: pendingContributions.length,
  });
  persistData();
  showToast(`Reminders sent to ${pendingContributions.length} member(s).`, "success");
  render();
}

function handleRequestPayout(form) {
  const user = getCurrentUser();
  const group = findGroupById(form.dataset.groupId);
  if (!user || !group) {
    return;
  }
  if (!hasVerifiedKyc(user)) {
    showToast("KYC verification is required before requesting payouts.", "error");
    return;
  }
  if (!areAllContributionsPaid(group.id, group.cycle)) {
    showToast("All contributions must be completed before payout request.", "warning");
    return;
  }
  if (getCurrentPayout(group.id, group.cycle)) {
    showToast("Payout request already exists for this cycle.", "warning");
    return;
  }

  const eligibleRecipientId = getEligibleRecipient(group, group.cycle);
  if (eligibleRecipientId !== user.id) {
    showToast("You are not the current eligible recipient.", "error");
    return;
  }

  const formData = new FormData(form);
  const reason = String(formData.get("reason") || "Custom reason");
  const customReason = String(formData.get("customReason") || "").trim();
  const amount = getCycleContributions(group.id, group.cycle).reduce(
    (sum, entry) => sum + Number(entry.amount),
    0
  );

  const payout = {
    id: uid("pay"),
    groupId: group.id,
    cycle: group.cycle,
    recipientId: user.id,
    amount,
    currency: group.currency,
    reason,
    customReason,
    status: "requested",
    requestedAt: new Date().toISOString(),
    leaderApprovedBy: null,
    adminApprovedBy: null,
    recipientMfaConfirmed: false,
    releasedAt: null,
    platformFee: 0,
    netAmount: 0,
  };

  state.data.payouts.push(payout);
  notifyUser(
    group.leaderId,
    "Payout request submitted",
    `${user.fullName} requested payout for ${group.name}.`,
    "payout",
    `payout-request-${group.id}-${group.cycle}`
  );
  state.data.users
    .filter((member) => member.role === "admin")
    .forEach((admin) => {
      notifyUser(
        admin.id,
        "Payout request needs review",
        `Cycle ${group.cycle} payout request is pending in ${group.name}.`,
        "compliance",
        `admin-payout-request-${payout.id}-${admin.id}`
      );
    });
  logAudit(user.id, "REQUEST_PAYOUT", "payout", payout.id, {
    groupId: group.id,
    amount,
  });
  persistData();
  form.reset();
  showToast("Payout request submitted.", "success");
  render();
}

function handleVote(form) {
  const user = getCurrentUser();
  const group = findGroupById(form.dataset.groupId);
  if (!user || !group) {
    return;
  }
  const formData = new FormData(form);
  const candidateId = String(formData.get("candidateId") || "");
  const note = String(formData.get("note") || "").trim();

  if (!group.memberIds.includes(candidateId)) {
    showToast("Vote candidate must be a group member.", "error");
    return;
  }
  if (!group.memberIds.includes(user.id)) {
    showToast("Only group members can vote.", "error");
    return;
  }
  if (
    state.data.payoutVotes.some(
      (vote) => vote.groupId === group.id && vote.cycle === group.cycle && vote.voterId === user.id
    )
  ) {
    showToast("You have already voted for this cycle.", "warning");
    return;
  }

  state.data.payoutVotes.push({
    id: uid("vote"),
    groupId: group.id,
    cycle: group.cycle,
    voterId: user.id,
    candidateId,
    note,
    createdAt: new Date().toISOString(),
  });
  logAudit(user.id, "SUBMIT_PAYOUT_VOTE", "group", group.id, {
    targetUserId: candidateId,
  });
  persistData();
  form.reset();
  showToast("Vote submitted.", "success");
  render();
}

function handlePriorityClaim(form) {
  const user = getCurrentUser();
  const group = findGroupById(form.dataset.groupId);
  if (!user || !group) {
    return;
  }
  const formData = new FormData(form);
  const reason = String(formData.get("reason") || "Custom reason");
  const customReason = String(formData.get("customReason") || "").trim();

  if (!group.memberIds.includes(user.id)) {
    showToast("Only members can submit priority claims.", "error");
    return;
  }
  if (
    state.data.priorityClaims.some(
      (claim) => claim.groupId === group.id && claim.cycle === group.cycle && claim.userId === user.id
    )
  ) {
    showToast("Priority claim already submitted this cycle.", "warning");
    return;
  }

  state.data.priorityClaims.push({
    id: uid("claim"),
    groupId: group.id,
    cycle: group.cycle,
    userId: user.id,
    reason,
    customReason,
    weight: PRIORITY_WEIGHTS[reason] || PRIORITY_WEIGHTS["Custom reason"],
    createdAt: new Date().toISOString(),
  });
  logAudit(user.id, "SUBMIT_PRIORITY_CLAIM", "group", group.id, {
    reason,
  });
  persistData();
  form.reset();
  showToast("Priority claim submitted.", "success");
  render();
}

function approvePayout(groupId, payoutId) {
  const actor = getCurrentUser();
  const group = findGroupById(groupId);
  const payout = findPayoutById(payoutId);
  if (!actor || !group || !payout) {
    return;
  }
  if (!(isGroupLeader(group, actor.id) || actor.role === "admin")) {
    showToast("Only leader/admin can approve payouts.", "error");
    return;
  }
  if (payout.status === "released") {
    showToast("Payout already released.", "warning");
    return;
  }

  requireMfa("Payout approval confirmation", () => {
    if (actor.role === "admin") {
      payout.adminApprovedBy = actor.id;
    } else if (isGroupLeader(group, actor.id)) {
      payout.leaderApprovedBy = actor.id;
    }
    updatePayoutApprovalStatus(group, payout);
    logAudit(actor.id, "APPROVE_PAYOUT", "payout", payout.id, {
      groupId: group.id,
    });
    notifyUser(
      payout.recipientId,
      "Payout approval updated",
      `Your payout request in ${group.name} has updated approvals.`,
      "payout",
      `payout-approval-${payout.id}-${payout.recipientId}`
    );
    persistData();
    showToast("Payout approval recorded.", "success");
    render();
  });
}

function confirmPayoutIdentity(payoutId) {
  const actor = getCurrentUser();
  const payout = findPayoutById(payoutId);
  if (!actor || !payout) {
    return;
  }
  if (actor.id !== payout.recipientId) {
    showToast("Only payout recipient can confirm identity.", "error");
    return;
  }

  requireMfa("Payout recipient confirmation", () => {
    payout.recipientMfaConfirmed = true;
    logAudit(actor.id, "CONFIRM_PAYOUT_MFA", "payout", payout.id, {});
    persistData();
    showToast("Payout MFA confirmed.", "success");
    render();
  });
}

function releasePayout(groupId, payoutId) {
  const actor = getCurrentUser();
  const group = findGroupById(groupId);
  const payout = findPayoutById(payoutId);
  if (!actor || !group || !payout) {
    return;
  }
  if (!(isGroupLeader(group, actor.id) || actor.role === "admin")) {
    showToast("Only leader/admin can release payouts.", "error");
    return;
  }
  updatePayoutApprovalStatus(group, payout);
  if (payout.status !== "approved") {
    showToast("Payout approval conditions are not fully satisfied.", "error");
    return;
  }
  if (!payout.recipientMfaConfirmed) {
    showToast("Recipient MFA confirmation is required.", "error");
    return;
  }
  if (!areAllContributionsPaid(group.id, group.cycle)) {
    showToast("Cannot release payout until all contributions are paid.", "error");
    return;
  }

  requireMfa("Final payout release authorization", () => {
    payout.status = "released";
    payout.releasedAt = new Date().toISOString();
    payout.platformFee = roundTwo(payout.amount * PLATFORM_FEE_RATE);
    payout.netAmount = roundTwo(payout.amount - payout.platformFee);

    notifyUser(
      payout.recipientId,
      "Payout released",
      `Net payout ${formatCurrency(payout.netAmount, payout.currency)} has been released for ${group.name}.`,
      "payout",
      `payout-released-${payout.id}`
    );
    group.memberIds.forEach((memberId) => {
      if (memberId !== payout.recipientId) {
        notifyUser(
          memberId,
          "Payout completed",
          `${findUserById(payout.recipientId)?.fullName || "Recipient"} received payout for ${group.name}.`,
          "payout",
          `payout-completed-${payout.id}-${memberId}`
        );
      }
    });

    rollGroupCycle(group);
    logAudit(actor.id, "RELEASE_PAYOUT", "payout", payout.id, {
      groupId: group.id,
      netAmount: payout.netAmount,
      fee: payout.platformFee,
    });
    persistData();
    showToast("Payout released and next cycle prepared.", "success");
    render();
  });
}

function handleSendChat(form) {
  const user = getCurrentUser();
  const group = findGroupById(form.dataset.groupId);
  if (!user || !group) {
    return;
  }
  if (group.chatArchived || group.status === "completed") {
    showToast("Group chat is archived.", "warning");
    return;
  }
  if (!group.memberIds.includes(user.id)) {
    showToast("Only group members can message this chat.", "error");
    return;
  }
  const formData = new FormData(form);
  const content = String(formData.get("content") || "").trim();
  if (!content) {
    showToast("Message cannot be empty.", "error");
    return;
  }
  const announcement = formData.get("announcement") === "on";
  const pin = formData.get("pin") === "on";
  const canModerate = isGroupLeader(group, user.id) || user.role === "admin";
  const message = {
    id: uid("msg"),
    groupId: group.id,
    userId: user.id,
    content,
    type: announcement && canModerate ? "announcement" : "message",
    pinned: pin && canModerate,
    createdAt: new Date().toISOString(),
  };

  state.data.chats.push(message);
  if (message.type === "announcement") {
    group.memberIds
      .filter((memberId) => memberId !== user.id)
      .forEach((memberId) => {
        notifyUser(
          memberId,
          `Announcement in ${group.name}`,
          content.slice(0, 120),
          "chat",
          `chat-announce-${message.id}-${memberId}`
        );
      });
  }
  logAudit(user.id, "SEND_CHAT_MESSAGE", "chat", message.id, {
    groupId: group.id,
    announcement: message.type === "announcement",
  });
  persistData();
  form.reset();
  showToast("Message sent.", "success");
  render();
}

function togglePinnedMessage(messageId) {
  const actor = getCurrentUser();
  const message = state.data.chats.find((entry) => entry.id === messageId);
  if (!actor || !message) {
    return;
  }
  const group = findGroupById(message.groupId);
  if (!group) {
    return;
  }
  if (!(isGroupLeader(group, actor.id) || actor.role === "admin")) {
    showToast("Only leader/admin can pin or unpin messages.", "error");
    return;
  }
  message.pinned = !message.pinned;
  logAudit(actor.id, "TOGGLE_PIN_MESSAGE", "chat", message.id, {
    pinned: message.pinned,
  });
  persistData();
  render();
}

function handleKycSubmit(form) {
  const user = getCurrentUser();
  if (!user) {
    return;
  }
  const formData = new FormData(form);
  const idType = String(formData.get("idType") || "");
  const idNumber = String(formData.get("idNumber") || "").trim();
  const dob = String(formData.get("dob") || "");
  const selfieToken = String(formData.get("selfieToken") || "").trim();
  const address = String(formData.get("address") || "").trim();

  if (!idType || !idNumber || !dob || !selfieToken) {
    showToast("Complete all mandatory KYC fields.", "error");
    return;
  }
  user.kyc = {
    status: "pending",
    idType,
    idNumberToken: tokenize(`id:${idNumber}`),
    dob,
    selfieToken: tokenize(`selfie:${selfieToken}`),
    address: address ? tokenize(`addr:${address}`) : "",
    submittedAt: new Date().toISOString(),
  };
  notifyAdmins(
    "KYC review required",
    `${user.fullName} submitted KYC documents.`,
    "compliance",
    `kyc-submitted-${user.id}`
  );
  logAudit(user.id, "SUBMIT_KYC", "user", user.id, {});
  persistData();
  form.reset();
  showToast("KYC submitted for admin review.", "success");
  render();
}

function handleSecuritySettings(form) {
  const user = getCurrentUser();
  if (!user) {
    return;
  }
  const formData = new FormData(form);
  user.mfaEnabled = formData.get("mfaEnabled") === "on";
  user.biometricEnabled = formData.get("biometricEnabled") === "on";
  logAudit(user.id, "UPDATE_AUTH_SETTINGS", "user", user.id, {
    mfaEnabled: user.mfaEnabled,
    biometricEnabled: user.biometricEnabled,
  });
  persistData();
  showToast("Security preferences saved.", "success");
  render();
}

function handlePaymentMethod(form) {
  const user = getCurrentUser();
  if (!user) {
    return;
  }
  const formData = new FormData(form);
  const type = String(formData.get("type") || "bank");
  const label = String(formData.get("label") || "").trim();
  const identifier = String(formData.get("identifier") || "").trim();
  const autoDebit = formData.get("autoDebit") === "on";

  if (!label || identifier.length < 2) {
    showToast("Provide payment label and identifier tail.", "error");
    return;
  }

  requireMfa("Payment method update authorization", () => {
    const method = {
      id: uid("pm"),
      type,
      label,
      last4: identifier.slice(-4),
      token: tokenize(`${type}:${label}:${identifier}`),
      autoDebit,
      createdAt: new Date().toISOString(),
    };
    user.paymentMethods.push(method);
    logAudit(user.id, "ADD_PAYMENT_METHOD", "payment_method", method.id, { type });
    persistData();
    form.reset();
    showToast("Payment method tokenized and saved.", "success");
    render();
  });
}

function removePaymentMethod(methodId) {
  const user = getCurrentUser();
  if (!user) {
    return;
  }
  const method = user.paymentMethods.find((entry) => entry.id === methodId);
  if (!method) {
    showToast("Payment method not found.", "warning");
    return;
  }
  requireMfa("Remove payment method authorization", () => {
    user.paymentMethods = user.paymentMethods.filter((entry) => entry.id !== methodId);
    logAudit(user.id, "REMOVE_PAYMENT_METHOD", "payment_method", methodId, {});
    persistData();
    showToast("Payment method removed.", "success");
    render();
  });
}

function removeTrustedDevice(deviceId) {
  const user = getCurrentUser();
  if (!user) {
    return;
  }
  user.knownDevices = user.knownDevices.filter((entry) => entry.id !== deviceId);
  logAudit(user.id, "REMOVE_TRUSTED_DEVICE", "device", deviceId, {});
  persistData();
  showToast("Trusted device removed.", "success");
  render();
}

function reviewKyc(userId, status) {
  const actor = getCurrentUser();
  const target = findUserById(userId);
  if (!actor || actor.role !== "admin" || !target) {
    showToast("Admin role required.", "error");
    return;
  }
  if (!["verified", "rejected"].includes(status)) {
    return;
  }
  target.kyc.status = status;
  target.verifiedBadge = status === "verified";
  notifyUser(
    target.id,
    "KYC review completed",
    `Your KYC status is now: ${status}.`,
    "compliance",
    `kyc-reviewed-${target.id}-${status}-${Date.now()}`
  );
  logAudit(actor.id, "REVIEW_KYC", "user", target.id, { status });
  persistData();
  showToast(`KYC marked ${status}.`, "success");
  render();
}

function handleFraudFlag(form) {
  const actor = getCurrentUser();
  if (!actor || actor.role !== "admin") {
    showToast("Admin role required for fraud flags.", "error");
    return;
  }
  const formData = new FormData(form);
  const targetType = String(formData.get("targetType") || "");
  const targetId = String(formData.get("targetId") || "").trim();
  const reason = String(formData.get("reason") || "").trim();

  if (!targetType || !targetId || !reason) {
    showToast("Target and reason are required.", "error");
    return;
  }

  state.data.fraudFlags.push({
    id: uid("flag"),
    targetType,
    targetId,
    reason,
    createdBy: actor.id,
    createdAt: new Date().toISOString(),
  });
  logAudit(actor.id, "CREATE_FRAUD_FLAG", "flag", targetId, {
    targetType,
  });
  persistData();
  form.reset();
  showToast("Fraud flag created.", "success");
  render();
}

function handleDispute(form) {
  const user = getCurrentUser();
  if (!user) {
    return;
  }
  const groupId = form.dataset.groupId;
  const group = findGroupById(groupId);
  if (!group || !group.memberIds.includes(user.id)) {
    showToast("Only group members can file disputes.", "error");
    return;
  }
  const formData = new FormData(form);
  const summary = String(formData.get("summary") || "").trim();
  if (!summary) {
    showToast("Dispute summary cannot be empty.", "error");
    return;
  }

  const dispute = {
    id: uid("dispute"),
    groupId,
    reporterId: user.id,
    summary,
    status: "open",
    createdAt: new Date().toISOString(),
    resolvedAt: null,
    resolution: "",
  };
  state.data.disputes.push(dispute);
  notifyUser(
    group.leaderId,
    "New dispute filed",
    `${user.fullName} filed a dispute in ${group.name}.`,
    "dispute",
    `dispute-${dispute.id}-leader`
  );
  notifyAdmins(
    "Dispute requires review",
    `${user.fullName} filed a dispute in ${group.name}.`,
    "dispute",
    `dispute-${dispute.id}-admin`
  );
  logAudit(user.id, "FILE_DISPUTE", "dispute", dispute.id, { groupId });
  persistData();
  form.reset();
  showToast("Dispute submitted.", "success");
  render();
}

function resolveDispute(disputeId) {
  const actor = getCurrentUser();
  const dispute = state.data.disputes.find((item) => item.id === disputeId);
  if (!actor || !dispute) {
    return;
  }
  const group = findGroupById(dispute.groupId);
  if (!(actor.role === "admin" || (group && isGroupLeader(group, actor.id)))) {
    showToast("Only leaders/admin can resolve disputes.", "error");
    return;
  }
  dispute.status = "resolved";
  dispute.resolvedAt = new Date().toISOString();
  dispute.resolution = `Resolved by ${actor.fullName}.`;
  notifyUser(
    dispute.reporterId,
    "Dispute resolved",
    `Your dispute in ${group ? group.name : "group"} has been resolved.`,
    "dispute",
    `dispute-resolved-${dispute.id}`
  );
  logAudit(actor.id, "RESOLVE_DISPUTE", "dispute", dispute.id, {});
  persistData();
  showToast("Dispute marked as resolved.", "success");
  render();
}

function toggleGroupStatus(groupId, status) {
  const actor = getCurrentUser();
  const group = findGroupById(groupId);
  if (!actor || !group) {
    return;
  }
  if (actor.role !== "admin") {
    showToast("Only admin can suspend or reactivate groups.", "error");
    return;
  }
  if (!["active", "suspended"].includes(status)) {
    return;
  }

  group.status = status;
  if (status === "suspended") {
    notifyGroupMembers(
      group,
      "Group suspended",
      `${group.name} has been suspended for compliance review.`,
      "compliance",
      `group-suspended-${group.id}`
    );
  } else {
    notifyGroupMembers(
      group,
      "Group reactivated",
      `${group.name} is active again.`,
      "compliance",
      `group-active-${group.id}-${Date.now()}`
    );
  }
  logAudit(actor.id, "UPDATE_GROUP_STATUS", "group", group.id, { status });
  persistData();
  showToast(`Group status updated to ${status}.`, "success");
  render();
}

function copyInviteLink(link) {
  if (!link) {
    return;
  }
  if (!navigator.clipboard) {
    showToast("Clipboard API unavailable in this browser.", "warning");
    return;
  }
  navigator.clipboard
    .writeText(link)
    .then(() => showToast("Invite link copied.", "success"))
    .catch(() => showToast("Failed to copy invite link.", "error"));
}

function markNotificationRead(notificationId) {
  const user = getCurrentUser();
  const notification = state.data.notifications.find((item) => item.id === notificationId);
  if (!user || !notification || notification.userId !== user.id) {
    return;
  }
  notification.read = true;
  persistData();
  render();
}

function markAllNotificationsRead() {
  const user = getCurrentUser();
  if (!user) {
    return;
  }
  state.data.notifications.forEach((note) => {
    if (note.userId === user.id) {
      note.read = true;
    }
  });
  persistData();
  render();
}

function exportReport(format) {
  const actor = getCurrentUser();
  if (!actor || actor.role !== "admin") {
    showToast("Admin role required for exports.", "error");
    return;
  }
  const payload = {
    generatedAt: new Date().toISOString(),
    users: state.data.users.map((user) => ({
      id: user.id,
      fullName: user.fullName,
      email: user.email,
      role: user.role,
      kycStatus: user.kyc.status,
      trustScoreInternal: user.metrics.internalTrustScore,
      createdAt: user.createdAt,
    })),
    groups: state.data.groups.map((group) => ({
      id: group.id,
      name: group.name,
      status: group.status,
      leaderId: group.leaderId,
      members: group.memberIds.length,
      contributionAmount: group.contributionAmount,
      currency: group.currency,
      payoutLogic: group.payoutOrderLogic,
      cycle: group.cycle,
    })),
    transactions: {
      contributions: state.data.contributions.length,
      payouts: state.data.payouts.length,
      disputes: state.data.disputes.length,
      flags: state.data.fraudFlags.length,
    },
  };

  if (format === "csv") {
    const csv = [
      "type,id,name_or_email,status,metric_a,metric_b",
      ...payload.users.map(
        (user) =>
          `user,${user.id},"${escapeCsv(user.fullName)}","${user.kycStatus}",${user.trustScoreInternal},${user.role}`
      ),
      ...payload.groups.map(
        (group) =>
          `group,${group.id},"${escapeCsv(group.name)}","${group.status}",${group.members},${group.cycle}`
      ),
    ].join("\n");
    downloadText(`susukonnect-report-${Date.now()}.csv`, csv, "text/csv");
  } else {
    downloadText(
      `susukonnect-report-${Date.now()}.json`,
      JSON.stringify(payload, null, 2),
      "application/json"
    );
  }
  logAudit(actor.id, "EXPORT_REPORT", "report", format, {});
  persistData();
  showToast("Report exported.", "success");
}

function exportAuditLog() {
  const actor = getCurrentUser();
  if (!actor || actor.role !== "admin") {
    showToast("Admin role required for audit export.", "error");
    return;
  }
  const payload = {
    generatedAt: new Date().toISOString(),
    chainLength: state.data.auditLogs.length,
    entries: state.data.auditLogs,
  };
  downloadText(
    `susukonnect-audit-${Date.now()}.json`,
    JSON.stringify(payload, null, 2),
    "application/json"
  );
  logAudit(actor.id, "EXPORT_AUDIT_CHAIN", "audit", "chain", {
    count: state.data.auditLogs.length,
  });
  persistData();
  showToast("Audit log exported.", "success");
}

function handleMfaSubmit(event) {
  event.preventDefault();
  withUiGuard("MFA submit", () => {
    if (!state.pendingMfa) {
      return;
    }

    const codeInput = document.getElementById("mfa-input");
    if (!(codeInput instanceof HTMLInputElement)) {
      showToast("MFA input is unavailable. Please retry.", "error");
      return;
    }
    const code = String(codeInput.value || "").trim();
    if (code !== state.pendingMfa.code) {
      showToast("Invalid MFA code.", "error");
      return;
    }

    const onSuccess = state.pendingMfa.onSuccess;
    closeMfaModal();
    onSuccess?.();
  });
}

function openMfaModal(purpose, onSuccess) {
  const code = String(Math.floor(100000 + Math.random() * 900000));
  state.pendingMfa = {
    code,
    purpose,
    onSuccess,
  };
  updateMfaModal();
}

function closeMfaModal(triggerCancelledToast = false) {
  state.pendingMfa = null;
  updateMfaModal();
  if (triggerCancelledToast) {
    showToast("MFA flow cancelled.", "warning");
  }
}

function updateMfaModal() {
  const modal = document.getElementById("mfa-modal");
  const purpose = document.getElementById("mfa-purpose");
  const code = document.getElementById("mfa-code");
  const input = document.getElementById("mfa-input");

  if (!modal || !purpose || !code || !input) {
    return;
  }

  if (!state.pendingMfa) {
    modal.classList.add("hidden");
    purpose.textContent = "";
    code.textContent = "";
    input.value = "";
    return;
  }
  purpose.textContent = state.pendingMfa.purpose;
  code.textContent = `Demo MFA code: ${state.pendingMfa.code}`;
  modal.classList.remove("hidden");
  input.value = "";
  input.focus();
}

function requireMfa(purpose, callback) {
  openMfaModal(purpose, callback);
}

function synchronizeData() {
  let dirty = false;

  state.data.groups.forEach((group) => {
    const beforeOrder = group.payoutOrder.join(",");
    group.payoutOrder = group.payoutOrder.filter((memberId) => group.memberIds.includes(memberId));
    group.memberIds.forEach((memberId) => {
      if (!group.payoutOrder.includes(memberId)) {
        group.payoutOrder.push(memberId);
      }
    });
    if (beforeOrder !== group.payoutOrder.join(",")) {
      dirty = true;
    }
    dirty = ensureCycleContributionRecords(group) || dirty;
    if (group.status === "completed" && !group.chatArchived) {
      group.chatArchived = true;
      dirty = true;
    }
  });

  dirty = refreshLateContributionStatuses() || dirty;
  dirty = generateAutoReminders() || dirty;
  dirty = updateUserMetrics() || dirty;

  if (dirty) {
    persistData();
  }
}

function refreshLateContributionStatuses() {
  let changed = false;
  const now = new Date();

  state.data.contributions.forEach((entry) => {
    if (entry.status === "paid") {
      return;
    }
    const group = findGroupById(entry.groupId);
    if (!group || group.status !== "active") {
      return;
    }
    const graceDeadline = new Date(getGraceDeadline(group, entry.cycle));
    if (now > graceDeadline && entry.status !== "late") {
      entry.status = "late";
      changed = true;
      notifyUser(
        group.leaderId,
        "Late contribution alert",
        `${findUserById(entry.userId)?.fullName || entry.userId} is late for ${group.name} cycle ${entry.cycle}.`,
        "compliance",
        `late-alert-${entry.id}`
      );
      logAudit(group.leaderId, "LATE_CONTRIBUTION_ALERT", "contribution", entry.id, {
        groupId: group.id,
      });
    }
  });
  return changed;
}

function generateAutoReminders() {
  let changed = false;
  const now = new Date();
  state.data.contributions.forEach((entry) => {
    if (entry.status === "paid") {
      return;
    }
    const group = findGroupById(entry.groupId);
    if (!group || group.status !== "active") {
      return;
    }
    const dueDate = new Date(entry.dueDate);
    const daysUntilDue = Math.floor((dueDate.getTime() - now.getTime()) / (24 * 60 * 60 * 1000));
    if (daysUntilDue <= 3 && daysUntilDue >= 0 && !entry.reminderSentAt) {
      notifyUser(
        entry.userId,
        "Contribution due reminder",
        `${formatCurrency(entry.amount, group.currency)} due soon in ${group.name}.`,
        "reminder",
        `auto-reminder-${entry.id}`
      );
      entry.reminderSentAt = new Date().toISOString();
      changed = true;
    }
  });
  return changed;
}

function updateUserMetrics() {
  let changed = false;
  state.data.users.forEach((user) => {
    const paidContributions = state.data.contributions.filter(
      (entry) => entry.userId === user.id && entry.status === "paid"
    ).length;
    const completedGroups = state.data.groups.filter(
      (group) => group.status === "completed" && group.memberIds.includes(user.id)
    ).length;
    const lateCount = state.data.contributions.filter(
      (entry) => entry.userId === user.id && entry.status === "late"
    ).length;
    const trustScore = Math.max(
      0,
      Math.min(
        100,
        45 +
          Math.min(20, paidContributions * 2) +
          (user.kyc.status === "verified" ? 15 : 0) +
          Math.min(12, completedGroups * 3) -
          Math.min(20, lateCount * 4)
      )
    );

    if (
      user.metrics.paidContributions !== paidContributions ||
      user.metrics.completedGroups !== completedGroups ||
      user.metrics.internalTrustScore !== trustScore
    ) {
      user.metrics.paidContributions = paidContributions;
      user.metrics.completedGroups = completedGroups;
      user.metrics.internalTrustScore = trustScore;
      changed = true;
    }
  });
  return changed;
}

function ensureCycleContributionRecords(group) {
  let changed = false;
  const dueDate = getCycleDueDate(group, group.cycle);
  group.memberIds.forEach((memberId) => {
    const existing = state.data.contributions.find(
      (entry) => entry.groupId === group.id && entry.cycle === group.cycle && entry.userId === memberId
    );
    if (!existing) {
      state.data.contributions.push({
        id: uid("ctr"),
        groupId: group.id,
        cycle: group.cycle,
        userId: memberId,
        amount: group.contributionAmount,
        dueDate,
        status: "pending",
        methodId: "",
        methodType: "",
        autoDebit: false,
        paidAt: null,
        reminderSentAt: null,
        createdAt: new Date().toISOString(),
      });
      changed = true;
    }
  });
  return changed;
}

function addMemberToGroup(group, userId) {
  if (!group.memberIds.includes(userId)) {
    group.memberIds.push(userId);
    if (!group.payoutOrder.includes(userId)) {
      group.payoutOrder.push(userId);
    }
    ensureCycleContributionRecords(group);
    notifyUser(
      userId,
      "Group membership active",
      `You have joined ${group.name}.`,
      "group",
      `group-joined-${group.id}-${userId}`
    );
    notifyGroupMembers(
      group,
      "New member joined",
      `${findUserById(userId)?.fullName || userId} joined ${group.name}.`,
      "group",
      `member-joined-${group.id}-${userId}`
    );
  }
}

function updatePayoutApprovalStatus(group, payout) {
  const leaderApproved = group.requiresLeaderApproval ? Boolean(payout.leaderApprovedBy) : true;
  const adminApproved = isAdminApprovalRequired(payout.amount)
    ? Boolean(payout.adminApprovedBy)
    : true;
  payout.status = leaderApproved && adminApproved ? "approved" : "requested";
}

function rollGroupCycle(group) {
  group.cycle += 1;
  const reachedMaxCycles = group.cycle > group.totalMembers;
  if (reachedMaxCycles) {
    group.status = "completed";
    group.chatArchived = true;
    notifyGroupMembers(
      group,
      "Group cycle completed",
      `${group.name} completed all scheduled payout cycles.`,
      "milestone",
      `group-completed-${group.id}`
    );
    return;
  }
  ensureCycleContributionRecords(group);
  notifyGroupMembers(
    group,
    "New cycle started",
    `${group.name} moved to cycle ${group.cycle}.`,
    "milestone",
    `group-cycle-${group.id}-${group.cycle}`
  );
}

function summarizeVotes(groupId, cycle) {
  const votes = state.data.payoutVotes.filter(
    (vote) => vote.groupId === groupId && vote.cycle === cycle
  );
  const countMap = {};
  votes.forEach((vote) => {
    countMap[vote.candidateId] = (countMap[vote.candidateId] || 0) + 1;
  });
  return Object.entries(countMap)
    .map(([candidateId, count]) => ({
      candidateId,
      count,
      name: findUserById(candidateId)?.fullName || candidateId,
    }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));
}

function summarizePriorityClaims(groupId, cycle) {
  return state.data.priorityClaims
    .filter((claim) => claim.groupId === groupId && claim.cycle === cycle)
    .map((claim) => ({
      ...claim,
      name: findUserById(claim.userId)?.fullName || claim.userId,
    }))
    .sort((a, b) => b.weight - a.weight || new Date(a.createdAt) - new Date(b.createdAt));
}

function getEligibleRecipient(group, cycle) {
  const rotationRecipient =
    group.payoutOrder.length > 0
      ? group.payoutOrder[(cycle - 1) % group.payoutOrder.length]
      : group.memberIds[(cycle - 1) % group.memberIds.length];
  if (group.payoutOrderLogic === "fixed") {
    return rotationRecipient;
  }
  if (group.payoutOrderLogic === "voting") {
    const voteSummary = summarizeVotes(group.id, cycle);
    return voteSummary.length ? voteSummary[0].candidateId : rotationRecipient;
  }
  if (group.payoutOrderLogic === "priority") {
    const prioritySummary = summarizePriorityClaims(group.id, cycle);
    return prioritySummary.length ? prioritySummary[0].userId : rotationRecipient;
  }
  return rotationRecipient;
}

function handleMfaRequiredAction(purpose, action) {
  requireMfa(purpose, action);
}

function markSessionActivity() {
  if (!state.session) {
    return;
  }
  state.session.lastActivityAt = new Date().toISOString();
  saveSession(state.session);
}

function touchSession() {
  markSessionActivity();
}

function enforceSessionTimeout() {
  if (!state.session) {
    return;
  }
  const lastActivity = new Date(state.session.lastActivityAt || state.session.createdAt);
  const elapsedMinutes = (Date.now() - lastActivity.getTime()) / 1000 / 60;
  if (elapsedMinutes > SESSION_TIMEOUT_MINUTES) {
    logoutCurrentUser(true);
  }
}

function logoutCurrentUser(timeout = false) {
  const user = getCurrentUser();
  if (user) {
    logAudit(user.id, "LOGOUT", "user", user.id, { timeout });
  }
  state.session = null;
  clearSession();
  persistData();
  state.activeTab = "dashboard";
  showToast(timeout ? "Session expired due to inactivity." : "Signed out.", timeout ? "warning" : "success");
  render();
}

function registerServiceWorker() {
  if (!("serviceWorker" in navigator)) {
    return;
  }
  navigator.serviceWorker
    .register("./service-worker.js")
    .catch(() => {
      showToast("Service worker registration skipped.", "warning");
    });
}

function showToast(message, type = "success") {
  const container = document.getElementById("toast-root");
  if (!container) {
    return;
  }
  const toast = document.createElement("div");
  toast.className = `toast ${type}`;
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => {
    toast.remove();
  }, 4000);
}

function renderRoleBadge(role) {
  const text = role === "admin" ? "Platform Admin" : role === "leader" ? "Group Leader" : "Member";
  return `<span class="status-badge status-neutral">${escapeHtml(text)}</span>`;
}

function renderKycBadge(status) {
  switch (status) {
    case "verified":
      return '<span class="status-badge status-success">KYC verified</span>';
    case "pending":
      return '<span class="status-badge status-warning">KYC pending</span>';
    case "rejected":
      return '<span class="status-badge status-danger">KYC rejected</span>';
    default:
      return '<span class="status-badge status-neutral">KYC unverified</span>';
  }
}

function renderContributionStatusBadge(status) {
  if (status === "paid") {
    return '<span class="status-badge status-success">Paid</span>';
  }
  if (status === "late") {
    return '<span class="status-badge status-danger">Late</span>';
  }
  return '<span class="status-badge status-warning">Pending</span>';
}

function renderPayoutStatusBadge(status) {
  if (status === "released") {
    return '<span class="status-badge status-success">Released</span>';
  }
  if (status === "approved") {
    return '<span class="status-badge status-success">Approved</span>';
  }
  if (status === "rejected") {
    return '<span class="status-badge status-danger">Rejected</span>';
  }
  return '<span class="status-badge status-warning">Requested</span>';
}

function renderGroupStatusBadge(status) {
  if (status === "active") {
    return '<span class="status-badge status-success">Active</span>';
  }
  if (status === "suspended") {
    return '<span class="status-badge status-danger">Suspended</span>';
  }
  if (status === "completed") {
    return '<span class="status-badge status-neutral">Completed</span>';
  }
  return '<span class="status-badge status-neutral">Draft</span>';
}

function canAccessTab(user, tabId) {
  const config = TAB_CONFIG.find((tab) => tab.id === tabId);
  return config ? config.roles.includes(user.role) : true;
}

function canManageGroup(actor, group) {
  return actor.role === "admin" || isGroupLeader(group, actor.id);
}

function findGroupById(groupId) {
  return state.data.groups.find((group) => group.id === groupId);
}

function findContributionById(contributionId) {
  return state.data.contributions.find((entry) => entry.id === contributionId);
}

function findPayoutById(payoutId) {
  return state.data.payouts.find((entry) => entry.id === payoutId);
}

function findUserById(userId) {
  return state.data.users.find((user) => user.id === userId);
}

function getCurrentPayout(groupId, cycle) {
  return state.data.payouts.find((payout) => payout.groupId === groupId && payout.cycle === cycle);
}

function getCurrentUser() {
  if (!state.session) {
    return null;
  }
  return findUserById(state.session.userId) || null;
}

function getGroupsForUser(userId) {
  return state.data.groups.filter(
    (group) => Array.isArray(group.memberIds) && group.memberIds.includes(userId)
  );
}

function getCycleContributions(groupId, cycle) {
  return state.data.contributions.filter(
    (entry) => entry.groupId === groupId && entry.cycle === cycle
  );
}

function getContributionRecord(groupId, cycle, userId) {
  return state.data.contributions.find(
    (entry) => entry.groupId === groupId && entry.cycle === cycle && entry.userId === userId
  );
}

function areAllContributionsPaid(groupId, cycle) {
  const entries = getCycleContributions(groupId, cycle);
  return entries.length > 0 && entries.every((entry) => entry.status === "paid");
}

function getCycleDueDate(group, cycle) {
  const startDate = new Date(group.startDate);
  const dueDate = new Date(startDate);
  dueDate.setMonth(startDate.getMonth() + (cycle - 1));
  return dueDate.toISOString();
}

function getGraceDeadline(group, cycle) {
  const dueDate = new Date(getCycleDueDate(group, cycle));
  dueDate.setDate(dueDate.getDate() + Number(group.gracePeriodDays || 0));
  return dueDate.toISOString();
}

function getCalendarEventsForUser(userId) {
  const groups = getGroupsForUser(userId);
  const events = [];

  groups.forEach((group) => {
    const dueDate = getCycleDueDate(group, group.cycle);
    const graceDeadline = getGraceDeadline(group, group.cycle);
    events.push({
      id: `due-${group.id}-${group.cycle}`,
      date: dueDate,
      title: "Monthly contribution due",
      typeLabel: `${formatCurrency(group.contributionAmount, group.currency)} expected`,
      groupName: group.name,
    });
    events.push({
      id: `grace-${group.id}-${group.cycle}`,
      date: graceDeadline,
      title: "Grace period deadline",
      typeLabel: `Late status starts after this date`,
      groupName: group.name,
    });

    const payout = getCurrentPayout(group.id, group.cycle);
    events.push({
      id: `payout-${group.id}-${group.cycle}`,
      date: dueDate,
      title: payout ? "Payout workflow in progress" : "Payout check",
      typeLabel: payout ? `Status: ${payout.status}` : "Waiting for request / approvals",
      groupName: group.name,
    });

    if (group.status === "completed") {
      events.push({
        id: `milestone-${group.id}`,
        date: group.updatedAt || group.createdAt,
        title: "Group completed",
        typeLabel: "Chat archived and cycle closed",
        groupName: group.name,
      });
    }
  });

  return events.sort((a, b) => new Date(a.date) - new Date(b.date));
}

function getUserNotifications(userId) {
  return state.data.notifications
    .filter((item) => item.userId === userId)
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
}

function notifyUser(userId, title, body, type, dedupeKey) {
  if (
    dedupeKey &&
    state.data.notifications.some(
      (note) => note.userId === userId && note.dedupeKey === dedupeKey
    )
  ) {
    return;
  }
  state.data.notifications.push({
    id: uid("note"),
    userId,
    title,
    body,
    type,
    dedupeKey: dedupeKey || "",
    read: false,
    createdAt: new Date().toISOString(),
  });
}

function notifyAdmins(title, body, type, dedupeKeyBase) {
  state.data.users
    .filter((user) => user.role === "admin")
    .forEach((admin) => {
      notifyUser(admin.id, title, body, type, `${dedupeKeyBase}-${admin.id}`);
    });
}

function notifyGroupMembers(group, title, body, type, dedupeKeyBase) {
  group.memberIds.forEach((memberId) => {
    notifyUser(memberId, title, body, type, `${dedupeKeyBase}-${memberId}`);
  });
}

function logAudit(actorId, action, targetType, targetId, metadata = {}) {
  const previousHash =
    state.data.auditLogs.length > 0
      ? state.data.auditLogs[state.data.auditLogs.length - 1].entryHash
      : "GENESIS";
  const timestamp = new Date().toISOString();
  const payload = `${previousHash}|${timestamp}|${actorId}|${action}|${targetType}|${targetId}|${JSON.stringify(metadata)}`;
  const entryHash = hashValue(payload);
  state.data.auditLogs.push({
    id: uid("audit"),
    actorId,
    action,
    targetType,
    targetId,
    metadata,
    timestamp,
    previousHash,
    entryHash,
  });
}

function isGroupLeader(group, userId) {
  return group.leaderId === userId;
}

function isGroupMember(groupId, userId) {
  const group = findGroupById(groupId);
  return Boolean(group && group.memberIds.includes(userId));
}

function hasVerifiedKyc(user) {
  return user.kyc.status === "verified";
}

function isCurrentCycleContribution(entry) {
  const group = findGroupById(entry.groupId);
  return Boolean(group && group.cycle === entry.cycle);
}

function isAdminApprovalRequired(amount) {
  return Number(amount) >= ADMIN_PAYOUT_APPROVAL_THRESHOLD;
}

function upsertKnownDevice(user, deviceId) {
  const existing = user.knownDevices.find((device) => device.id === deviceId);
  const label = navigator.userAgent.slice(0, 60);
  if (existing) {
    existing.lastSeenAt = new Date().toISOString();
    existing.label = label;
    return;
  }
  user.knownDevices.push({
    id: deviceId,
    label,
    lastSeenAt: new Date().toISOString(),
  });
}

function applyGroupFilters(groups) {
  const maxContribution = Number(state.groupFilters.maxContribution || 0);
  return groups.filter((group) => {
    const groupName = String(group?.name || "").toLowerCase();
    const groupCommunity = String(group?.communityType || "").toLowerCase();
    const groupLocation = String(group?.location || "").toLowerCase();
    const groupContribution = Number(group?.contributionAmount || 0);
    const groupStartTimestamp = Date.parse(String(group?.startDate || ""));
    const filterStartTimestamp = Date.parse(state.groupFilters.startDate || "");

    const nameMatch = state.groupFilters.query
      ? groupName.includes(state.groupFilters.query.toLowerCase())
      : true;
    const communityMatch = state.groupFilters.community
      ? groupCommunity.includes(state.groupFilters.community.toLowerCase())
      : true;
    const locationMatch = state.groupFilters.location
      ? groupLocation.includes(state.groupFilters.location.toLowerCase())
      : true;
    const amountMatch = maxContribution
      ? groupContribution <= maxContribution
      : true;
    const startDateMatch = state.groupFilters.startDate
      ? !Number.isNaN(groupStartTimestamp) &&
        !Number.isNaN(filterStartTimestamp) &&
        groupStartTimestamp >= filterStartTimestamp
      : true;
    return nameMatch && communityMatch && locationMatch && amountMatch && startDateMatch;
  });
}

function calculatePlatformFee(amount) {
  return roundTwo(Number(amount || 0) * PLATFORM_FEE_RATE);
}

function downloadText(filename, content, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

function monthKey(dateString) {
  const date = new Date(dateString);
  return date.toLocaleDateString(undefined, {
    month: "long",
    year: "numeric",
  });
}

function formatCurrency(value, currency = "USD") {
  try {
    return new Intl.NumberFormat(undefined, {
      style: "currency",
      currency,
      maximumFractionDigits: 2,
    }).format(Number(value || 0));
  } catch (_) {
    return `${currency} ${Number(value || 0).toFixed(2)}`;
  }
}

function formatDate(value) {
  return new Date(value).toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

function formatDateTime(value) {
  return new Date(value).toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function escapeCsv(value) {
  return String(value ?? "").replace(/"/g, '""');
}

function roundTwo(value) {
  return Math.round((Number(value) + Number.EPSILON) * 100) / 100;
}

function uid(prefix) {
  return `${prefix}_${Math.random().toString(36).slice(2, 10)}${Date.now().toString(36).slice(-4)}`;
}

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function normalizePhone(value) {
  return String(value || "")
    .replace(/[^\d+]/g, "")
    .trim();
}

function hashPassword(password, salt) {
  return hashValue(`${salt}:${password}`);
}

function tokenize(value) {
  return `tok_${hashValue(value)}_${Math.random().toString(36).slice(2, 7)}`;
}

function hashValue(value) {
  let hash = 2166136261;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return `h${(hash >>> 0).toString(16).padStart(8, "0")}`;
}

function getDeviceFingerprint() {
  const existing = safeStorageGet(DEVICE_KEY);
  if (existing) {
    return existing;
  }
  const fingerprint = [
    navigator.userAgent,
    navigator.language,
    Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC",
    Math.random().toString(36).slice(2, 10),
  ].join("|");
  const token = `dev_${hashValue(fingerprint)}_${Date.now().toString(36)}`;
  safeStorageSet(DEVICE_KEY, token);
  return token;
}

function persistData() {
  safeStorageSet(STORAGE_KEY, JSON.stringify(state.data));
}

function loadData() {
  const saved = safeStorageGet(STORAGE_KEY);
  if (!saved) {
    return createSeedData();
  }
  try {
    return JSON.parse(saved);
  } catch (_) {
    return createSeedData();
  }
}

function loadSession() {
  const saved = safeStorageGet(SESSION_KEY);
  if (!saved) {
    return null;
  }
  try {
    return JSON.parse(saved);
  } catch (_) {
    return null;
  }
}

function saveSession(session) {
  safeStorageSet(SESSION_KEY, JSON.stringify(session));
}

function clearSession() {
  safeStorageRemove(SESSION_KEY);
}

function withUiGuard(actionName, fn) {
  try {
    return fn();
  } catch (error) {
    notifyRuntimeError(actionName, error);
    render();
    return undefined;
  }
}

function notifyRuntimeError(actionName, error) {
  // Keep stack traces available for diagnostics.
  console.error(`[SusuKonnect] ${actionName}`, error);
  const now = Date.now();
  if (now - lastRuntimeErrorToastAt < RUNTIME_ERROR_TOAST_COOLDOWN_MS) {
    return;
  }
  lastRuntimeErrorToastAt = now;
  if (typeof showToast === "function") {
    showToast(
      "Something went wrong. Please retry. If this keeps happening, refresh the app.",
      "error"
    );
  }
}

function reportStorageIssue(error) {
  console.warn("[SusuKonnect] Browser storage is unavailable.", error);
  if (storageWarningShown) {
    return;
  }
  storageWarningShown = true;
  setTimeout(() => {
    if (typeof showToast === "function") {
      showToast(
        "Browser storage is blocked. Signups may not persist until storage is enabled.",
        "warning"
      );
    }
  }, 0);
}

function safeStorageGet(key) {
  try {
    return localStorage.getItem(key);
  } catch (error) {
    reportStorageIssue(error);
    return null;
  }
}

function safeStorageSet(key, value) {
  try {
    localStorage.setItem(key, value);
    return true;
  } catch (error) {
    reportStorageIssue(error);
    return false;
  }
}

function safeStorageRemove(key) {
  try {
    localStorage.removeItem(key);
    return true;
  } catch (error) {
    reportStorageIssue(error);
    return false;
  }
}

function ensureDataShape(rawData) {
  const raw = rawData && typeof rawData === "object" ? rawData : {};
  const data = {
    users: Array.isArray(raw.users) ? raw.users : [],
    groups: Array.isArray(raw.groups) ? raw.groups : [],
    contributions: Array.isArray(raw.contributions) ? raw.contributions : [],
    payouts: Array.isArray(raw.payouts) ? raw.payouts : [],
    payoutVotes: Array.isArray(raw.payoutVotes) ? raw.payoutVotes : [],
    priorityClaims: Array.isArray(raw.priorityClaims) ? raw.priorityClaims : [],
    chats: Array.isArray(raw.chats) ? raw.chats : [],
    notifications: Array.isArray(raw.notifications) ? raw.notifications : [],
    auditLogs: Array.isArray(raw.auditLogs) ? raw.auditLogs : [],
    disputes: Array.isArray(raw.disputes) ? raw.disputes : [],
    fraudFlags: Array.isArray(raw.fraudFlags) ? raw.fraudFlags : [],
    authControls:
      raw.authControls && typeof raw.authControls === "object"
        ? raw.authControls
        : { loginAttempts: {} },
  };

  if (!data.authControls.loginAttempts || typeof data.authControls.loginAttempts !== "object") {
    data.authControls.loginAttempts = {};
  }

  data.users = data.users
    .filter((user) => user && typeof user === "object")
    .map((user, index) => {
      const knownDevices = Array.isArray(user.knownDevices)
        ? user.knownDevices
            .filter((device) => device && typeof device === "object")
            .map((device) => ({
              id: String(device.id || uid("dev")),
              label: String(device.label || "Trusted device"),
              lastSeenAt: asIsoTimestamp(device.lastSeenAt),
            }))
        : [];
      const paymentMethods = Array.isArray(user.paymentMethods)
        ? user.paymentMethods
            .filter((method) => method && typeof method === "object")
            .map((method) => ({
              id: String(method.id || uid("pm")),
              type: String(method.type || "bank"),
              label: String(method.label || "Payment method"),
              last4: String(method.last4 || "0000"),
              token: String(method.token || tokenize(`method:${method.id || uid("pmseed")}`)),
              autoDebit: Boolean(method.autoDebit),
              createdAt: asIsoTimestamp(method.createdAt),
            }))
        : [];
      const metrics = user.metrics && typeof user.metrics === "object" ? user.metrics : {};
      const kyc = user.kyc && typeof user.kyc === "object" ? user.kyc : {};
      return {
        id: String(user.id || `usr_recovered_${index}`),
        fullName: String(user.fullName || "Unknown User"),
        email: normalizeEmail(String(user.email || `recovered${index}@susukonnect.app`)),
        phone: String(user.phone || ""),
        role: ["member", "leader", "admin"].includes(user.role) ? user.role : "member",
        salt: String(user.salt || uid("salt")),
        passwordHash: String(user.passwordHash || hashPassword("Password@2026", String(user.salt || uid("salt")))),
        acceptedTerms: user.acceptedTerms !== false,
        verifiedBadge: Boolean(user.verifiedBadge),
        biometricEnabled: typeof user.biometricEnabled === "boolean" ? user.biometricEnabled : false,
        mfaEnabled: typeof user.mfaEnabled === "boolean" ? user.mfaEnabled : true,
        status: user.status === "suspended" ? "suspended" : "active",
        knownDevices,
        paymentMethods,
        kyc: {
          status: ["verified", "pending", "rejected", "unverified"].includes(kyc.status)
            ? kyc.status
            : "unverified",
          idType: String(kyc.idType || ""),
          idNumberToken: String(kyc.idNumberToken || ""),
          dob: String(kyc.dob || ""),
          selfieToken: String(kyc.selfieToken || ""),
          address: String(kyc.address || ""),
          submittedAt: kyc.submittedAt ? asIsoTimestamp(kyc.submittedAt) : null,
        },
        metrics: {
          paidContributions: asFiniteNumber(metrics.paidContributions, 0),
          completedGroups: asFiniteNumber(metrics.completedGroups, 0),
          internalTrustScore: asFiniteNumber(metrics.internalTrustScore, 50),
        },
        createdAt: asIsoTimestamp(user.createdAt),
        lastLoginAt: user.lastLoginAt ? asIsoTimestamp(user.lastLoginAt) : null,
      };
    });

  data.groups = data.groups
    .filter((group) => group && typeof group === "object")
    .map((group, index) => {
      const leaderId = String(group.leaderId || data.users[0]?.id || "");
      const memberIds = normalizeStringArray(group.memberIds);
      if (leaderId && !memberIds.includes(leaderId)) {
        memberIds.unshift(leaderId);
      }
      const joinRequests = normalizeStringArray(group.joinRequests).filter(
        (userId) => !memberIds.includes(userId)
      );
      const payoutOrder = normalizeStringArray(group.payoutOrder).filter((userId) =>
        memberIds.includes(userId)
      );
      memberIds.forEach((userId) => {
        if (!payoutOrder.includes(userId)) {
          payoutOrder.push(userId);
        }
      });
      return {
        id: String(group.id || `grp_recovered_${index}`),
        inviteCode: String(group.inviteCode || uid("join")),
        name: String(group.name || `Recovered Group ${index + 1}`),
        description: String(group.description || ""),
        communityType: String(group.communityType || ""),
        location: String(group.location || ""),
        startDate: asDateInput(group.startDate),
        contributionAmount: asFiniteNumber(group.contributionAmount, 0),
        currency: CURRENCIES.includes(group.currency) ? group.currency : "USD",
        totalMembers: Math.max(2, Math.round(asFiniteNumber(group.totalMembers, memberIds.length || 2))),
        payoutFrequency: "monthly",
        payoutOrderLogic: ["fixed", "voting", "priority"].includes(group.payoutOrderLogic)
          ? group.payoutOrderLogic
          : "fixed",
        gracePeriodDays: Math.max(0, Math.round(asFiniteNumber(group.gracePeriodDays, 0))),
        requiresLeaderApproval: Boolean(group.requiresLeaderApproval),
        rules: String(group.rules || ""),
        leaderId,
        memberIds,
        joinRequests,
        payoutOrder,
        cycle: Math.max(1, Math.round(asFiniteNumber(group.cycle, 1))),
        status: ["active", "suspended", "completed"].includes(group.status)
          ? group.status
          : "active",
        chatArchived: Boolean(group.chatArchived),
        createdAt: asIsoTimestamp(group.createdAt),
        updatedAt: group.updatedAt ? asIsoTimestamp(group.updatedAt) : undefined,
      };
    });

  data.contributions = data.contributions
    .filter((entry) => entry && typeof entry === "object")
    .map((entry, index) => ({
      id: String(entry.id || `ctr_recovered_${index}`),
      groupId: String(entry.groupId || ""),
      cycle: Math.max(1, Math.round(asFiniteNumber(entry.cycle, 1))),
      userId: String(entry.userId || ""),
      amount: asFiniteNumber(entry.amount, 0),
      dueDate: asIsoTimestamp(entry.dueDate),
      status: ["pending", "late", "paid"].includes(entry.status) ? entry.status : "pending",
      methodId: String(entry.methodId || ""),
      methodType: String(entry.methodType || ""),
      autoDebit: Boolean(entry.autoDebit),
      paidAt: entry.paidAt ? asIsoTimestamp(entry.paidAt) : null,
      reminderSentAt: entry.reminderSentAt ? asIsoTimestamp(entry.reminderSentAt) : null,
      createdAt: asIsoTimestamp(entry.createdAt),
    }));

  data.payouts = data.payouts
    .filter((entry) => entry && typeof entry === "object")
    .map((entry, index) => ({
      id: String(entry.id || `pay_recovered_${index}`),
      groupId: String(entry.groupId || ""),
      cycle: Math.max(1, Math.round(asFiniteNumber(entry.cycle, 1))),
      recipientId: String(entry.recipientId || ""),
      amount: asFiniteNumber(entry.amount, 0),
      currency: CURRENCIES.includes(entry.currency) ? entry.currency : "USD",
      reason: PAYOUT_REASONS.includes(entry.reason) ? entry.reason : "Custom reason",
      customReason: String(entry.customReason || ""),
      status: ["requested", "approved", "released", "rejected"].includes(entry.status)
        ? entry.status
        : "requested",
      requestedAt: asIsoTimestamp(entry.requestedAt),
      leaderApprovedBy: entry.leaderApprovedBy ? String(entry.leaderApprovedBy) : null,
      adminApprovedBy: entry.adminApprovedBy ? String(entry.adminApprovedBy) : null,
      recipientMfaConfirmed: Boolean(entry.recipientMfaConfirmed),
      releasedAt: entry.releasedAt ? asIsoTimestamp(entry.releasedAt) : null,
      platformFee: asFiniteNumber(entry.platformFee, 0),
      netAmount: asFiniteNumber(entry.netAmount, 0),
    }));

  data.payoutVotes = data.payoutVotes
    .filter((entry) => entry && typeof entry === "object")
    .map((entry, index) => ({
      id: String(entry.id || `vote_recovered_${index}`),
      groupId: String(entry.groupId || ""),
      cycle: Math.max(1, Math.round(asFiniteNumber(entry.cycle, 1))),
      voterId: String(entry.voterId || ""),
      candidateId: String(entry.candidateId || ""),
      note: String(entry.note || ""),
      createdAt: asIsoTimestamp(entry.createdAt),
    }));

  data.priorityClaims = data.priorityClaims
    .filter((entry) => entry && typeof entry === "object")
    .map((entry, index) => ({
      id: String(entry.id || `claim_recovered_${index}`),
      groupId: String(entry.groupId || ""),
      cycle: Math.max(1, Math.round(asFiniteNumber(entry.cycle, 1))),
      userId: String(entry.userId || ""),
      reason: PAYOUT_REASONS.includes(entry.reason) ? entry.reason : "Custom reason",
      customReason: String(entry.customReason || ""),
      weight: asFiniteNumber(entry.weight, PRIORITY_WEIGHTS["Custom reason"]),
      createdAt: asIsoTimestamp(entry.createdAt),
    }));

  data.chats = data.chats
    .filter((entry) => entry && typeof entry === "object")
    .map((entry, index) => ({
      id: String(entry.id || `msg_recovered_${index}`),
      groupId: String(entry.groupId || ""),
      userId: String(entry.userId || ""),
      content: String(entry.content || ""),
      type: entry.type === "announcement" ? "announcement" : "message",
      pinned: Boolean(entry.pinned),
      createdAt: asIsoTimestamp(entry.createdAt),
    }));

  data.notifications = data.notifications
    .filter((entry) => entry && typeof entry === "object")
    .map((entry, index) => ({
      id: String(entry.id || `note_recovered_${index}`),
      userId: String(entry.userId || ""),
      title: String(entry.title || ""),
      body: String(entry.body || ""),
      type: String(entry.type || "general"),
      dedupeKey: String(entry.dedupeKey || ""),
      read: Boolean(entry.read),
      createdAt: asIsoTimestamp(entry.createdAt),
    }));

  data.auditLogs = data.auditLogs
    .filter((entry) => entry && typeof entry === "object")
    .map((entry, index) => ({
      id: String(entry.id || `audit_recovered_${index}`),
      actorId: String(entry.actorId || "system"),
      action: String(entry.action || "UNKNOWN"),
      targetType: String(entry.targetType || "unknown"),
      targetId: String(entry.targetId || "unknown"),
      metadata: entry.metadata && typeof entry.metadata === "object" ? entry.metadata : {},
      timestamp: asIsoTimestamp(entry.timestamp),
      previousHash: String(entry.previousHash || "GENESIS"),
      entryHash: String(entry.entryHash || hashValue(`recovered:${index}:${Date.now()}`)),
    }));

  data.disputes = data.disputes
    .filter((entry) => entry && typeof entry === "object")
    .map((entry, index) => ({
      id: String(entry.id || `dispute_recovered_${index}`),
      groupId: String(entry.groupId || ""),
      reporterId: String(entry.reporterId || ""),
      summary: String(entry.summary || ""),
      status: entry.status === "resolved" ? "resolved" : "open",
      createdAt: asIsoTimestamp(entry.createdAt),
      resolvedAt: entry.resolvedAt ? asIsoTimestamp(entry.resolvedAt) : null,
      resolution: String(entry.resolution || ""),
    }));

  data.fraudFlags = data.fraudFlags
    .filter((entry) => entry && typeof entry === "object")
    .map((entry, index) => ({
      id: String(entry.id || `flag_recovered_${index}`),
      targetType: ["user", "group", "transaction"].includes(entry.targetType)
        ? entry.targetType
        : "transaction",
      targetId: String(entry.targetId || ""),
      reason: String(entry.reason || ""),
      createdBy: String(entry.createdBy || "system"),
      createdAt: asIsoTimestamp(entry.createdAt),
    }));

  data.authControls.loginAttempts = data.authControls.loginAttempts || {};

  return data;
}

function normalizeStringArray(value) {
  if (!Array.isArray(value)) {
    return [];
  }
  return value
    .map((item) => String(item || "").trim())
    .filter((item) => item.length > 0);
}

function asFiniteNumber(value, fallback = 0) {
  const number = Number(value);
  return Number.isFinite(number) ? number : fallback;
}

function asIsoTimestamp(value) {
  const date = value ? new Date(value) : new Date();
  if (Number.isNaN(date.getTime())) {
    return new Date().toISOString();
  }
  return date.toISOString();
}

function asDateInput(value) {
  const date = value ? new Date(value) : new Date();
  if (Number.isNaN(date.getTime())) {
    return new Date().toISOString().slice(0, 10);
  }
  return date.toISOString().slice(0, 10);
}

function createSeedData() {
  const now = new Date();
  const start = new Date(now.getFullYear(), now.getMonth(), 5);
  const startDate = start.toISOString().slice(0, 10);

  const adminSalt = uid("salt");
  const leaderSalt = uid("salt");
  const memberSalt = uid("salt");
  const pendingSalt = uid("salt");

  const admin = {
    id: "usr_admin",
    fullName: "Platform Admin",
    email: "admin@susukonnect.app",
    phone: "+15550000001",
    role: "admin",
    salt: adminSalt,
    passwordHash: hashPassword("Admin@2026", adminSalt),
    acceptedTerms: true,
    verifiedBadge: true,
    biometricEnabled: false,
    mfaEnabled: true,
    status: "active",
    knownDevices: [],
    paymentMethods: [],
    kyc: {
      status: "verified",
      idType: "Passport",
      idNumberToken: tokenize("admin-id"),
      dob: "1990-01-01",
      selfieToken: tokenize("admin-selfie"),
      address: tokenize("admin-address"),
      submittedAt: now.toISOString(),
    },
    metrics: { paidContributions: 0, completedGroups: 0, internalTrustScore: 82 },
    createdAt: now.toISOString(),
    lastLoginAt: null,
  };

  const leader = {
    id: "usr_leader",
    fullName: "Aisha Leader",
    email: "leader@susukonnect.app",
    phone: "+15550000002",
    role: "leader",
    salt: leaderSalt,
    passwordHash: hashPassword("Leader@2026", leaderSalt),
    acceptedTerms: true,
    verifiedBadge: true,
    biometricEnabled: true,
    mfaEnabled: true,
    status: "active",
    knownDevices: [],
    paymentMethods: [
      {
        id: "pm_leader_main",
        type: "bank",
        label: "Primary ACH",
        last4: "1008",
        token: tokenize("leader-bank-1008"),
        autoDebit: true,
        createdAt: now.toISOString(),
      },
    ],
    kyc: {
      status: "verified",
      idType: "Driver's License",
      idNumberToken: tokenize("leader-id"),
      dob: "1993-03-20",
      selfieToken: tokenize("leader-selfie"),
      address: tokenize("leader-address"),
      submittedAt: now.toISOString(),
    },
    metrics: { paidContributions: 4, completedGroups: 1, internalTrustScore: 88 },
    createdAt: now.toISOString(),
    lastLoginAt: null,
  };

  const member = {
    id: "usr_member",
    fullName: "Samuel Member",
    email: "member@susukonnect.app",
    phone: "+15550000003",
    role: "member",
    salt: memberSalt,
    passwordHash: hashPassword("Member@2026", memberSalt),
    acceptedTerms: true,
    verifiedBadge: true,
    biometricEnabled: false,
    mfaEnabled: true,
    status: "active",
    knownDevices: [],
    paymentMethods: [
      {
        id: "pm_member_debit",
        type: "debit",
        label: "Family debit card",
        last4: "4455",
        token: tokenize("member-debit-4455"),
        autoDebit: false,
        createdAt: now.toISOString(),
      },
    ],
    kyc: {
      status: "verified",
      idType: "Passport",
      idNumberToken: tokenize("member-id"),
      dob: "1995-07-11",
      selfieToken: tokenize("member-selfie"),
      address: tokenize("member-address"),
      submittedAt: now.toISOString(),
    },
    metrics: { paidContributions: 3, completedGroups: 1, internalTrustScore: 79 },
    createdAt: now.toISOString(),
    lastLoginAt: null,
  };

  const pendingUser = {
    id: "usr_pending",
    fullName: "New Applicant",
    email: "applicant@susukonnect.app",
    phone: "+15550000004",
    role: "member",
    salt: pendingSalt,
    passwordHash: hashPassword("Member@2026", pendingSalt),
    acceptedTerms: true,
    verifiedBadge: false,
    biometricEnabled: false,
    mfaEnabled: true,
    status: "active",
    knownDevices: [],
    paymentMethods: [],
    kyc: {
      status: "pending",
      idType: "National ID",
      idNumberToken: tokenize("pending-id"),
      dob: "1999-10-10",
      selfieToken: tokenize("pending-selfie"),
      address: tokenize("pending-address"),
      submittedAt: now.toISOString(),
    },
    metrics: { paidContributions: 0, completedGroups: 0, internalTrustScore: 52 },
    createdAt: now.toISOString(),
    lastLoginAt: null,
  };

  const fixedGroup = {
    id: "grp_fixed_001",
    inviteCode: "JOINFIXED01",
    name: "Diaspora Family Circle",
    description: "Monthly fixed-rotation savings circle for tuition and emergency needs.",
    communityType: "West African Diaspora",
    location: "New York",
    startDate,
    contributionAmount: 200,
    currency: "USD",
    totalMembers: 5,
    payoutFrequency: "monthly",
    payoutOrderLogic: "fixed",
    gracePeriodDays: 3,
    requiresLeaderApproval: true,
    rules: "Contributions due by the 5th of each month. Grace period is 3 days.",
    leaderId: leader.id,
    memberIds: [leader.id, member.id],
    joinRequests: [pendingUser.id],
    payoutOrder: [leader.id, member.id],
    cycle: 1,
    status: "active",
    chatArchived: false,
    createdAt: now.toISOString(),
  };

  const votingGroup = {
    id: "grp_vote_001",
    inviteCode: "JOINVOTE01",
    name: "Community Growth Pot",
    description: "Voting-based payout order for small business support.",
    communityType: "Caribbean Entrepreneurs",
    location: "Toronto",
    startDate,
    contributionAmount: 150,
    currency: "USD",
    totalMembers: 4,
    payoutFrequency: "monthly",
    payoutOrderLogic: "voting",
    gracePeriodDays: 4,
    requiresLeaderApproval: false,
    rules: "Each member submits one vote every cycle.",
    leaderId: leader.id,
    memberIds: [leader.id, member.id],
    joinRequests: [],
    payoutOrder: [leader.id, member.id],
    cycle: 1,
    status: "active",
    chatArchived: false,
    createdAt: now.toISOString(),
  };

  const priorityGroup = {
    id: "grp_priority_001",
    inviteCode: "JOINPRIO01",
    name: "Emergency Shield Circle",
    description: "Priority payout reasons support urgent medical and rent situations.",
    communityType: "General",
    location: "London",
    startDate,
    contributionAmount: 180,
    currency: "GBP",
    totalMembers: 3,
    payoutFrequency: "monthly",
    payoutOrderLogic: "priority",
    gracePeriodDays: 2,
    requiresLeaderApproval: true,
    rules: "Priority reasons are scored and visible to all members.",
    leaderId: leader.id,
    memberIds: [leader.id, member.id],
    joinRequests: [],
    payoutOrder: [member.id, leader.id],
    cycle: 1,
    status: "active",
    chatArchived: false,
    createdAt: now.toISOString(),
  };

  const contributionDueIso = new Date(start).toISOString();

  const contributions = [
    {
      id: "ctr_fix_leader",
      groupId: fixedGroup.id,
      cycle: 1,
      userId: leader.id,
      amount: 200,
      dueDate: contributionDueIso,
      status: "paid",
      methodId: "pm_leader_main",
      methodType: "bank",
      autoDebit: true,
      paidAt: new Date(now.getTime() - 2 * 24 * 60 * 60 * 1000).toISOString(),
      reminderSentAt: null,
      createdAt: now.toISOString(),
    },
    {
      id: "ctr_fix_member",
      groupId: fixedGroup.id,
      cycle: 1,
      userId: member.id,
      amount: 200,
      dueDate: contributionDueIso,
      status: "pending",
      methodId: "",
      methodType: "",
      autoDebit: false,
      paidAt: null,
      reminderSentAt: null,
      createdAt: now.toISOString(),
    },
    {
      id: "ctr_vote_leader",
      groupId: votingGroup.id,
      cycle: 1,
      userId: leader.id,
      amount: 150,
      dueDate: contributionDueIso,
      status: "paid",
      methodId: "pm_leader_main",
      methodType: "bank",
      autoDebit: true,
      paidAt: new Date(now.getTime() - 1 * 24 * 60 * 60 * 1000).toISOString(),
      reminderSentAt: null,
      createdAt: now.toISOString(),
    },
    {
      id: "ctr_vote_member",
      groupId: votingGroup.id,
      cycle: 1,
      userId: member.id,
      amount: 150,
      dueDate: contributionDueIso,
      status: "paid",
      methodId: "pm_member_debit",
      methodType: "debit",
      autoDebit: false,
      paidAt: new Date(now.getTime() - 1 * 24 * 60 * 60 * 1000).toISOString(),
      reminderSentAt: null,
      createdAt: now.toISOString(),
    },
    {
      id: "ctr_prio_leader",
      groupId: priorityGroup.id,
      cycle: 1,
      userId: leader.id,
      amount: 180,
      dueDate: contributionDueIso,
      status: "paid",
      methodId: "pm_leader_main",
      methodType: "bank",
      autoDebit: true,
      paidAt: new Date(now.getTime() - 12 * 60 * 60 * 1000).toISOString(),
      reminderSentAt: null,
      createdAt: now.toISOString(),
    },
    {
      id: "ctr_prio_member",
      groupId: priorityGroup.id,
      cycle: 1,
      userId: member.id,
      amount: 180,
      dueDate: contributionDueIso,
      status: "paid",
      methodId: "pm_member_debit",
      methodType: "debit",
      autoDebit: false,
      paidAt: new Date(now.getTime() - 10 * 60 * 60 * 1000).toISOString(),
      reminderSentAt: null,
      createdAt: now.toISOString(),
    },
  ];

  const payouts = [
    {
      id: "pay_prio_001",
      groupId: priorityGroup.id,
      cycle: 1,
      recipientId: member.id,
      amount: 360,
      currency: "GBP",
      reason: "Medical procedure",
      customReason: "",
      status: "requested",
      requestedAt: new Date(now.getTime() - 8 * 60 * 60 * 1000).toISOString(),
      leaderApprovedBy: leader.id,
      adminApprovedBy: null,
      recipientMfaConfirmed: false,
      releasedAt: null,
      platformFee: 0,
      netAmount: 0,
    },
  ];

  const payoutVotes = [
    {
      id: "vote_seed_001",
      groupId: votingGroup.id,
      cycle: 1,
      voterId: leader.id,
      candidateId: member.id,
      note: "Business expansion need",
      createdAt: now.toISOString(),
    },
  ];

  const priorityClaims = [
    {
      id: "claim_seed_001",
      groupId: priorityGroup.id,
      cycle: 1,
      userId: member.id,
      reason: "Medical procedure",
      customReason: "Surgery co-pay",
      weight: PRIORITY_WEIGHTS["Medical procedure"],
      createdAt: now.toISOString(),
    },
  ];

  const chats = [
    {
      id: "msg_seed_001",
      groupId: fixedGroup.id,
      userId: leader.id,
      content: "Welcome to the circle. Contributions are due by the 5th each month.",
      type: "announcement",
      pinned: true,
      createdAt: now.toISOString(),
    },
    {
      id: "msg_seed_002",
      groupId: fixedGroup.id,
      userId: member.id,
      content: "Thanks! I will complete my contribution before grace deadline.",
      type: "message",
      pinned: false,
      createdAt: now.toISOString(),
    },
  ];

  const notifications = [
    {
      id: "note_seed_001",
      userId: member.id,
      title: "Contribution reminder",
      body: "Your contribution for Diaspora Family Circle is pending.",
      type: "reminder",
      dedupeKey: "seed-reminder-member",
      read: false,
      createdAt: now.toISOString(),
    },
    {
      id: "note_seed_002",
      userId: admin.id,
      title: "KYC review pending",
      body: "New Applicant is awaiting verification.",
      type: "compliance",
      dedupeKey: "seed-kyc-pending",
      read: false,
      createdAt: now.toISOString(),
    },
  ];

  const auditLogs = [];
  const seed = {
    users: [admin, leader, member, pendingUser],
    groups: [fixedGroup, votingGroup, priorityGroup],
    contributions,
    payouts,
    payoutVotes,
    priorityClaims,
    chats,
    notifications,
    auditLogs,
    disputes: [],
    fraudFlags: [],
    authControls: { loginAttempts: {} },
  };

  const payloads = [
    {
      actorId: admin.id,
      action: "SEED_PLATFORM_READY",
      targetType: "system",
      targetId: "seed",
      metadata: {},
    },
  ];
  payloads.forEach((payload) => {
    const previousHash =
      seed.auditLogs.length > 0 ? seed.auditLogs[seed.auditLogs.length - 1].entryHash : "GENESIS";
    const timestamp = now.toISOString();
    const message = `${previousHash}|${timestamp}|${payload.actorId}|${payload.action}|${payload.targetType}|${payload.targetId}|${JSON.stringify(payload.metadata)}`;
    const entryHash = hashValue(message);
    seed.auditLogs.push({
      id: uid("audit"),
      actorId: payload.actorId,
      action: payload.action,
      targetType: payload.targetType,
      targetId: payload.targetId,
      metadata: payload.metadata,
      timestamp,
      previousHash,
      entryHash,
    });
  });

  return seed;
}
