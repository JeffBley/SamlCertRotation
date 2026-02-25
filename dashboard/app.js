// Configuration
// Leave empty for same-origin (SWA linked backend), set for standalone API testing.
const API_BASE_URL = ''; // Leave empty for same-origin, or set to your Function App URL

// Store apps data for filtering
let allApps = [];
let allAuditEntries = [];
let createCertDaysThreshold = 60;
let activateCertDaysThreshold = 30;
let currentUserRoles = [];
let currentUserUpn = '';
let sessionTimeoutMinutes = 0;
let idleTimer = null;
let countdownTimer = null;
let countdownSeconds = 120;

// Cache flags — set to true after first successful load; cleared on force-refresh
const _cache = {
    data: false,        // Overview / Applications
    myApps: false,      // My SAML Apps
    myStaleCerts: false, // My Stale Certs
    cleanup: false,     // Certificate Clean-up
    reports: false,     // Reports
    audit: false,       // Audit Log
    policy: false,      // Policy Settings
    settings: false,    // Settings
};

// Invalidate all tab caches (call before mutation-triggered reloads)
function invalidateAllCaches() {
    for (const key in _cache) _cache[key] = false;
}
const ADMIN_APP_ROLE_VALUE = 'SamlCertRotation.Admin';
const READER_APP_ROLE_VALUE = 'SamlCertRotation.Reader';
const SPONSOR_APP_ROLE_VALUE = 'SamlCertRotation.Sponsor';

// Current action for confirmation modal
let pendingAction = null;

// Column visibility state (keys match checkbox values)
const visibleColumns = {
    application: true,
    applicationId: false,
    sponsor: true,
    autoRotate: true,
    certExpiry: false,
    daysRemaining: true,
    status: true,
    policyType: false,
    createCertDays: false,
    activateCertDays: false
};

// My Apps column visibility state
const myAppsVisibleColumns = {
    application: true,
    applicationId: false,
    autoRotate: true,
    certExpiry: false,
    daysRemaining: true,
    status: true,
    policyType: false,
    createCertDays: false,
    activateCertDays: false,
    deeplink: true
};

// Audit column visibility state
const auditVisibleColumns = {
    time: true,
    application: true,
    applicationId: false,
    initiatedBy: true,
    action: true,
    result: true,
    details: true
};

// Edit policy modal state
let editPolicyAppId = null;
let editPolicyAppName = null;

// HTML escape function to prevent XSS
function escapeHtml(text) {
    if (text == null) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// Debounce utility — delays fn execution until pause of `delay` ms
function debounce(fn, delay = 250) {
    let timer;
    return function (...args) {
        clearTimeout(timer);
        timer = setTimeout(() => fn.apply(this, args), delay);
    };
}

function toSafeClassToken(value, fallback = 'unknown') {
    const token = String(value ?? '')
        .toLowerCase()
        .replace(/[^a-z0-9_-]/g, '');
    return token || fallback;
}

function toDomIdToken(value, fallback = 'item') {
    const token = String(value ?? '').replace(/[^A-Za-z0-9_-]/g, '_');
    return token || fallback;
}

function toJsStringLiteral(value) {
    return JSON.stringify(String(value ?? ''));
}

// Authentication and role helpers
// End app session (clears SWA auth cookie) and redirect to login
function endAppSession() {
    stopIdleTracking();
    window.location.href = '/.auth/logout?post_logout_redirect_uri=/';
}

// Sign Out button - same as app session termination
function signOut() {
    endAppSession();
}

// Session idle timeout tracking
function resetIdleTimer() {
    if (sessionTimeoutMinutes <= 0) return;
    clearTimeout(idleTimer);
    idleTimer = setTimeout(showTimeoutPrompt, sessionTimeoutMinutes * 60 * 1000);
}

function startIdleTracking() {
    if (sessionTimeoutMinutes <= 0) return;
    const events = ['mousedown', 'mousemove', 'keydown', 'scroll', 'touchstart', 'click'];
    events.forEach(evt => document.addEventListener(evt, resetIdleTimer, { passive: true }));
    resetIdleTimer();
}

function stopIdleTracking() {
    clearTimeout(idleTimer);
    clearInterval(countdownTimer);
    const events = ['mousedown', 'mousemove', 'keydown', 'scroll', 'touchstart', 'click'];
    events.forEach(evt => document.removeEventListener(evt, resetIdleTimer));
}

function showTimeoutPrompt() {
    countdownSeconds = 120;
    updateCountdownDisplay();
    document.getElementById('sessionTimeoutModal').classList.add('show');
    countdownTimer = setInterval(() => {
        countdownSeconds--;
        updateCountdownDisplay();
        if (countdownSeconds <= 0) {
            clearInterval(countdownTimer);
            endAppSession();
        }
    }, 1000);
}

function updateCountdownDisplay() {
    const mins = Math.floor(countdownSeconds / 60);
    const secs = countdownSeconds % 60;
    document.getElementById('timeout-countdown').textContent =
        `${mins}:${secs.toString().padStart(2, '0')}`;
}

function renewSession() {
    clearInterval(countdownTimer);
    document.getElementById('sessionTimeoutModal').classList.remove('show');
    resetIdleTimer();
}

function isAdminUser() {
    return currentUserRoles.includes('admin');
}

function isReaderUser() {
    return currentUserRoles.includes('reader');
}

function isSponsorUser() {
    return currentUserRoles.includes('sponsor');
}

function isSponsorOnly() {
    return isSponsorUser() && !currentUserRoles.includes('admin') && !currentUserRoles.includes('reader');
}

async function loadCurrentUserRoles() {
    try {
        const response = await fetch('/.auth/me', { credentials: 'include' });
        if (!response.ok) {
            return;
        }

        const authInfo = await response.json();
        const principal = Array.isArray(authInfo)
            ? (authInfo.length > 0 ? authInfo[0]?.clientPrincipal : null)
            : authInfo?.clientPrincipal ?? null;

        const roles = principal?.userRoles;
        const normalizedRoles = Array.isArray(roles)
            ? roles.map(role => String(role).toLowerCase())
            : [];

        const claims = Array.isArray(principal?.claims) ? principal.claims : [];
        const claimRoleValues = claims
            .filter(claim => {
                const claimType = String(claim?.typ || claim?.type || '').toLowerCase();
                return claimType === 'roles' || claimType === 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role';
            })
            .map(claim => String(claim?.val || claim?.value || '').trim())
            .filter(value => value.length > 0);

        if (claimRoleValues.some(value => value.toLowerCase() === ADMIN_APP_ROLE_VALUE.toLowerCase())) {
            normalizedRoles.push('admin', 'reader');
        } else if (claimRoleValues.some(value => value.toLowerCase() === READER_APP_ROLE_VALUE.toLowerCase())) {
            normalizedRoles.push('reader');
        }
        if (claimRoleValues.some(value => value.toLowerCase() === SPONSOR_APP_ROLE_VALUE.toLowerCase())) {
            normalizedRoles.push('sponsor');
        }

        currentUserRoles = [...new Set(normalizedRoles)];
        currentUserUpn = principal?.userDetails || '';
    } catch {
        currentUserRoles = [];
        currentUserUpn = '';
    }
}

function hasDashboardAccess() {
    return currentUserRoles.includes('admin') || currentUserRoles.includes('reader') || currentUserRoles.includes('sponsor');
}

function applyRoleBasedAccess() {
    // Display UPN
    const upnEl = document.getElementById('user-upn');
    if (upnEl) upnEl.textContent = currentUserUpn;

    const readOnly = !isAdminUser();
    const sponsorOnly = isSponsorOnly();
    const isSponsor = isSponsorUser();
    const isAdminOrReader = isAdminUser() || isReaderUser();

    const adminTabsRow = document.getElementById('admin-tabs');
    const sponsorTabsRow = document.getElementById('sponsor-tabs');
    const tabsWrapper = document.getElementById('tabs-wrapper');

    // Show/hide tab rows based on roles
    if (adminTabsRow) adminTabsRow.style.display = isAdminOrReader ? 'flex' : 'none';
    if (sponsorTabsRow) sponsorTabsRow.style.display = isSponsor ? 'flex' : 'none';

    // For sponsor-only users, hide admin row and auto-select My SAML Apps
    if (sponsorOnly) {
        // Remove active from any admin tabs/content
        document.querySelectorAll('#admin-tabs .tab').forEach(t => t.classList.remove('active'));
        const adminContentTabs = ['overview', 'applications', 'cleanup', 'policy', 'settings', 'audit', 'reports', 'testing'];
        adminContentTabs.forEach(tabName => {
            const tabContent = document.getElementById(`tab-${tabName}`);
            if (tabContent) tabContent.classList.remove('active');
        });
        // Activate myapps tab
        const myAppsTab = sponsorTabsRow?.querySelector('.tab[data-tab="myapps"]');
        if (myAppsTab) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            myAppsTab.classList.add('active');
        }
        const myAppsContent = document.getElementById('tab-myapps');
        if (myAppsContent) myAppsContent.classList.add('active');
    }

    // Reveal tabs now that role-based visibility is applied (prevents flash)
    if (tabsWrapper) tabsWrapper.style.visibility = 'visible';

    if (sponsorOnly) {
        loadMyApps();
        return;
    }

    // Run buttons
    const reportBtn = document.getElementById('btn-report-only');
    const prodBtn = document.getElementById('btn-prod-run');
    if (reportBtn) { reportBtn.disabled = readOnly; reportBtn.style.opacity = readOnly ? '0.5' : '1'; reportBtn.style.cursor = readOnly ? 'not-allowed' : 'pointer'; }
    if (prodBtn) { prodBtn.disabled = readOnly; prodBtn.style.opacity = readOnly ? '0.5' : '1'; prodBtn.style.cursor = readOnly ? 'not-allowed' : 'pointer'; }

    // Policy tab inputs and Save Policy button
    document.getElementById('createDays').disabled = readOnly;
    document.getElementById('activateDays').disabled = readOnly;
    document.querySelectorAll('#tab-policy .btn-primary').forEach(btn => {
        btn.disabled = readOnly; btn.style.opacity = readOnly ? '0.5' : '1'; btn.style.cursor = readOnly ? 'not-allowed' : 'pointer';
    });

    // Settings tab - all inputs, selects, textareas, and Save Settings button
    document.querySelectorAll('#tab-settings input:not([readonly]), #tab-settings select, #tab-settings textarea').forEach(el => {
        el.disabled = readOnly;
    });
    document.querySelectorAll('#tab-settings .btn-primary').forEach(btn => {
        btn.disabled = readOnly; btn.style.opacity = readOnly ? '0.5' : '1'; btn.style.cursor = readOnly ? 'not-allowed' : 'pointer';
    });
}

function enforceRoleAccessOrRedirect() {
    if (!hasDashboardAccess()) {
        window.location.href = '/unauthorized.html';
        return false;
    }

    return true;
}

// Dashboard filter controls
// Close all dropdown menus
function closeAllDropdowns() {
    document.querySelectorAll('.dropdown-menu.show').forEach(menu => {
        menu.classList.remove('show');
    });
}

function toggleAuditActionFilterDropdown(event) {
    event.stopPropagation();
    const dropdown = document.getElementById('audit-action-filter-dropdown');
    const wasOpen = dropdown.classList.contains('show');
    closeAllDropdowns();
    if (!wasOpen) {
        dropdown.classList.add('show');
    }
}

function getSelectedAuditActionFilters() {
    return Array.from(document.querySelectorAll('.audit-action-filter-option-input:checked'))
        .map(input => input.value);
}

function updateAuditActionFilterLabel() {
    const selectedActions = getSelectedAuditActionFilters();
    const label = document.getElementById('audit-action-filter-label');

    if (!label) return;

    if (selectedActions.length === 0) {
        label.textContent = 'Actions';
        return;
    }

    if (selectedActions.length <= 2) {
        label.textContent = selectedActions.join(', ');
        return;
    }

    label.textContent = `${selectedActions.length} selected`;
}

function onAuditActionFilterChanged() {
    updateAuditActionFilterLabel();
    applyAuditFilters();
}

function toggleAppAutoRotateFilterDropdown(event) {
    event.stopPropagation();
    const dropdown = document.getElementById('app-auto-rotate-filter-dropdown');
    const wasOpen = dropdown.classList.contains('show');
    closeAllDropdowns();
    if (!wasOpen) {
        dropdown.classList.add('show');
    }
}

function toggleAppStatusFilterDropdown(event) {
    event.stopPropagation();
    const dropdown = document.getElementById('app-status-filter-dropdown');
    const wasOpen = dropdown.classList.contains('show');
    closeAllDropdowns();
    if (!wasOpen) {
        dropdown.classList.add('show');
    }
}

function toggleAppPolicyTypeFilterDropdown(event) {
    event.stopPropagation();
    const dropdown = document.getElementById('app-policy-type-filter-dropdown');
    const wasOpen = dropdown.classList.contains('show');
    closeAllDropdowns();
    if (!wasOpen) {
        dropdown.classList.add('show');
    }
}

function toggleAuditFilterPanel() {
    const panel = document.getElementById('audit-filter-panel');
    const btn = document.getElementById('btn-toggle-audit-filters');
    if (panel.style.display === 'none') {
        panel.style.display = 'block';
        btn.textContent = 'Hide Filters';
    } else {
        panel.style.display = 'none';
        btn.textContent = 'Add Filter';
    }
}

function toggleAppFilterPanel() {
    const panel = document.getElementById('app-filter-panel');
    const btn = document.getElementById('btn-toggle-app-filters');
    if (panel.style.display === 'none') {
        panel.style.display = 'block';
        btn.textContent = 'Hide Filters';
    } else {
        panel.style.display = 'none';
        btn.textContent = 'Add Filters';
    }
}

function clearAppFilters() {
    document.querySelectorAll('.app-auto-rotate-filter-option-input').forEach(input => { input.checked = false; });
    document.querySelectorAll('.app-status-filter-option-input').forEach(input => { input.checked = false; });
    document.querySelectorAll('.app-policy-type-filter-option-input').forEach(input => { input.checked = false; });
    document.getElementById('app-sponsor-search').value = '';
    updateAppAutoRotateFilterLabel();
    updateAppStatusFilterLabel();
    updateAppPolicyTypeFilterLabel();
    document.getElementById('app-filter-panel').style.display = 'none';
    document.getElementById('btn-toggle-app-filters').textContent = 'Add Filters';
    applyFilters();
}

function getSelectedAppAutoRotateFilters() {
    return Array.from(document.querySelectorAll('.app-auto-rotate-filter-option-input:checked'))
        .map(input => input.value);
}

function getSelectedAppStatusFilters() {
    return Array.from(document.querySelectorAll('.app-status-filter-option-input:checked'))
        .map(input => input.value);
}

function getSelectedAppPolicyTypeFilters() {
    return Array.from(document.querySelectorAll('.app-policy-type-filter-option-input:checked'))
        .map(input => input.value);
}

function updateAppAutoRotateFilterLabel() {
    const selected = getSelectedAppAutoRotateFilters();
    const label = document.getElementById('app-auto-rotate-filter-label');
    if (!label) return;

    if (selected.length === 0) {
        label.textContent = 'Auto-Rotate';
    } else if (selected.length <= 2) {
        label.textContent = selected.map(value => {
            if (value === 'notset') return 'Not Set';
            if (value === 'notify') return 'Notify';
            return value.charAt(0).toUpperCase() + value.slice(1);
        }).join(', ');
    } else {
        label.textContent = `${selected.length} selected`;
    }
}

function updateAppStatusFilterLabel() {
    const selected = getSelectedAppStatusFilters();
    const label = document.getElementById('app-status-filter-label');
    if (!label) return;

    if (selected.length === 0) {
        label.textContent = 'Status';
    } else if (selected.length <= 2) {
        label.textContent = selected.map(value => value.toUpperCase() === 'OK' ? 'OK' : value.charAt(0).toUpperCase() + value.slice(1)).join(', ');
    } else {
        label.textContent = `${selected.length} selected`;
    }
}

function updateAppPolicyTypeFilterLabel() {
    const selected = getSelectedAppPolicyTypeFilters();
    const label = document.getElementById('app-policy-type-filter-label');
    if (!label) return;

    if (selected.length === 0) {
        label.textContent = 'Policy Type';
    } else if (selected.length <= 2) {
        label.textContent = selected.join(', ');
    } else {
        label.textContent = `${selected.length} selected`;
    }
}

function onAppFilterChanged() {
    updateAppAutoRotateFilterLabel();
    updateAppStatusFilterLabel();
    updateAppPolicyTypeFilterLabel();
    applyFilters();
}

function getComputedAppStatus(app) {
    const daysUntilExpiry = typeof app.daysUntilExpiry === 'number' ? app.daysUntilExpiry : null;

    if (daysUntilExpiry === null) {
        return 'ok';
    }

    if (daysUntilExpiry < 0) {
        return 'expired';
    }

    if (daysUntilExpiry <= activateCertDaysThreshold) {
        return 'critical';
    }

    if (daysUntilExpiry <= createCertDaysThreshold) {
        return 'warning';
    }

    return 'ok';
}

function getFilteredApps() {
    const searchTerm = (document.getElementById('app-search')?.value || '').trim().toLowerCase();
    const sponsorTerm = (document.getElementById('app-sponsor-search')?.value || '').trim().toLowerCase();
    const selectedAutoRotateFilters = getSelectedAppAutoRotateFilters();
    const selectedStatusFilters = getSelectedAppStatusFilters();
    const selectedPolicyTypeFilters = getSelectedAppPolicyTypeFilters();

    return allApps.filter(app => {
        const status = (app.autoRotateStatus || '').toLowerCase();
        const autoRotateValue = status === 'on'
            ? 'on'
            : status === 'off'
                ? 'off'
                : status === 'notify'
                    ? 'notify'
                    : 'notset';
        const computedStatus = getComputedAppStatus(app);

        const autoRotateMatch = selectedAutoRotateFilters.length === 0 || selectedAutoRotateFilters.includes(autoRotateValue);
        const statusMatch = selectedStatusFilters.length === 0 || selectedStatusFilters.includes(computedStatus);
        const policyTypeMatch = selectedPolicyTypeFilters.length === 0 || selectedPolicyTypeFilters.includes(app.policyType || 'Global');
        const nameMatch = !searchTerm || (app.displayName || '').toLowerCase().includes(searchTerm);
        const sponsorMatch = !sponsorTerm || (app.sponsor || '').toLowerCase().includes(sponsorTerm);

        return autoRotateMatch && statusMatch && policyTypeMatch && nameMatch && sponsorMatch;
    });
}

// Toggle actions menu for an app
function toggleActionsMenu(event, appId) {
    event.stopPropagation();
    const menu = document.getElementById(`actions-menu-${appId}`);
    const wasOpen = menu.classList.contains('show');
    closeAllDropdowns();
    if (!wasOpen) {
        menu.classList.add('show');
    }
}

// Close dropdowns when clicking outside
document.addEventListener('click', closeAllDropdowns);

// Create new SAML certificate for an app
async function createNewCert(appId, appName) {
    closeAllDropdowns();
    try {
        showLoading('Creating new certificate...');
        await apiCall(`applications/${appId}/certificate`, { method: 'POST' });
        showSuccess(`New certificate created for ${appName}`);
        invalidateAllCaches();
        await loadData();
        if (isSponsorUser()) loadMyApps();
    } catch (error) {
        showError(`Failed to create certificate: ${error.message}`);
    }
}

// Activate the newest certificate for an app
async function activateNewestCert(appId, appName) {
    closeAllDropdowns();
    try {
        showLoading('Activating newest certificate...');
        await apiCall(`applications/${appId}/certificate/activate`, { method: 'POST' });
        showSuccess(`Newest certificate activated for ${appName}`);
        invalidateAllCaches();
        await loadData();
        if (isSponsorUser()) loadMyApps();
    } catch (error) {
        showError(`Failed to activate certificate: ${error.message}`);
    }
}

// Sponsor-initiated certificate creation
async function sponsorCreateCert(appId, appName) {
    closeAllDropdowns();
    try {
        showLoading('Creating new certificate...');
        await apiCall(`sponsor/applications/${appId}/certificate`, { method: 'POST' });
        showSuccess(`New certificate created for ${appName}`);
        invalidateAllCaches();
        await loadMyApps();
    } catch (error) {
        showError(`Failed to create certificate: ${error.message}`);
    }
}

// Sponsor-initiated certificate activation
async function sponsorActivateCert(appId, appName) {
    closeAllDropdowns();
    try {
        showLoading('Activating newest certificate...');
        await apiCall(`sponsor/applications/${appId}/certificate/activate`, { method: 'POST' });
        showSuccess(`Newest certificate activated for ${appName}`);
        invalidateAllCaches();
        await loadMyApps();
    } catch (error) {
        showError(`Failed to activate certificate: ${error.message}`);
    }
}

// Sponsor-initiated policy edit — reuses the same edit policy modal
// Sets a flag so saveAppPolicy() knows to use the sponsor endpoint
let sponsorEditPolicyMode = false;
let sponsorEditPolicyState = { appId: null, appName: null };

async function sponsorEditPolicy(appId, appName) {
    closeAllDropdowns();
    sponsorEditPolicyMode = true;
    sponsorEditPolicyState = { appId, appName };
    // Reuse the editPolicy flow which opens the modal and wires up save via saveAppPolicy()
    await editPolicy(appId, appName);
}

// Sponsor-initiated sponsor edit — reuses the same edit sponsor modal
// Sets a flag so saveSponsorModal() knows to use the sponsor endpoint
let sponsorEditSponsorMode = false;
let sponsorEditSponsorState = { appId: null, appName: null };

function sponsorEditSponsor(appId, appName, currentSponsor) {
    closeAllDropdowns();
    sponsorEditSponsorMode = true;
    sponsorEditSponsorState = { appId, appName };
    // Reuse the editSponsor flow which opens the modal and wires up save via saveSponsorModal()
    editSponsor(appId, appName, currentSponsor);
}

// Edit sponsor tag for an app — opens modal with per-sponsor input rows
let editSponsorState = { appId: null, appName: null };

function editSponsor(appId, appName, currentSponsor) {
    closeAllDropdowns();
    editSponsorState = { appId, appName };

    document.getElementById('editSponsorTitle').textContent = `Edit Sponsors — ${appName}`;
    document.getElementById('editSponsorError').style.display = 'none';

    const container = document.getElementById('sponsorEmailRows');
    container.innerHTML = '';

    // Parse existing sponsors (semicolon-separated)
    const existing = (currentSponsor || '').split(';').map(e => e.trim()).filter(e => e.length > 0);
    if (existing.length === 0) existing.push(''); // start with one empty row

    existing.forEach(email => addSponsorRow(email));
    document.getElementById('editSponsorModal').classList.add('show');
}

function addSponsorRow(value) {
    const container = document.getElementById('sponsorEmailRows');
    const row = document.createElement('div');
    row.style.cssText = 'display:flex;gap:8px;align-items:center;margin-bottom:6px;';
    row.innerHTML = `
        <input type="email" placeholder="sponsor@example.com" value="${escapeHtml(value || '')}" 
               class="sponsor-email-input" 
               style="flex:1;padding:6px 10px;border:1px solid #d2d0ce;border-radius:4px;font-size:13px;">
        <button type="button" class="btn-remove-sponsor" title="Remove"
                style="background:none;border:none;color:#d13438;cursor:pointer;font-size:18px;padding:0 4px;line-height:1;">&#x2715;</button>
    `;
    row.querySelector('.btn-remove-sponsor').addEventListener('click', () => {
        row.remove();
        // Keep at least one row
        if (container.querySelectorAll('.sponsor-email-input').length === 0) {
            addSponsorRow('');
        }
    });
    container.appendChild(row);
    // Focus the new input if it's empty
    const input = row.querySelector('input');
    if (!value) input.focus();
}

async function saveSponsorModal() {
    const container = document.getElementById('sponsorEmailRows');
    const inputs = container.querySelectorAll('.sponsor-email-input');
    const emails = Array.from(inputs).map(i => i.value.trim()).filter(e => e.length > 0);

    const errorEl = document.getElementById('editSponsorError');

    if (emails.length === 0) {
        errorEl.textContent = 'At least one sponsor email is required.';
        errorEl.style.display = 'block';
        return;
    }

    const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const invalid = emails.filter(e => !emailPattern.test(e));
    if (invalid.length > 0) {
        errorEl.textContent = `Invalid email: ${invalid.join(', ')}`;
        errorEl.style.display = 'block';
        return;
    }

    errorEl.style.display = 'none';
    const sponsorEmail = emails.join(';');

    try {
        showLoading('Updating sponsor...');
        document.getElementById('editSponsorModal').classList.remove('show');

        const isSponsorMode = sponsorEditSponsorMode;
        const appId = isSponsorMode ? sponsorEditSponsorState.appId : editSponsorState.appId;
        const appName = isSponsorMode ? sponsorEditSponsorState.appName : editSponsorState.appName;
        const endpoint = isSponsorMode ? `sponsor/applications/${appId}/sponsor` : `applications/${appId}/sponsor`;

        await apiCall(endpoint, {
            method: 'PUT',
            body: JSON.stringify({ sponsorEmail })
        });
        showSuccess(`Sponsor updated for ${appName}`);
        invalidateAllCaches();

        if (isSponsorMode) {
            sponsorEditSponsorMode = false;
            sponsorEditSponsorState = { appId: null, appName: null };
            await loadMyApps();
        } else {
            await loadData();
            if (isSponsorUser()) loadMyApps();
        }
    } catch (error) {
        sponsorEditSponsorMode = false;
        showError(`Failed to update sponsor: ${error.message}`);
    }
}

async function resendReminderEmail(appId, appName) {
    closeAllDropdowns();
    try {
        showLoading('Sending reminder email...');
        const result = await apiCall(`applications/${appId}/resend-reminder`, { method: 'POST' });
        showSuccess(result?.message || `Reminder email sent for ${appName}`);
    } catch (error) {
        showError(`Failed to send reminder email: ${error.message}`);
    }
}

// Open the edit policy modal for an app
async function editPolicy(appId, appName) {
    closeAllDropdowns();
    editPolicyAppId = appId;
    editPolicyAppName = appName;
    document.getElementById('editPolicyTitle').textContent = `Edit Policy — ${appName}`;
    document.getElementById('editPolicyError').style.display = 'none';

    try {
        showLoading('Loading app policy...');
        const result = await apiCall(`policy/app/${appId}`);
        clearStatusBanner();

        if (result.isAppSpecific) {
            document.getElementById('editPolicyCreateDays').value = result.policy.createCertDaysBeforeExpiry ?? '';
            document.getElementById('editPolicyActivateDays').value = result.policy.activateCertDaysBeforeExpiry ?? '';
            const override = result.policy.createCertsForNotifyOverride;
            document.getElementById('editPolicyNotifyOverride').value = override === true ? 'enabled' : override === false ? 'disabled' : 'default';
        } else {
            // No app-specific policy — leave blank (will use global)
            document.getElementById('editPolicyCreateDays').value = '';
            document.getElementById('editPolicyActivateDays').value = '';
            document.getElementById('editPolicyNotifyOverride').value = 'default';
        }

        document.getElementById('editPolicyModal').classList.add('show');
    } catch (error) {
        showError(`Failed to load app policy: ${error.message}`);
    }
}

// Save the app-specific policy from the modal
async function saveAppPolicy() {
    const createDaysVal = document.getElementById('editPolicyCreateDays').value.trim();
    const activateDaysVal = document.getElementById('editPolicyActivateDays').value.trim();
    const errorEl = document.getElementById('editPolicyError');

    const createDays = createDaysVal === '' ? null : parseInt(createDaysVal, 10);
    const activateDays = activateDaysVal === '' ? null : parseInt(activateDaysVal, 10);

    if (createDays !== null && (isNaN(createDays) || createDays < 1 || createDays > 365)) {
        errorEl.textContent = 'Create cert days must be between 1 and 365, or blank for global default.';
        errorEl.style.display = 'block';
        return;
    }
    if (activateDays !== null && (isNaN(activateDays) || activateDays < 1 || activateDays > 365)) {
        errorEl.textContent = 'Activate cert days must be between 1 and 365, or blank for global default.';
        errorEl.style.display = 'block';
        return;
    }

    if (createDays !== null && activateDays !== null && activateDays >= createDays) {
        errorEl.textContent = 'Activate cert days must be less than Create cert days.';
        errorEl.style.display = 'block';
        return;
    }

    const notifyOverrideVal = document.getElementById('editPolicyNotifyOverride').value;
    const createCertsForNotifyOverride = notifyOverrideVal === 'enabled' ? true : notifyOverrideVal === 'disabled' ? false : null;

    try {
        showLoading('Saving app policy...');
        document.getElementById('editPolicyModal').classList.remove('show');

        const isSponsorMode = sponsorEditPolicyMode;
        const appId = isSponsorMode ? sponsorEditPolicyState.appId : editPolicyAppId;
        const appName = isSponsorMode ? sponsorEditPolicyState.appName : editPolicyAppName;
        const endpoint = isSponsorMode ? `sponsor/applications/${appId}/policy` : `policy/app/${appId}`;

        await apiCall(endpoint, {
            method: 'PUT',
            body: JSON.stringify({
                appDisplayName: appName,
                createCertDaysBeforeExpiry: createDays,
                activateCertDaysBeforeExpiry: activateDays,
                createCertsForNotifyOverride: createCertsForNotifyOverride
            })
        });
        showSuccess(`Policy updated for ${appName}`);
        invalidateAllCaches();

        if (isSponsorMode) {
            sponsorEditPolicyMode = false;
            sponsorEditPolicyState = { appId: null, appName: null };
            await loadMyApps();
        } else {
            await loadData();
            if (isSponsorUser()) loadMyApps();
        }
    } catch (error) {
        sponsorEditPolicyMode = false;
        showError(`Failed to update app policy: ${error.message}`);
    }
}

function closeEditPolicyModal() {
    document.getElementById('editPolicyModal').classList.remove('show');
    editPolicyAppId = null;
    editPolicyAppName = null;
    sponsorEditPolicyMode = false;
    sponsorEditPolicyState = { appId: null, appName: null };
}

// Update column visibility from checkboxes and re-render
function updateColumnVisibility() {
    document.querySelectorAll('.app-columns-filter-option-input').forEach(cb => {
        visibleColumns[cb.value] = cb.checked;
    });
    applyFilters();
}

// Close the confirmation modal
function closeModal() {
    document.getElementById('confirmModal').classList.remove('show');
    pendingAction = null;
    // Reset modal to defaults
    document.getElementById('modalTitle').textContent = 'Confirm Action';
    document.getElementById('confirmModalMessage').textContent = 'Are you sure you want to proceed?';
    document.getElementById('modalConfirmBtn').textContent = 'Confirm';
}

// Execute the pending action from the confirmation modal
async function confirmModalAction() {
    if (!pendingAction) return;
    
    // Save action before closing modal (which clears pendingAction)
    const action = pendingAction;
    document.getElementById('confirmModal').classList.remove('show');
    pendingAction = null;
    // Reset modal to defaults
    document.getElementById('modalTitle').textContent = 'Confirm Action';
    document.getElementById('confirmModalMessage').textContent = 'Are you sure you want to proceed?';
    document.getElementById('modalConfirmBtn').textContent = 'Confirm';
    
    if (action.type === 'triggerRotation') {
        try {
            const isReportOnly = action.mode === 'report-only';
            showLoading(isReportOnly ? 'Running report-only evaluation...' : 'Running production rotation...');

            const endpoint = isReportOnly
                ? 'rotation/trigger/report-only'
                : 'rotation/trigger/prod';

            const result = await apiCall(endpoint, { method: 'POST' });
            const skipped = typeof result.skipped === 'number'
                ? result.skipped
                : Math.max(0, (result.totalProcessed || 0) - (result.successful || 0) - (result.failed || 0));
            showSuccess(`${result.message}. Processed ${result.totalProcessed} apps. Success: ${result.successful}, Skipped: ${skipped}, Failed: ${result.failed}`);
            invalidateAllCaches();
            await loadData();
            // Refresh reports tab so the new run appears immediately
            loadReports();
        } catch (error) {
            showError(`Failed to run rotation: ${error.message}`);
        }
    }
}

function triggerReportOnlyRun() {
    pendingAction = { type: 'triggerRotation', mode: 'report-only' };
    document.getElementById('modalTitle').textContent = 'Run - Report-only';
    document.getElementById('confirmModalMessage').textContent =
        'Run an immediate report-only evaluation. No certificate changes will be made.';
    document.getElementById('modalConfirmBtn').textContent = 'Run';
    document.getElementById('confirmModal').classList.add('show');
}

function triggerProdRun() {
    pendingAction = { type: 'triggerRotation', mode: 'prod' };
    document.getElementById('modalTitle').textContent = 'Run - Prod';
    document.getElementById('confirmModalMessage').textContent =
        'Run immediate production automation. This may create or activate certificates.';
    document.getElementById('modalConfirmBtn').textContent = 'Run';
    document.getElementById('confirmModal').classList.add('show');
}

// Show loading message
function showLoading(message) {
    renderStatusBanner(message, {
        background: '#e3f2fd',
        color: '#1565c0'
    });
}

// Show success message
function showSuccess(message) {
    renderStatusBanner(message, {
        background: '#e8f5e9',
        color: '#2e7d32'
    });
    setTimeout(() => {
        document.getElementById('error-container').innerHTML = '';
    }, 5000);
}

function clearStatusBanner() {
    document.getElementById('error-container').innerHTML = '';
}

function renderStatusBanner(message, styles = {}) {
    const container = document.getElementById('error-container');
    container.innerHTML = '';

    const banner = document.createElement('div');
    banner.style.padding = '15px';
    banner.style.borderRadius = '6px';
    banner.style.background = styles.background || '#f3f2f1';
    banner.style.color = styles.color || '#323130';
    banner.textContent = message || '';

    container.appendChild(banner);
}

// Tab navigation
document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        tab.classList.add('active');
        document.getElementById(`tab-${tab.dataset.tab}`).classList.add('active');

        if (tab.dataset.tab === 'audit') {
            loadAuditLog(false);
        } else if (tab.dataset.tab === 'policy') {
            loadPolicy(false);
        } else if (tab.dataset.tab === 'settings') {
            loadSettings(false);
        } else if (tab.dataset.tab === 'cleanup') {
            loadCleanupData(false);
        } else if (tab.dataset.tab === 'testing') {
            loadTestEmailTemplates();
        } else if (tab.dataset.tab === 'reports') {
            loadReports(false);
        } else if (tab.dataset.tab === 'myapps') {
            loadMyApps(false);
        } else if (tab.dataset.tab === 'mystalecerts') {
            loadMyStaleCerts(false);
        }
    });
});

// API and state-loading helpers
// API helper
async function apiCall(endpoint, options = {}) {
    try {
        const method = (options.method || 'GET').toUpperCase();
        const isSponsorEndpoint = endpoint.startsWith('sponsor/') || endpoint.startsWith('dashboard/my-apps');
        if (method !== 'GET' && !isAdminUser() && !isSponsorEndpoint) {
            throw new Error('Admin role is required for this action.');
        }

        const response = await fetch(`${API_BASE_URL}/api/${endpoint}`, {
            ...options,
            credentials: 'include',
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            }
        });
        if (!response.ok) {
            let serverMessage = '';
            try {
                const errorBody = await response.json();
                serverMessage = errorBody.error || errorBody.message || '';
            } catch (_) { /* response body not JSON */ }
            throw new Error(serverMessage || `API error: ${response.status}`);
        }
        return await response.json();
    } catch (error) {
        showError(error.message);
        throw error;
    }
}

// Show error message
function showError(message) {
    const container = document.getElementById('error-container');
    container.innerHTML = '';

    const errorDiv = document.createElement('div');
    errorDiv.className = 'error';
    errorDiv.textContent = message || 'An error occurred';

    container.appendChild(errorDiv);
    setTimeout(() => {
        document.getElementById('error-container').innerHTML = '';
    }, 5000);
}

// Load dashboard data
async function loadData(force = true) {
    if (!force && _cache.data) { applyFilters(); return; }
    try {
        showLoading('Refreshing data...');
        const [stats, policy, settings] = await Promise.all([
            apiCall('dashboard/stats'),
            apiCall('policy').catch(() => null),
            apiCall('settings').catch(() => null)
        ]);

        if (policy) {
            createCertDaysThreshold = typeof policy.createCertDaysBeforeExpiry === 'number'
                ? policy.createCertDaysBeforeExpiry
                : createCertDaysThreshold;
            activateCertDaysThreshold = typeof policy.activateCertDaysBeforeExpiry === 'number'
                ? policy.activateCertDaysBeforeExpiry
                : activateCertDaysThreshold;
        }

        // Start session idle tracking
        if (settings && typeof settings.sessionTimeoutMinutes === 'number') {
            sessionTimeoutMinutes = settings.sessionTimeoutMinutes;
        }
        startIdleTracking();
        
        // Update stats
        document.getElementById('stat-total').textContent = stats.totalSamlApps;
        document.getElementById('stat-on').textContent = stats.appsWithAutoRotateOn;
        document.getElementById('stat-off').textContent = stats.appsWithAutoRotateOff;
        document.getElementById('stat-notify').textContent = stats.appsWithAutoRotateNotify;
        document.getElementById('stat-null').textContent = stats.appsWithAutoRotateNull;
        document.getElementById('stat-expiring-30').textContent = stats.appsExpiringSoon;
        document.getElementById('stat-expired').textContent = stats.appsWithExpiredCerts;
        const expiringThresholdDays = typeof stats.expiringSoonThresholdDays === 'number'
            ? stats.expiringSoonThresholdDays
            : createCertDaysThreshold;
        document.getElementById('stat-expiring-label').textContent = `Expiring ≤${expiringThresholdDays} Days`;

        // Update last updated
        document.getElementById('last-updated').textContent = 
            `Last updated: ${new Date(stats.generatedAt).toLocaleString()}`;

        // Store apps for filtering
        allApps = stats.apps;
        applyFilters();
        clearStatusBanner();
        _cache.data = true;

    } catch (error) {
        document.getElementById('apps-table-container').innerHTML = 
            `<div class="error">Failed to load data: ${escapeHtml(error.message)}</div>`;
    }
}

// ── My SAML Apps (Sponsor view) ──────────────────────────────────
let myAppsData = [];
let myAppsRawResult = null; // cached raw API response for reuse by My Stale Certs
let myAppsSponsorCanRotate = false;
let myAppsSponsorCanUpdatePolicy = false;
let myAppsSponsorCanEditSponsors = false;

async function loadMyApps(force = true) {
    const container = document.getElementById('myapps-table-container');
    if (!container) return;
    if (!force && _cache.myApps) { applyMyAppsFilter(); return; }
    container.innerHTML = '<div class="loading">Loading your sponsored applications...</div>';
    try {
        const result = await apiCall('dashboard/my-apps');
        myAppsRawResult = result;
        myAppsData = result.apps || [];
        myAppsSponsorCanRotate = result.sponsorsCanRotateCerts === true;
        myAppsSponsorCanUpdatePolicy = result.sponsorsCanUpdatePolicy === true;
        myAppsSponsorCanEditSponsors = result.sponsorsCanEditSponsors === true;
        applyMyAppsFilter();
        _cache.myApps = true;
    } catch (error) {
        container.innerHTML = `<div class="error">Failed to load your applications: ${escapeHtml(error.message)}</div>`;
    }
}

function applyMyAppsFilter() {
    const filtered = getFilteredMyApps();
    const sortBy = (document.getElementById('myapp-sort-by')?.value || 'daysRemaining').toLowerCase();
    const sortDirection = (document.getElementById('myapp-sort-direction')?.value || 'asc').toLowerCase();

    filtered.sort((a, b) => {
        let left, right;
        switch (sortBy) {
            case 'daysremaining':
                left = typeof a.daysUntilExpiry === 'number' ? a.daysUntilExpiry : Infinity;
                right = typeof b.daysUntilExpiry === 'number' ? b.daysUntilExpiry : Infinity;
                break;
            case 'expirydate':
                left = a.certExpiryDate ? new Date(a.certExpiryDate).getTime() : Infinity;
                right = b.certExpiryDate ? new Date(b.certExpiryDate).getTime() : Infinity;
                break;
            case 'name':
            default:
                left = (a.displayName || '').toLowerCase();
                right = (b.displayName || '').toLowerCase();
                break;
        }
        if (left < right) return sortDirection === 'asc' ? -1 : 1;
        if (left > right) return sortDirection === 'asc' ? 1 : -1;
        return 0;
    });
    renderMyApps(filtered);
}

function getFilteredMyApps() {
    const searchTerm = (document.getElementById('myapp-search')?.value || '').trim().toLowerCase();
    const selectedAutoRotateFilters = Array.from(document.querySelectorAll('.myapp-auto-rotate-filter-option-input:checked')).map(i => i.value);
    const selectedStatusFilters = Array.from(document.querySelectorAll('.myapp-status-filter-option-input:checked')).map(i => i.value);
    const selectedPolicyTypeFilters = Array.from(document.querySelectorAll('.myapp-policy-type-filter-option-input:checked')).map(i => i.value);

    return myAppsData.filter(app => {
        const status = (app.autoRotateStatus || '').toLowerCase();
        const autoRotateValue = status === 'on' ? 'on' : status === 'off' ? 'off' : status === 'notify' ? 'notify' : 'notset';
        const computedStatus = getComputedAppStatus(app);

        const autoRotateMatch = selectedAutoRotateFilters.length === 0 || selectedAutoRotateFilters.includes(autoRotateValue);
        const statusMatch = selectedStatusFilters.length === 0 || selectedStatusFilters.includes(computedStatus);
        const policyTypeMatch = selectedPolicyTypeFilters.length === 0 || selectedPolicyTypeFilters.includes(app.policyType || 'Global');
        const nameMatch = !searchTerm || (app.displayName || '').toLowerCase().includes(searchTerm);

        return autoRotateMatch && statusMatch && policyTypeMatch && nameMatch;
    });
}

function buildEntraDeeplink(objectId, appId) {
    return `https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/SignOn/objectId/${encodeURIComponent(objectId)}/appId/${encodeURIComponent(appId)}/preferredSingleSignOnMode/saml/servicePrincipalType/Application/fromNav/`;
}

function renderMyApps(apps) {
    const container = document.getElementById('myapps-table-container');
    if (!container) return;

    if (apps.length === 0) {
        container.innerHTML = '<div style="text-align:center;padding:40px;color:#666;">No sponsored applications match the selected filters.</div>';
        return;
    }

    const formatComputedStatus = (status) => {
        if (status === 'ok') return 'OK';
        return status.charAt(0).toUpperCase() + status.slice(1);
    };

    const canRotate = myAppsSponsorCanRotate || isAdminUser();
    const canUpdatePolicy = myAppsSponsorCanUpdatePolicy || isAdminUser();
    const canEditSponsors = myAppsSponsorCanEditSponsors || isAdminUser();
    const hasAnyAction = canRotate || canUpdatePolicy || canEditSponsors;
    const adminMyApps = isAdminUser();

    const col = (key) => myAppsVisibleColumns[key];
    const hide = (key) => col(key) ? '' : ' style="display:none;"';

    const tableHtml = `
        <table>
            <thead>
                <tr>
                    <th${hide('application')}>Application</th>
                    <th${hide('applicationId')}>Application ID</th>
                    <th${hide('autoRotate')}>Auto-Rotate</th>
                    <th${hide('certExpiry')}>Certificate Expiry</th>
                    <th${hide('daysRemaining')}>Days Remaining</th>
                    <th${hide('status')}>Status</th>
                    <th${hide('policyType')}>Policy Type</th>
                    <th${hide('createCertDays')}>Create Cert (days)</th>
                    <th${hide('activateCertDays')}>Activate Cert (days)</th>
                    <th${hide('deeplink')}>View in Entra ID</th>
                    ${hasAnyAction ? '<th style="width:60px;">Actions</th>' : ''}
                </tr>
            </thead>
            <tbody>
                ${apps.map(app => {
                    const computedStatus = getComputedAppStatus(app);
                    const computedStatusClass = toSafeClassToken(computedStatus, 'ok');
                    const autoRotateStatusClass = toSafeClassToken(app.autoRotateStatus || 'null', 'null');
                    const deeplink = buildEntraDeeplink(app.id, app.appId || '');
                    const appIdToken = 'myapp-' + toDomIdToken(app.id, 'myapp');
                    const isAppSpecific = app.policyType === 'App-Specific';
                    return `
                    <tr>
                        <td${hide('application')}>${escapeHtml(app.displayName)}</td>
                        <td${hide('applicationId')} style="${col('applicationId') ? '' : 'display:none;'}font-size:12px;">${escapeHtml(app.id)}</td>
                        <td${hide('autoRotate')}>
                            <span class="status-badge status-${autoRotateStatusClass}">
                                ${((app.autoRotateStatus || '').toLowerCase() === 'notify') ? 'Notify' : (escapeHtml(app.autoRotateStatus) || 'Not Set')}
                            </span>
                        </td>
                        <td${hide('certExpiry')}>${app.certExpiryDate ? new Date(app.certExpiryDate).toLocaleDateString() : 'N/A'}</td>
                        <td${hide('daysRemaining')}>${app.daysUntilExpiry ?? 'N/A'}</td>
                        <td${hide('status')}>
                            <span class="expiry-badge expiry-${computedStatusClass}">
                                ${formatComputedStatus(computedStatus)}
                            </span>
                        </td>
                        <td${hide('policyType')}>
                            <span class="status-badge ${isAppSpecific ? 'status-on' : ''}">${escapeHtml(app.policyType || 'Global')}</span>
                        </td>
                        <td${hide('createCertDays')}>${app.createCertDaysBeforeExpiry ?? 'N/A'}</td>
                        <td${hide('activateCertDays')}>${app.activateCertDaysBeforeExpiry ?? 'N/A'}</td>
                        <td${hide('deeplink')}><a href="${escapeHtml(deeplink)}" target="_blank" rel="noopener noreferrer" title="Open in Entra admin center">Open in Entra ↗</a></td>
                        ${hasAnyAction ? `
                        <td class="actions-cell">
                            <button class="actions-btn" data-action="toggle-menu" data-app-id-token="${appIdToken}">⋮</button>
                            <div id="actions-menu-${appIdToken}" class="dropdown-menu">
                                ${adminMyApps ? `
                                <button class="dropdown-item" data-action="create-cert" data-app-id="${escapeHtml(app.id)}" data-app-name="${escapeHtml(app.displayName)}">
                                    Create new SAML certificate
                                </button>
                                <button class="dropdown-item" data-action="activate-cert" data-app-id="${escapeHtml(app.id)}" data-app-name="${escapeHtml(app.displayName)}">
                                    Make newest cert active
                                </button>
                                <button class="dropdown-item" data-action="edit-sponsor" data-app-id="${escapeHtml(app.id)}" data-app-name="${escapeHtml(app.displayName)}" data-sponsor="${escapeHtml(app.sponsor || '')}">
                                    Edit Sponsor
                                </button>
                                <button class="dropdown-item" data-action="edit-policy" data-app-id="${escapeHtml(app.id)}" data-app-name="${escapeHtml(app.displayName)}">
                                    Edit Policy
                                </button>
                                <button class="dropdown-item ${computedStatus === 'ok' ? 'disabled' : ''}" ${computedStatus === 'ok' ? 'disabled' : ''} data-action="resend-reminder" data-app-id="${escapeHtml(app.id)}" data-app-name="${escapeHtml(app.displayName)}">
                                    Resend Reminder Email
                                </button>
                                ` : `
                                ${canRotate ? `
                                <button class="dropdown-item" data-action="sponsor-create-cert" data-app-id="${escapeHtml(app.id)}" data-app-name="${escapeHtml(app.displayName)}">
                                    Create new SAML certificate
                                </button>
                                <button class="dropdown-item" data-action="sponsor-activate-cert" data-app-id="${escapeHtml(app.id)}" data-app-name="${escapeHtml(app.displayName)}">
                                    Make newest cert active
                                </button>
                                ` : ''}
                                ${canUpdatePolicy ? `
                                <button class="dropdown-item" data-action="sponsor-edit-policy" data-app-id="${escapeHtml(app.id)}" data-app-name="${escapeHtml(app.displayName)}">
                                    Edit Policy
                                </button>
                                ` : ''}
                                ${canEditSponsors ? `
                                <button class="dropdown-item" data-action="sponsor-edit-sponsor" data-app-id="${escapeHtml(app.id)}" data-app-name="${escapeHtml(app.displayName)}" data-sponsor="${escapeHtml(app.sponsor || '')}">
                                    Edit Sponsor
                                </button>
                                ` : ''}
                                `}
                            </div>
                        </td>
                        ` : ''}
                    </tr>
                `;
                }).join('')}
            </tbody>
        </table>
    `;
    container.innerHTML = tableHtml;
}

// Apply filters, sort, and render apps table
function applyFilters() {
    const filtered = getFilteredApps();
    const sortBy = (document.getElementById('app-sort-by')?.value || 'name').toLowerCase();
    const sortDirection = (document.getElementById('app-sort-direction')?.value || 'asc').toLowerCase();

    filtered.sort((a, b) => {
        let left, right;
        switch (sortBy) {
            case 'daysremaining':
                left = typeof a.daysUntilExpiry === 'number' ? a.daysUntilExpiry : Infinity;
                right = typeof b.daysUntilExpiry === 'number' ? b.daysUntilExpiry : Infinity;
                break;
            case 'expirydate':
                left = a.certExpiryDate ? new Date(a.certExpiryDate).getTime() : Infinity;
                right = b.certExpiryDate ? new Date(b.certExpiryDate).getTime() : Infinity;
                break;
            case 'name':
            default:
                left = (a.displayName || '').toLowerCase();
                right = (b.displayName || '').toLowerCase();
                break;
        }
        if (left < right) return sortDirection === 'asc' ? -1 : 1;
        if (left > right) return sortDirection === 'asc' ? 1 : -1;
        return 0;
    });

    renderApps(filtered);
}

// Render apps table
function renderApps(apps) {
    if (apps.length === 0) {
        document.getElementById('apps-table-container').innerHTML = 
            '<div style="text-align:center;padding:40px;color:#666;">No applications match the selected filters.</div>';
        return;
    }

    const formatComputedStatus = (status) => {
        if (status === 'ok') return 'OK';
        return status.charAt(0).toUpperCase() + status.slice(1);
    };

    const col = (key) => visibleColumns[key];
    const hide = (key) => col(key) ? '' : ' style="display:none;"';

    const tableHtml = `
        <table>
            <thead>
                <tr>
                    <th${hide('application')}>Application</th>
                    <th${hide('applicationId')}>Application ID</th>
                    <th${hide('sponsor')}>Sponsor</th>
                    <th${hide('autoRotate')}>Auto-Rotate</th>
                    <th${hide('certExpiry')}>Certificate Expiry</th>
                    <th${hide('daysRemaining')}>Days Remaining</th>
                    <th${hide('status')}>Status</th>
                    <th${hide('policyType')}>Policy Type</th>
                    <th${hide('createCertDays')}>Create Cert (days)</th>
                    <th${hide('activateCertDays')}>Activate Cert (days)</th>
                    <th style="width:60px;">Actions</th>
                </tr>
            </thead>
            <tbody>
                ${apps.map(app => {
                    const computedStatus = getComputedAppStatus(app);
                    const appIdToken = 'admin-' + toDomIdToken(app.id, 'app');
                    const autoRotateStatusClass = toSafeClassToken(app.autoRotateStatus || 'null', 'null');
                    const computedStatusClass = toSafeClassToken(computedStatus, 'ok');
                    const isAppSpecific = app.policyType === 'App-Specific';
                    return `
                    <tr>
                        <td${hide('application')}>${escapeHtml(app.displayName)}</td>
                        <td${hide('applicationId')} style="${col('applicationId') ? '' : 'display:none;'}font-size:12px;">${escapeHtml(app.id)}</td>
                        <td${hide('sponsor')}>${escapeHtml(app.sponsor) || 'Not Set'}</td>
                        <td${hide('autoRotate')}>
                            <span class="status-badge status-${autoRotateStatusClass}">
                                ${((app.autoRotateStatus || '').toLowerCase() === 'notify') ? 'Notify' : (escapeHtml(app.autoRotateStatus) || 'Not Set')}
                            </span>
                        </td>
                        <td${hide('certExpiry')}>${app.certExpiryDate ? new Date(app.certExpiryDate).toLocaleDateString() : 'N/A'}</td>
                        <td${hide('daysRemaining')}>${app.daysUntilExpiry ?? 'N/A'}</td>
                        <td${hide('status')}>
                            <span class="expiry-badge expiry-${computedStatusClass}">
                                ${formatComputedStatus(computedStatus)}
                            </span>
                        </td>
                        <td${hide('policyType')}>
                            <span class="status-badge ${isAppSpecific ? 'status-on' : ''}">${escapeHtml(app.policyType || 'Global')}</span>
                        </td>
                        <td${hide('createCertDays')}>${app.createCertDaysBeforeExpiry ?? 'N/A'}</td>
                        <td${hide('activateCertDays')}>${app.activateCertDaysBeforeExpiry ?? 'N/A'}</td>
                        <td class="actions-cell">
                            <button class="actions-btn" data-action="toggle-menu" data-app-id-token="${appIdToken}">⋮</button>
                            <div id="actions-menu-${appIdToken}" class="dropdown-menu">
                                <button class="dropdown-item ${isAdminUser() ? '' : 'disabled'}" ${isAdminUser() ? '' : 'disabled style="opacity:0.5;cursor:not-allowed;"'} data-action="create-cert" data-app-id="${escapeHtml(app.id)}" data-app-name="${escapeHtml(app.displayName)}">
                                    Create new SAML certificate
                                </button>
                                <button class="dropdown-item ${isAdminUser() ? '' : 'disabled'}" ${isAdminUser() ? '' : 'disabled style="opacity:0.5;cursor:not-allowed;"'} data-action="activate-cert" data-app-id="${escapeHtml(app.id)}" data-app-name="${escapeHtml(app.displayName)}">
                                    Make newest cert active
                                </button>
                                <button class="dropdown-item ${isAdminUser() ? '' : 'disabled'}" ${isAdminUser() ? '' : 'disabled style="opacity:0.5;cursor:not-allowed;"'} data-action="edit-sponsor" data-app-id="${escapeHtml(app.id)}" data-app-name="${escapeHtml(app.displayName)}" data-sponsor="${escapeHtml(app.sponsor || '')}">
                                    Edit Sponsor
                                </button>
                                <button class="dropdown-item ${isAdminUser() ? '' : 'disabled'}" ${isAdminUser() ? '' : 'disabled style="opacity:0.5;cursor:not-allowed;"'} data-action="edit-policy" data-app-id="${escapeHtml(app.id)}" data-app-name="${escapeHtml(app.displayName)}">
                                    Edit Policy
                                </button>
                                <button class="dropdown-item ${(computedStatus === 'ok' || !isAdminUser()) ? 'disabled' : ''}" ${(computedStatus === 'ok' || !isAdminUser()) ? 'disabled' : ''} ${!isAdminUser() ? 'style="opacity:0.5;cursor:not-allowed;"' : ''} data-action="resend-reminder" data-app-id="${escapeHtml(app.id)}" data-app-name="${escapeHtml(app.displayName)}">
                                    Resend Reminder Email
                                </button>
                            </div>
                        </td>
                    </tr>
                `;
                }).join('')}
            </tbody>
        </table>
    `;
    document.getElementById('apps-table-container').innerHTML = tableHtml;
}

// Load policy settings
let cachedPolicy = null;
let cachedPolicySettings = null;

async function loadPolicy(force = true) {
    if (!force && _cache.policy && cachedPolicy && cachedPolicySettings) {
        document.getElementById('createDays').value = cachedPolicy.createCertDaysBeforeExpiry;
        document.getElementById('activateDays').value = cachedPolicy.activateCertDaysBeforeExpiry;
        document.getElementById('createCertsForNotifyApps').value = cachedPolicySettings.createCertsForNotifyApps === false ? 'disabled' : 'enabled';
        return;
    }
    try {
        const [policy, settings] = await Promise.all([
            apiCall('policy'),
            apiCall('settings')
        ]);
        cachedPolicy = policy;
        document.getElementById('createDays').value = policy.createCertDaysBeforeExpiry;
        document.getElementById('activateDays').value = policy.activateCertDaysBeforeExpiry;

        cachedPolicySettings = settings;
        document.getElementById('createCertsForNotifyApps').value = settings.createCertsForNotifyApps === false ? 'disabled' : 'enabled';
        _cache.policy = true;
    } catch (error) {
        console.error('Failed to load policy:', error);
    }
}

// Save policy settings
async function savePolicy() {
    try {
        const createDays = parseInt(document.getElementById('createDays').value, 10);
        const activateDays = parseInt(document.getElementById('activateDays').value, 10);

        if (isNaN(createDays) || createDays < 1 || createDays > 365) {
            showError('Create cert days must be between 1 and 365.');
            return;
        }
        if (isNaN(activateDays) || activateDays < 1 || activateDays > 365) {
            showError('Activate cert days must be between 1 and 365.');
            return;
        }
        if (activateDays >= createDays) {
            showError('Activate cert days must be less than Create cert days.');
            return;
        }

        const policy = {
            createCertDaysBeforeExpiry: createDays,
            activateCertDaysBeforeExpiry: activateDays,
            isEnabled: true
        };
        await apiCall('policy', {
            method: 'PUT',
            body: JSON.stringify(policy)
        });

        const createCertsForNotify = document.getElementById('createCertsForNotifyApps').value === 'enabled';
        await apiCall('settings', {
            method: 'PUT',
            body: JSON.stringify({ createCertsForNotifyApps: createCertsForNotify })
        });

        showSuccess('Policy saved successfully!');
        invalidateAllCaches();
    } catch (error) {
        showError('Failed to save policy: ' + error.message);
    }
}

// Load settings
let cachedSettings = null;

function applySettingsToForm(settings) {
    document.getElementById('notificationEmails').value = settings.notificationEmails || '';
    document.getElementById('rotationSchedule').value = formatCronSchedule(settings.rotationSchedule || '0 0 6 * * *');
    document.getElementById('reportOnlyMode').value = settings.reportOnlyModeEnabled === false ? 'disabled' : 'enabled';
    document.getElementById('retentionPolicyDays').value = settings.retentionPolicyDays || 180;
    document.getElementById('sponsorsReceiveNotifications').value = settings.sponsorsReceiveNotifications === false ? 'disabled' : 'enabled';
    document.getElementById('sponsorRemindersEnabled').value = settings.sponsorRemindersEnabled === false ? 'disabled' : 'enabled';
    document.getElementById('sponsorReminderCount').value = (settings.sponsorReminderCount >= 1 && settings.sponsorReminderCount <= 3) ? settings.sponsorReminderCount : 3;
    document.getElementById('sponsorFirstReminderDays').value = Number.isInteger(settings.sponsorFirstReminderDays) ? settings.sponsorFirstReminderDays : 30;
    document.getElementById('sponsorSecondReminderDays').value = Number.isInteger(settings.sponsorSecondReminderDays) ? settings.sponsorSecondReminderDays : 7;
    document.getElementById('sponsorThirdReminderDays').value = Number.isInteger(settings.sponsorThirdReminderDays) ? settings.sponsorThirdReminderDays : 1;
    document.getElementById('notifySponsorsOnExpiration').value = settings.notifySponsorsOnExpiration === true ? 'enabled' : 'disabled';
    document.getElementById('sessionTimeoutMinutes').value = typeof settings.sessionTimeoutMinutes === 'number' ? settings.sessionTimeoutMinutes : 0;
    document.getElementById('reportsRetentionPolicyDays').value = settings.reportsRetentionPolicyDays || 14;
    const sponsorsCanRotateEl = document.getElementById('sponsorsCanRotateCerts');
    if (sponsorsCanRotateEl) sponsorsCanRotateEl.value = settings.sponsorsCanRotateCerts === true ? 'enabled' : 'disabled';
    const sponsorsCanUpdatePolicyEl = document.getElementById('sponsorsCanUpdatePolicy');
    if (sponsorsCanUpdatePolicyEl) sponsorsCanUpdatePolicyEl.value = settings.sponsorsCanUpdatePolicy === true ? 'enabled' : 'disabled';
    const sponsorsCanEditSponsorsEl = document.getElementById('sponsorsCanEditSponsors');
    if (sponsorsCanEditSponsorsEl) sponsorsCanEditSponsorsEl.value = settings.sponsorsCanEditSponsors === true ? 'enabled' : 'disabled';
    toggleSponsorReminderSettings();
    toggleSponsorReminderCount();
}

async function loadSettings(force = true) {
    if (!force && _cache.settings && cachedSettings) {
        applySettingsToForm(cachedSettings);
        return;
    }
    try {
        const settings = await apiCall('settings');
        cachedSettings = settings;
        applySettingsToForm(settings);
        _cache.settings = true;
    } catch (error) {
        console.error('Failed to load settings:', error);
    }
}

// Format CRON schedule to human-readable string
function formatCronSchedule(cron) {
    // CRON format: second minute hour dayOfMonth month dayOfWeek
    const parts = cron.split(' ');
    if (parts.length !== 6) return cron;
    
    const hourField = parts[2];
    const minuteField = parts[1];
    
    // Every N hours (e.g., */12)
    const everyHoursMatch = hourField.match(/^\*\/(\d+)$/);
    if (everyHoursMatch && parts[3] === '*' && parts[4] === '*' && parts[5] === '*') {
        return `Every ${everyHoursMatch[1]} hours (${cron})`;
    }

    // Weekly on a specific day (e.g., dayOfWeek = 1 for Monday)
    const dayOfWeek = parseInt(parts[5]);
    const hour = parseInt(hourField);
    const minute = parseInt(minuteField);
    if (!isNaN(dayOfWeek) && !isNaN(hour) && parts[3] === '*' && parts[4] === '*') {
        const days = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
        const dayName = days[dayOfWeek] || `day ${dayOfWeek}`;
        const hourStr = hour.toString().padStart(2, '0');
        const minStr = minute.toString().padStart(2, '0');
        return `Every ${dayName} at ${hourStr}:${minStr} UTC (${cron})`;
    }

    // Daily at a fixed time
    if (!isNaN(hour) && !isNaN(minute) && parts[3] === '*' && parts[4] === '*' && parts[5] === '*') {
        const hourStr = hour.toString().padStart(2, '0');
        const minStr = minute.toString().padStart(2, '0');
        return `Daily at ${hourStr}:${minStr} UTC (${cron})`;
    }
    
    return cron;
}

// Save settings
async function saveSettings() {
    try {
        const retentionPolicyDays = parseInt(document.getElementById('retentionPolicyDays').value, 10);

        if (Number.isNaN(retentionPolicyDays) || retentionPolicyDays < 1) {
            showError('Retention policy must be at least 1 day.');
            return;
        }

        const reportsRetentionPolicyDays = parseInt(document.getElementById('reportsRetentionPolicyDays').value, 10);

        if (Number.isNaN(reportsRetentionPolicyDays) || reportsRetentionPolicyDays < 1) {
            showError('Reports retention policy must be at least 1 day.');
            return;
        }

        const sponsorRemindersEnabled = document.getElementById('sponsorRemindersEnabled').value === 'enabled';
        const sponsorReminderCount = parseInt(document.getElementById('sponsorReminderCount').value, 10) || 3;

        // Only validate reminder days that are active based on the count
        const sponsorFirstReminderDays = parseInt(document.getElementById('sponsorFirstReminderDays').value, 10);
        const sponsorSecondReminderDays = parseInt(document.getElementById('sponsorSecondReminderDays').value, 10);
        const sponsorThirdReminderDays = parseInt(document.getElementById('sponsorThirdReminderDays').value, 10);

        const activeReminderValues = [sponsorFirstReminderDays, sponsorSecondReminderDays, sponsorThirdReminderDays].slice(0, sponsorReminderCount);
        const invalidReminderValue = activeReminderValues.some(value => !Number.isInteger(value) || value < 1 || value > 180);

        if (sponsorRemindersEnabled && invalidReminderValue) {
            showError('Sponsor reminder values must be whole numbers between 1 and 180.');
            return;
        }

        const settings = {
            notificationEmails: document.getElementById('notificationEmails').value.trim(),
            reportOnlyModeEnabled: document.getElementById('reportOnlyMode').value === 'enabled',
            sponsorsReceiveNotifications: document.getElementById('sponsorsReceiveNotifications').value === 'enabled',
            sponsorRemindersEnabled,
            sponsorReminderCount,
            notifySponsorsOnExpiration: document.getElementById('notifySponsorsOnExpiration').value === 'enabled',
            sponsorFirstReminderDays,
            sponsorSecondReminderDays,
            sponsorThirdReminderDays,
            retentionPolicyDays,
            reportsRetentionPolicyDays,
            sessionTimeoutMinutes: parseInt(document.getElementById('sessionTimeoutMinutes').value, 10) || 0,
            sponsorsCanRotateCerts: document.getElementById('sponsorsCanRotateCerts')?.value === 'enabled',
            sponsorsCanUpdatePolicy: document.getElementById('sponsorsCanUpdatePolicy')?.value === 'enabled',
            sponsorsCanEditSponsors: document.getElementById('sponsorsCanEditSponsors')?.value === 'enabled'
        };
        await apiCall('settings', {
            method: 'PUT',
            body: JSON.stringify(settings)
        });
        // Update idle tracking with new timeout setting
        stopIdleTracking();
        sessionTimeoutMinutes = parseInt(document.getElementById('sessionTimeoutMinutes').value, 10) || 0;
        startIdleTracking();
        showSuccess('Settings saved successfully!');
        invalidateAllCaches();
    } catch (error) {
        showError('Failed to save settings: ' + error.message);
    }
}

function toggleSponsorReminderSettings() {
    const select = document.getElementById('sponsorRemindersEnabled');
    const reminderContainer = document.getElementById('sponsor-reminder-settings');

    if (!select || !reminderContainer) {
        return;
    }

    reminderContainer.style.display = select.value === 'enabled' ? 'block' : 'none';
    if (select.value === 'enabled') {
        toggleSponsorReminderCount();
    }
}

function toggleSponsorReminderCount() {
    const countSelect = document.getElementById('sponsorReminderCount');
    if (!countSelect) return;

    const count = parseInt(countSelect.value, 10) || 3;

    const reminder1 = document.getElementById('reminder1-group');
    const reminder2 = document.getElementById('reminder2-group');
    const reminder3 = document.getElementById('reminder3-group');

    if (reminder1) reminder1.style.display = count >= 1 ? 'block' : 'none';
    if (reminder2) reminder2.style.display = count >= 2 ? 'block' : 'none';
    if (reminder3) reminder3.style.display = count >= 3 ? 'block' : 'none';
}

// ── Reports tab ──────────────────────────────────────────────────
let cachedReports = [];

function renderReportsTable(reports) {
    const tbody = document.getElementById('reports-table-body');
    document.getElementById('reports-list-view').style.display = '';
    document.getElementById('reports-detail-view').style.display = 'none';
    if (!reports || reports.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:#888;">No reports found.</td></tr>';
        return;
    }
    tbody.innerHTML = '';
    reports.forEach(r => {
        const tr = document.createElement('tr');
        const modeLabel = r.mode === 'prod' ? '<span style="color:#d83b01;font-weight:600;">Prod</span>' : '<span style="color:#0078d4;">Report-only</span>';
        tr.innerHTML = `
            <td>${new Date(r.runDate).toLocaleString()}</td>
            <td>${modeLabel}</td>
            <td>${escapeHtml(r.triggeredBy || 'Scheduled')}</td>
            <td>${r.totalProcessed}</td>
            <td>${r.successful}</td>
            <td>${r.skipped}</td>
            <td>${r.failed > 0 ? '<span style="color:#d83b01;font-weight:600;">' + r.failed + '</span>' : r.failed}</td>
            <td><button class="btn btn-secondary" style="padding:4px 12px;font-size:12px;" data-action="view-report" data-report-id="${escapeHtml(r.id)}">View Report</button></td>
        `;
        tbody.appendChild(tr);
    });
}

async function loadReports(force = true) {
    if (!force && _cache.reports) { renderReportsTable(cachedReports); return; }
    const tbody = document.getElementById('reports-table-body');
    tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:#888;">Loading...</td></tr>';
    // Always show list view and hide detail view when loading
    document.getElementById('reports-list-view').style.display = '';
    document.getElementById('reports-detail-view').style.display = 'none';
    try {
        const reports = await apiCall('reports');
        cachedReports = reports || [];
        renderReportsTable(cachedReports);
        _cache.reports = true;
    } catch (error) {
        tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:#d83b01;">Failed to load reports.</td></tr>';
        console.error('Failed to load reports:', error);
    }
}

async function viewReport(id) {
    document.getElementById('reports-list-view').style.display = 'none';
    const detailView = document.getElementById('reports-detail-view');
    detailView.style.display = '';

    const summaryDiv = document.getElementById('report-detail-summary');
    const tbody = document.getElementById('report-detail-table-body');
    summaryDiv.innerHTML = '<span style="color:#888;">Loading...</span>';
    tbody.innerHTML = '';

    try {
        const report = await apiCall(`reports/${id}`);
        const modeLabel = report.mode === 'prod' ? 'Production' : 'Report-only';
        document.getElementById('report-detail-title').textContent = `Run Report — ${new Date(report.runDate).toLocaleString()}`;

        summaryDiv.innerHTML = `
            <div><strong>Mode:</strong> ${modeLabel}</div>
            <div><strong>Triggered By:</strong> ${escapeHtml(report.triggeredBy || 'Scheduled')}</div>
            <div><strong>Date:</strong> ${new Date(report.runDate).toLocaleString()}</div>
            <div><strong>Apps Evaluated:</strong> ${report.totalProcessed}</div>
            <div><strong>Successful:</strong> ${report.successful}</div>
            <div><strong>Apps Skipped (no action required):</strong> ${report.skipped}</div>
            <div><strong>Failed:</strong> ${report.failed}</div>
        `;

        if (!report.results || report.results.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:#888;">No actionable apps — all certificates are healthy.</td></tr>';
            return;
        }

        // Sort: failures first, then by name
        const sorted = [...report.results].sort((a, b) => {
            if (!a.success && b.success) return -1;
            if (a.success && !b.success) return 1;
            return (a.appDisplayName || '').localeCompare(b.appDisplayName || '');
        });

        sorted.forEach(r => {
            const tr = document.createElement('tr');
            const resultIcon = r.success ? '✅' : '❌';
            const actionStyle = (r.action || 'None') === 'None' ? 'color:#888;' : '';
            tr.innerHTML = `
                <td>${escapeHtml(r.appDisplayName || '')}</td>
                <td style="${actionStyle}">${escapeHtml(r.action || 'None')}</td>
                <td>${resultIcon}</td>
                <td style="font-size:12px;font-family:monospace;">${escapeHtml(r.newCertificateThumbprint || '—')}</td>
                <td style="color:#d83b01;font-size:12px;">${escapeHtml(r.errorMessage || '')}</td>
            `;
            tbody.appendChild(tr);
        });
    } catch (error) {
        summaryDiv.innerHTML = '<span style="color:#d83b01;">Failed to load report detail.</span>';
        console.error('Failed to load report:', error);
    }
}

function backToReportList() {
    document.getElementById('reports-detail-view').style.display = 'none';
    document.getElementById('reports-list-view').style.display = '';
}

// Audit log filters and rendering
// Load audit log
async function loadAuditLog(force = true) {
    if (!force && _cache.audit) { applyAuditFilters(); return; }
    try {
        showLoading('Refreshing audit log...');
        const fromDate = document.getElementById('audit-from-date')?.value;
        const toDate = document.getElementById('audit-to-date')?.value;

        let endpoint = 'audit?days=30';
        if (fromDate && toDate) {
            endpoint = `audit?from=${encodeURIComponent(fromDate)}&to=${encodeURIComponent(toDate)}`;
        }

        allAuditEntries = await apiCall(endpoint);
        applyAuditFilters();
        clearStatusBanner();
        _cache.audit = true;

    } catch (error) {
        document.getElementById('audit-table-container').innerHTML = 
            `<div class="error">Failed to load audit log: ${escapeHtml(error.message)}</div>`;
    }
}

function setDefaultAuditDateRange() {
    const fromInput = document.getElementById('audit-from-date');
    const toInput = document.getElementById('audit-to-date');

    if (!fromInput || !toInput) {
        return;
    }

    if (fromInput.value && toInput.value) {
        return;
    }

    const today = new Date();
    const fromDate = new Date(today);
    fromDate.setDate(fromDate.getDate() - 30);

    const toDateValue = today.toISOString().split('T')[0];
    const fromDateValue = fromDate.toISOString().split('T')[0];

    if (!fromInput.value) {
        fromInput.value = fromDateValue;
    }

    if (!toInput.value) {
        toInput.value = toDateValue;
    }
}

function toggleAuditResultFilterDropdown(event) {
    event.stopPropagation();
    const dropdown = document.getElementById('audit-result-filter-dropdown');
    const wasOpen = dropdown.classList.contains('show');
    closeAllDropdowns();
    if (!wasOpen) {
        dropdown.classList.add('show');
    }
}

function getSelectedAuditResultFilters() {
    return Array.from(document.querySelectorAll('.audit-result-filter-option-input:checked'))
        .map(input => input.value);
}

function updateAuditResultFilterLabel() {
    const selected = getSelectedAuditResultFilters();
    const label = document.getElementById('audit-result-filter-label');
    if (!label) return;
    if (selected.length === 0) {
        label.textContent = 'Result';
    } else {
        label.textContent = selected.map(v => v.charAt(0).toUpperCase() + v.slice(1)).join(', ');
    }
}

function onAuditResultFilterChanged() {
    updateAuditResultFilterLabel();
    applyAuditFilters();
}

function updateAuditColumnVisibility() {
    document.querySelectorAll('.audit-columns-filter-option-input').forEach(cb => {
        auditVisibleColumns[cb.value] = cb.checked;
    });
    applyAuditFilters();
}

function clearAuditFilters() {
    document.querySelectorAll('.audit-action-filter-option-input').forEach(input => { input.checked = false; });
    document.querySelectorAll('.audit-result-filter-option-input').forEach(input => { input.checked = false; });
    document.getElementById('audit-initiated-by-search').value = '';
    document.getElementById('audit-application-search').value = '';
    document.getElementById('audit-details-search').value = '';
    updateAuditActionFilterLabel();
    updateAuditResultFilterLabel();
    document.getElementById('audit-filter-panel').style.display = 'none';
    document.getElementById('btn-toggle-audit-filters').textContent = 'Add Filter';
    applyAuditFilters();
}

function applyAuditFilters() {
    const sortBy = (document.getElementById('audit-sort-by')?.value || 'time').toLowerCase();
    const sortDirection = (document.getElementById('audit-sort-direction')?.value || 'desc').toLowerCase();
    const selectedActionFilters = getSelectedAuditActionFilters();
    const selectedResultFilters = getSelectedAuditResultFilters();
    const initiatedByTerm = (document.getElementById('audit-initiated-by-search')?.value || '').trim().toLowerCase();
    const applicationTerm = (document.getElementById('audit-application-search')?.value || '').trim().toLowerCase();
    const detailsTerm = (document.getElementById('audit-details-search')?.value || '').trim().toLowerCase();

    let filtered = allAuditEntries.filter(entry => {
        // Actions filter
        const actionMatch = selectedActionFilters.length === 0 || selectedActionFilters.includes(entry.actionType || '');
        if (!actionMatch) return false;

        // Result filter
        if (selectedResultFilters.length > 0) {
            const resultVal = entry.isSuccess ? 'success' : 'failed';
            if (!selectedResultFilters.includes(resultVal)) return false;
        }

        // Initiated By text filter
        if (initiatedByTerm) {
            const performedBy = (entry.performedBy || 'System').toLowerCase();
            if (!performedBy.includes(initiatedByTerm)) return false;
        }

        // Application text filter
        if (applicationTerm) {
            const appName = (entry.appDisplayName || '').toLowerCase();
            if (!appName.includes(applicationTerm)) return false;
        }

        // Details text filter
        if (detailsTerm) {
            const details = `${entry.description || ''} ${entry.errorMessage || ''}`.toLowerCase();
            if (!details.includes(detailsTerm)) return false;
        }

        return true;
    });

    filtered.sort((a, b) => {
        let left;
        let right;

        switch (sortBy) {
            case 'application':
                left = (a.appDisplayName || '').toLowerCase();
                right = (b.appDisplayName || '').toLowerCase();
                break;
            case 'initiatedBy':
                left = (a.performedBy || 'System').toLowerCase();
                right = (b.performedBy || 'System').toLowerCase();
                break;
            case 'action':
                left = (a.actionType || '').toLowerCase();
                right = (b.actionType || '').toLowerCase();
                break;
            case 'result':
                left = a.isSuccess ? 1 : 0;
                right = b.isSuccess ? 1 : 0;
                break;
            case 'time':
            default:
                left = new Date(a.timestamp || 0).getTime();
                right = new Date(b.timestamp || 0).getTime();
                break;
        }

        if (left < right) return sortDirection === 'asc' ? -1 : 1;
        if (left > right) return sortDirection === 'asc' ? 1 : -1;
        return 0;
    });

    renderAuditLogTable(filtered);
}

function renderAuditLogTable(entries) {
    if (!entries || entries.length === 0) {
        document.getElementById('audit-table-container').innerHTML =
            '<div style="text-align:center;padding:40px;color:#666;">No audit entries match the selected filters.</div>';
        return;
    }

    const ac = (key) => auditVisibleColumns[key];
    const ahide = (key) => ac(key) ? '' : ' style="display:none;"';

    const tableHtml = `
        <table>
            <thead>
                <tr>
                    <th${ahide('time')}>Time</th>
                    <th${ahide('application')}>Application</th>
                    <th${ahide('applicationId')}>Application ID</th>
                    <th${ahide('initiatedBy')}>Initiated By</th>
                    <th${ahide('action')}>Action</th>
                    <th${ahide('result')}>Result</th>
                    <th${ahide('details')}>Details</th>
                </tr>
            </thead>
            <tbody>
                ${entries.map(entry => {
                    const spId = entry.servicePrincipalId || '';
                    const showId = spId && spId !== 'SYSTEM' ? spId : '-';
                    return `
                    <tr>
                        <td${ahide('time')}>${new Date(entry.timestamp).toLocaleString()}</td>
                        <td${ahide('application')}>${escapeHtml(entry.appDisplayName || '-')}</td>
                        <td${ahide('applicationId')} style="${ac('applicationId') ? '' : 'display:none;'}font-size:12px;">${escapeHtml(showId)}</td>
                        <td${ahide('initiatedBy')}>${escapeHtml(entry.performedBy || 'System')}</td>
                        <td${ahide('action')}>${escapeHtml(entry.actionType)}</td>
                        <td${ahide('result')}>
                            <span class="status-badge ${entry.isSuccess ? 'status-on' : 'status-off'}">
                                ${entry.isSuccess ? 'Success' : 'Failed'}
                            </span>
                        </td>
                        <td${ahide('details')}>${escapeHtml(entry.description)}${entry.errorMessage ? ` - ${escapeHtml(entry.errorMessage)}` : ''}</td>
                    </tr>
                `;
                }).join('')}
            </tbody>
        </table>
    `;
    document.getElementById('audit-table-container').innerHTML = tableHtml;
}

// Cleanup/export helpers
// Store cleanup data for export
let cleanupApps = [];
let myStaleCerts = [];

// Load certificate cleanup data
async function loadCleanupData(force = true) {
    if (!force && _cache.cleanup) { renderCleanupTable(cleanupApps); return; }
    try {
        showLoading('Refreshing cleanup data...');
        // Get detailed app data including all certificates
        const apps = await apiCall('applications');
        
        // Find apps with inactive AND expired certificates
        cleanupApps = [];
        const now = new Date();
        
        for (const app of apps) {
            if (app.certificates && app.certificates.length > 0) {
                const expiredInactiveCerts = app.certificates.filter(cert => {
                    const endDate = new Date(cert.endDateTime);
                    return !cert.isActive && endDate < now;
                });
                
                if (expiredInactiveCerts.length > 0) {
                    cleanupApps.push({
                        displayName: app.displayName,
                        id: app.id,
                        appId: app.appId,
                        expiredInactiveCertCount: expiredInactiveCerts.length,
                        certificates: expiredInactiveCerts.map(c => ({
                            keyId: c.keyId,
                            thumbprint: c.thumbprint,
                            endDateTime: c.endDateTime
                        }))
                    });
                }
            }
        }
        
        renderCleanupTable(cleanupApps);
        clearStatusBanner();
        _cache.cleanup = true;
        
    } catch (error) {
        document.getElementById('cleanup-table-container').innerHTML = 
            `<div class="error">Failed to load cleanup data: ${escapeHtml(error.message)}</div>`;
    }
}

// Render cleanup table
function renderCleanupTable(apps) {
    if (apps.length === 0) {
        document.getElementById('cleanup-table-container').innerHTML = 
            '<div style="text-align:center;padding:40px;color:#666;">No applications have inactive expired certificates. Your tenant is clean!</div>';
        return;
    }

    const tableHtml = `
        <table>
            <thead>
                <tr>
                    <th>Application Name</th>
                    <th>App ID</th>
                    <th>Expired Inactive Certs</th>
                </tr>
            </thead>
            <tbody>
                ${apps.map(app => `
                    <tr>
                        <td>${escapeHtml(app.displayName)}</td>
                        <td style="font-family:monospace;font-size:12px;">${escapeHtml(app.appId)}</td>
                        <td>${app.expiredInactiveCertCount}</td>
                    </tr>
                `).join('')}
            </tbody>
        </table>
        <p style="margin-top:16px;color:#666;font-size:13px;">
            Total: ${apps.length} application(s) with ${apps.reduce((sum, a) => sum + a.expiredInactiveCertCount, 0)} expired inactive certificate(s)
        </p>
    `;
    document.getElementById('cleanup-table-container').innerHTML = tableHtml;
}

// Export cleanup list to JSON
function exportCleanupListJson() {
    if (cleanupApps.length === 0) {
        showError('No cleanup data to export');
        return;
    }
    
    const exportData = {
        exportDate: new Date().toISOString(),
        exportType: 'certificate-cleanup',
        totalApps: cleanupApps.length,
        totalExpiredCerts: cleanupApps.reduce((sum, a) => sum + a.expiredInactiveCertCount, 0),
        applications: cleanupApps
    };
    
    downloadJson(exportData, `certificate-cleanup-${formatDateForFilename()}.json`);
}

// Export cleanup list to CSV
function exportCleanupListCsv() {
    if (cleanupApps.length === 0) {
        showError('No cleanup data to export');
        return;
    }

    const rows = [];
    rows.push('Application,Application ID,App ID,Expired Inactive Certs,Certificate Key ID,Thumbprint,Expiry Date');
    for (const app of cleanupApps) {
        if (app.certificates && app.certificates.length > 0) {
            for (const cert of app.certificates) {
                rows.push([
                    escapeCsvField(app.displayName || ''),
                    escapeCsvField(app.id || ''),
                    escapeCsvField(app.appId || ''),
                    app.expiredInactiveCertCount,
                    escapeCsvField(cert.keyId || ''),
                    escapeCsvField(cert.thumbprint || ''),
                    cert.endDateTime ? new Date(cert.endDateTime).toISOString() : ''
                ].join(','));
            }
        } else {
            rows.push([
                escapeCsvField(app.displayName || ''),
                escapeCsvField(app.id || ''),
                escapeCsvField(app.appId || ''),
                app.expiredInactiveCertCount,
                '', '', ''
            ].join(','));
        }
    }
    downloadCsvFile(rows.join('\n'), `certificate-cleanup-${formatDateForFilename()}.csv`);
}

// ── My SAML Apps filter helpers ──

function toggleMyAppFilterPanel() {
    const panel = document.getElementById('myapp-filter-panel');
    const btn = document.getElementById('btn-toggle-myapp-filters');
    if (panel.style.display === 'none') {
        panel.style.display = 'block';
        btn.textContent = 'Hide Filters';
    } else {
        panel.style.display = 'none';
        btn.textContent = 'Add Filters';
    }
}

function clearMyAppFilters() {
    document.querySelectorAll('.myapp-auto-rotate-filter-option-input').forEach(input => { input.checked = false; });
    document.querySelectorAll('.myapp-status-filter-option-input').forEach(input => { input.checked = false; });
    document.querySelectorAll('.myapp-policy-type-filter-option-input').forEach(input => { input.checked = false; });
    updateMyAppAutoRotateFilterLabel();
    updateMyAppStatusFilterLabel();
    updateMyAppPolicyTypeFilterLabel();
    document.getElementById('myapp-filter-panel').style.display = 'none';
    document.getElementById('btn-toggle-myapp-filters').textContent = 'Add Filters';
    applyMyAppsFilter();
}

function updateMyAppAutoRotateFilterLabel() {
    const selected = Array.from(document.querySelectorAll('.myapp-auto-rotate-filter-option-input:checked')).map(i => i.value);
    const label = document.getElementById('myapp-auto-rotate-filter-label');
    if (!label) return;
    if (selected.length === 0) { label.textContent = 'Auto-Rotate'; }
    else if (selected.length <= 2) {
        label.textContent = selected.map(v => v === 'notset' ? 'Not Set' : v === 'notify' ? 'Notify' : v.charAt(0).toUpperCase() + v.slice(1)).join(', ');
    } else { label.textContent = `${selected.length} selected`; }
}

function updateMyAppStatusFilterLabel() {
    const selected = Array.from(document.querySelectorAll('.myapp-status-filter-option-input:checked')).map(i => i.value);
    const label = document.getElementById('myapp-status-filter-label');
    if (!label) return;
    if (selected.length === 0) { label.textContent = 'Status'; }
    else if (selected.length <= 2) {
        label.textContent = selected.map(v => v.toUpperCase() === 'OK' ? 'OK' : v.charAt(0).toUpperCase() + v.slice(1)).join(', ');
    } else { label.textContent = `${selected.length} selected`; }
}

function updateMyAppPolicyTypeFilterLabel() {
    const selected = Array.from(document.querySelectorAll('.myapp-policy-type-filter-option-input:checked')).map(i => i.value);
    const label = document.getElementById('myapp-policy-type-filter-label');
    if (!label) return;
    if (selected.length === 0) { label.textContent = 'Policy Type'; }
    else if (selected.length <= 2) { label.textContent = selected.join(', '); }
    else { label.textContent = `${selected.length} selected`; }
}

function onMyAppFilterChanged() {
    updateMyAppAutoRotateFilterLabel();
    updateMyAppStatusFilterLabel();
    updateMyAppPolicyTypeFilterLabel();
    applyMyAppsFilter();
}

function toggleMyAppAutoRotateFilterDropdown(event) {
    event.stopPropagation();
    const dd = document.getElementById('myapp-auto-rotate-filter-dropdown');
    const wasOpen = dd.classList.contains('show');
    closeAllDropdowns();
    if (!wasOpen) dd.classList.add('show');
}

function toggleMyAppStatusFilterDropdown(event) {
    event.stopPropagation();
    const dd = document.getElementById('myapp-status-filter-dropdown');
    const wasOpen = dd.classList.contains('show');
    closeAllDropdowns();
    if (!wasOpen) dd.classList.add('show');
}

function toggleMyAppPolicyTypeFilterDropdown(event) {
    event.stopPropagation();
    const dd = document.getElementById('myapp-policy-type-filter-dropdown');
    const wasOpen = dd.classList.contains('show');
    closeAllDropdowns();
    if (!wasOpen) dd.classList.add('show');
}

function updateMyAppsColumnVisibility() {
    document.querySelectorAll('.myapp-columns-filter-option-input').forEach(cb => {
        myAppsVisibleColumns[cb.value] = cb.checked;
    });
    applyMyAppsFilter();
}

function toggleExportMyAppsDropdown(e) {
    e.stopPropagation();
    const dd = document.getElementById('export-myapps-dropdown');
    const wasOpen = dd.classList.contains('show');
    closeAllDropdowns();
    if (!wasOpen) dd.classList.add('show');
}

// Export My Apps to JSON
function exportMyAppsJson() {
    const filteredApps = getFilteredMyApps();
    if (filteredApps.length === 0) { showError('No applications to export'); return; }
    const exportData = {
        exportDate: new Date().toISOString(),
        exportType: 'my-saml-applications',
        totalApps: filteredApps.length,
        applications: filteredApps.map(app => ({
            displayName: app.displayName,
            id: app.id,
            autoRotateStatus: app.autoRotateStatus,
            certExpiryDate: app.certExpiryDate,
            daysUntilExpiry: app.daysUntilExpiry,
            expiryCategory: app.expiryCategory,
            policyType: app.policyType || 'Global',
            createCertDaysBeforeExpiry: app.createCertDaysBeforeExpiry,
            activateCertDaysBeforeExpiry: app.activateCertDaysBeforeExpiry
        }))
    };
    downloadJson(exportData, `my-saml-applications-${formatDateForFilename()}.json`);
}

// Export My Apps to CSV
function exportMyAppsCsv() {
    const filteredApps = getFilteredMyApps();
    if (filteredApps.length === 0) { showError('No applications to export'); return; }
    const rows = [];
    rows.push('Application,Application ID,Auto-Rotate,Certificate Expiry,Days Remaining,Status,Policy Type,Create Cert (days),Activate Cert (days)');
    for (const app of filteredApps) {
        rows.push([
            escapeCsvField(app.displayName || ''),
            escapeCsvField(app.id || ''),
            escapeCsvField(app.autoRotateStatus || ''),
            app.certExpiryDate ? new Date(app.certExpiryDate).toISOString() : '',
            app.daysUntilExpiry != null ? app.daysUntilExpiry : '',
            escapeCsvField(getComputedAppStatus(app) || ''),
            escapeCsvField(app.policyType || 'Global'),
            app.createCertDaysBeforeExpiry != null ? app.createCertDaysBeforeExpiry : '',
            app.activateCertDaysBeforeExpiry != null ? app.activateCertDaysBeforeExpiry : ''
        ].join(','));
    }
    downloadCsvFile(rows.join('\n'), `my-saml-applications-${formatDateForFilename()}.csv`);
}

// ── My Stale Certs ──

async function loadMyStaleCerts(force = true) {
    const container = document.getElementById('mystalecerts-table-container');
    if (!container) return;
    if (!force && _cache.myStaleCerts) { renderMyStaleCerts(myStaleCerts); return; }
    container.innerHTML = '<div class="loading">Loading stale certificate data...</div>';
    try {
        // Reuse cached my-apps data if available, otherwise fetch
        let apps;
        if (myAppsRawResult && _cache.myApps) {
            apps = myAppsRawResult.apps || [];
        } else {
            const result = await apiCall('dashboard/my-apps');
            myAppsRawResult = result;
            apps = result.apps || [];
        }
        myStaleCerts = [];
        const now = new Date();

        for (const app of apps) {
            if (app.certificates && app.certificates.length > 0) {
                const expiredInactiveCerts = app.certificates.filter(cert => {
                    const endDate = new Date(cert.endDateTime);
                    return !cert.isActive && endDate < now;
                });
                if (expiredInactiveCerts.length > 0) {
                    myStaleCerts.push({
                        displayName: app.displayName,
                        id: app.id,
                        appId: app.appId,
                        expiredInactiveCertCount: expiredInactiveCerts.length,
                        certificates: expiredInactiveCerts.map(c => ({
                            keyId: c.keyId,
                            thumbprint: c.thumbprint,
                            endDateTime: c.endDateTime
                        }))
                    });
                }
            }
        }
        renderMyStaleCerts(myStaleCerts);
        _cache.myStaleCerts = true;
    } catch (error) {
        container.innerHTML = `<div class="error">Failed to load stale certificate data: ${escapeHtml(error.message)}</div>`;
    }
}

function renderMyStaleCerts(apps) {
    const container = document.getElementById('mystalecerts-table-container');
    if (!container) return;

    if (apps.length === 0) {
        container.innerHTML = '<div style="text-align:center;padding:40px;color:#666;">None of your sponsored applications have inactive expired certificates. All clean!</div>';
        return;
    }

    const tableHtml = `
        <table>
            <thead>
                <tr>
                    <th>Application Name</th>
                    <th>App ID</th>
                    <th>Expired Inactive Certs</th>
                    <th>View in Entra ID</th>
                </tr>
            </thead>
            <tbody>
                ${apps.map(app => {
                    const deeplink = buildEntraDeeplink(app.id, app.appId || '');
                    return `
                    <tr>
                        <td>${escapeHtml(app.displayName)}</td>
                        <td style="font-family:monospace;font-size:12px;">${escapeHtml(app.appId)}</td>
                        <td>${app.expiredInactiveCertCount}</td>
                        <td><a href="${escapeHtml(deeplink)}" target="_blank" rel="noopener noreferrer" title="Open in Entra admin center">Open in Entra ↗</a></td>
                    </tr>
                `;
                }).join('')}
            </tbody>
        </table>
        <p style="margin-top:16px;color:#666;font-size:13px;">
            Total: ${apps.length} application(s) with ${apps.reduce((sum, a) => sum + a.expiredInactiveCertCount, 0)} expired inactive certificate(s)
        </p>
    `;
    container.innerHTML = tableHtml;
}

function toggleExportMyStaleCertsDropdown(e) {
    e.stopPropagation();
    const dd = document.getElementById('export-mystalecerts-dropdown');
    const wasOpen = dd.classList.contains('show');
    closeAllDropdowns();
    if (!wasOpen) dd.classList.add('show');
}

function exportMyStaleCertsJson() {
    if (myStaleCerts.length === 0) { showError('No stale certificate data to export'); return; }
    const exportData = {
        exportDate: new Date().toISOString(),
        exportType: 'my-stale-certificates',
        totalApps: myStaleCerts.length,
        totalExpiredCerts: myStaleCerts.reduce((sum, a) => sum + a.expiredInactiveCertCount, 0),
        applications: myStaleCerts
    };
    downloadJson(exportData, `my-stale-certificates-${formatDateForFilename()}.json`);
}

function exportMyStaleCertsCsv() {
    if (myStaleCerts.length === 0) { showError('No stale certificate data to export'); return; }
    const rows = [];
    rows.push('Application,Application ID,App ID,Expired Inactive Certs,Certificate Key ID,Thumbprint,Expiry Date');
    for (const app of myStaleCerts) {
        if (app.certificates && app.certificates.length > 0) {
            for (const cert of app.certificates) {
                rows.push([
                    escapeCsvField(app.displayName || ''),
                    escapeCsvField(app.id || ''),
                    escapeCsvField(app.appId || ''),
                    app.expiredInactiveCertCount,
                    escapeCsvField(cert.keyId || ''),
                    escapeCsvField(cert.thumbprint || ''),
                    cert.endDateTime ? new Date(cert.endDateTime).toISOString() : ''
                ].join(','));
            }
        } else {
            rows.push([
                escapeCsvField(app.displayName || ''),
                escapeCsvField(app.id || ''),
                escapeCsvField(app.appId || ''),
                app.expiredInactiveCertCount,
                '', '', ''
            ].join(','));
        }
    }
    downloadCsvFile(rows.join('\n'), `my-stale-certificates-${formatDateForFilename()}.csv`);
}

// Export currently visible applications to JSON
function exportApplicationsJson() {
    const filteredApps = getFilteredApps();

    if (filteredApps.length === 0) {
        showError('No applications to export');
        return;
    }
    
    const exportData = {
        exportDate: new Date().toISOString(),
        exportType: 'saml-applications',
        totalApps: filteredApps.length,
        applications: filteredApps.map(app => ({
            displayName: app.displayName,
            id: app.id,
            sponsor: app.sponsor,
            autoRotateStatus: app.autoRotateStatus,
            certExpiryDate: app.certExpiryDate,
            daysUntilExpiry: app.daysUntilExpiry,
            expiryCategory: app.expiryCategory,
            policyType: app.policyType || 'Global',
            createCertDaysBeforeExpiry: app.createCertDaysBeforeExpiry,
            activateCertDaysBeforeExpiry: app.activateCertDaysBeforeExpiry
        }))
    };
    
    downloadJson(exportData, `saml-applications-${formatDateForFilename()}.json`);
}

// Export currently visible applications to CSV
function exportApplicationsCsv() {
    const filteredApps = getFilteredApps();

    if (filteredApps.length === 0) {
        showError('No applications to export');
        return;
    }

    const rows = [];
    rows.push('Application,Application ID,Sponsor,Auto-Rotate,Certificate Expiry,Days Remaining,Status,Policy Type,Create Cert (days),Activate Cert (days)');
    for (const app of filteredApps) {
        rows.push([
            escapeCsvField(app.displayName || ''),
            escapeCsvField(app.id || ''),
            escapeCsvField(app.sponsor || ''),
            escapeCsvField(app.autoRotateStatus || ''),
            app.certExpiryDate ? new Date(app.certExpiryDate).toISOString() : '',
            app.daysUntilExpiry != null ? app.daysUntilExpiry : '',
            escapeCsvField(app.expiryCategory || ''),
            escapeCsvField(app.policyType || 'Global'),
            app.createCertDaysBeforeExpiry != null ? app.createCertDaysBeforeExpiry : '',
            app.activateCertDaysBeforeExpiry != null ? app.activateCertDaysBeforeExpiry : ''
        ].join(','));
    }
    downloadCsvFile(rows.join('\n'), `saml-applications-${formatDateForFilename()}.csv`);
}

// Export audit log to JSON
function exportAuditLogJson() {
    const entries = getFilteredAuditEntries();
    if (entries.length === 0) {
        showError('No audit entries to export');
        return;
    }

    const exportData = {
        exportDate: new Date().toISOString(),
        exportType: 'audit-log',
        totalEntries: entries.length,
        entries: entries.map(e => ({
            timestamp: e.timestamp,
            appDisplayName: e.appDisplayName,
            servicePrincipalId: e.servicePrincipalId,
            performedBy: e.performedBy || 'System',
            actionType: e.actionType,
            isSuccess: e.isSuccess,
            description: e.description,
            errorMessage: e.errorMessage || '',
            certificateThumbprint: e.certificateThumbprint || '',
            newCertificateThumbprint: e.newCertificateThumbprint || ''
        }))
    };

    downloadJson(exportData, `audit-log-${formatDateForFilename()}.json`);
}

// Export audit log to CSV
function exportAuditLogCsv() {
    const entries = getFilteredAuditEntries();
    if (entries.length === 0) {
        showError('No audit entries to export');
        return;
    }

    const rows = [];
    rows.push('Time,Application,Application ID,Initiated By,Action,Result,Details,Error,Certificate Thumbprint,New Certificate Thumbprint');
    for (const e of entries) {
        rows.push([
            e.timestamp ? new Date(e.timestamp).toISOString() : '',
            escapeCsvField(e.appDisplayName || ''),
            escapeCsvField(e.servicePrincipalId || ''),
            escapeCsvField(e.performedBy || 'System'),
            escapeCsvField(e.actionType || ''),
            e.isSuccess ? 'Success' : 'Failed',
            escapeCsvField(e.description || ''),
            escapeCsvField(e.errorMessage || ''),
            escapeCsvField(e.certificateThumbprint || ''),
            escapeCsvField(e.newCertificateThumbprint || '')
        ].join(','));
    }
    downloadCsvFile(rows.join('\n'), `audit-log-${formatDateForFilename()}.csv`);
}

// Get filtered audit entries (applies current filters — mirrors applyAuditFilters logic)
function getFilteredAuditEntries() {
    const selectedActionFilters = getSelectedAuditActionFilters();
    const selectedResultFilters = getSelectedAuditResultFilters();
    const initiatedByTerm = (document.getElementById('audit-initiated-by-search')?.value || '').trim().toLowerCase();
    const applicationTerm = (document.getElementById('audit-application-search')?.value || '').trim().toLowerCase();
    const detailsTerm = (document.getElementById('audit-details-search')?.value || '').trim().toLowerCase();

    return allAuditEntries.filter(entry => {
        const actionMatch = selectedActionFilters.length === 0 || selectedActionFilters.includes(entry.actionType || '');
        if (!actionMatch) return false;

        if (selectedResultFilters.length > 0) {
            const resultVal = entry.isSuccess ? 'success' : 'failed';
            if (!selectedResultFilters.includes(resultVal)) return false;
        }

        if (initiatedByTerm) {
            const performedBy = (entry.performedBy || 'System').toLowerCase();
            if (!performedBy.includes(initiatedByTerm)) return false;
        }

        if (applicationTerm) {
            const appName = (entry.appDisplayName || '').toLowerCase();
            if (!appName.includes(applicationTerm)) return false;
        }

        if (detailsTerm) {
            const details = `${entry.description || ''} ${entry.errorMessage || ''}`.toLowerCase();
            if (!details.includes(detailsTerm)) return false;
        }

        return true;
    });
}

// Toggle export dropdown helpers
function toggleExportAppsDropdown(e) {
    e.stopPropagation();
    const dd = document.getElementById('export-apps-dropdown');
    const wasOpen = dd.classList.contains('show');
    closeAllDropdowns();
    if (!wasOpen) dd.classList.add('show');
}

function toggleExportCleanupDropdown(e) {
    e.stopPropagation();
    const dd = document.getElementById('export-cleanup-dropdown');
    const wasOpen = dd.classList.contains('show');
    closeAllDropdowns();
    if (!wasOpen) dd.classList.add('show');
}

function toggleExportAuditDropdown(e) {
    e.stopPropagation();
    const dd = document.getElementById('export-audit-dropdown');
    const wasOpen = dd.classList.contains('show');
    closeAllDropdowns();
    if (!wasOpen) dd.classList.add('show');
}

// Download JSON file helper
function downloadJson(data, filename) {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// Format date for filename
function formatDateForFilename() {
    const now = new Date();
    return `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}`;
}

// ── Bulk Sponsor Update ──

let pendingBulkUpdates = [];

function toggleBulkSponsorsDropdown() {
    const dropdown = document.getElementById('bulk-sponsors-dropdown');
    if (!dropdown) return;
    const isOpen = dropdown.classList.contains('show');
    // Close all dropdowns first
    document.querySelectorAll('.dropdown-menu.show').forEach(d => d.classList.remove('show'));
    if (!isOpen) dropdown.classList.add('show');
}

function downloadEmptyCsv() {
    const csv = 'Application,ApplicationId,SponsorEmail\n';
    downloadCsvFile(csv, `sponsor-template-${formatDateForFilename()}.csv`);
    document.getElementById('bulk-sponsors-dropdown')?.classList.remove('show');
}

function downloadFilledCsv() {
    if (!allApps || allApps.length === 0) {
        showError('No applications loaded. Please refresh first.');
        return;
    }

    const rows = allApps.map(app => {
        const name = escapeCsvField(app.displayName || '');
        const id = escapeCsvField(app.id || '');
        const sponsor = escapeCsvField(app.sponsor || '');
        return `${name},${id},${sponsor}`;
    });

    const csv = 'Application,ApplicationId,SponsorEmail\n' + rows.join('\n') + '\n';
    downloadCsvFile(csv, `sponsor-export-${formatDateForFilename()}.csv`);
    document.getElementById('bulk-sponsors-dropdown')?.classList.remove('show');
}

function escapeCsvField(value) {
    if (value.includes(',') || value.includes('"') || value.includes('\n')) {
        return '"' + value.replace(/"/g, '""') + '"';
    }
    return value;
}

function downloadCsvFile(csvContent, filename) {
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function triggerBulkUpload() {
    document.getElementById('bulk-sponsors-dropdown')?.classList.remove('show');
    document.getElementById('bulk-csv-file-input').click();
}

function handleBulkCsvUpload(event) {
    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = function(e) {
        try {
            const csvText = e.target.result;
            const parsed = parseCsv(csvText);
            if (parsed.length === 0) {
                showError('CSV file is empty or has no data rows.');
                return;
            }
            previewBulkUpdates(parsed);
        } catch (err) {
            showError('Failed to parse CSV: ' + err.message);
        }
    };
    reader.readAsText(file);
    // Reset file input so the same file can be re-uploaded
    event.target.value = '';
}

function parseCsv(text) {
    const lines = text.split(/\r?\n/).filter(line => line.trim().length > 0);
    if (lines.length < 1) return [];

    // Parse header to find column indices
    const headerCols = parseCsvLine(lines[0]).map(h => h.trim().toLowerCase());
    const appIdIdx = headerCols.findIndex(h => h === 'applicationid');
    const sponsorIdx = headerCols.findIndex(h => h === 'sponsoremail');

    if (appIdIdx === -1) {
        throw new Error('Missing required column: ApplicationId');
    }
    if (sponsorIdx === -1) {
        throw new Error('Missing required column: SponsorEmail');
    }

    const results = [];
    for (let i = 1; i < lines.length; i++) {
        const cols = parseCsvLine(lines[i]);
        const applicationId = (cols[appIdIdx] || '').trim();
        const sponsorEmail = (cols[sponsorIdx] || '').trim();

        if (applicationId) {
            results.push({ applicationId, sponsorEmail });
        }
    }
    return results;
}

function parseCsvLine(line) {
    const result = [];
    let current = '';
    let inQuotes = false;

    for (let i = 0; i < line.length; i++) {
        const ch = line[i];
        if (inQuotes) {
            if (ch === '"' && i + 1 < line.length && line[i + 1] === '"') {
                current += '"';
                i++;
            } else if (ch === '"') {
                inQuotes = false;
            } else {
                current += ch;
            }
        } else {
            if (ch === '"') {
                inQuotes = true;
            } else if (ch === ',') {
                result.push(current);
                current = '';
            } else {
                current += ch;
            }
        }
    }
    result.push(current);
    return result;
}

function previewBulkUpdates(csvData) {
    // Build a lookup from current apps
    const appLookup = {};
    allApps.forEach(app => {
        appLookup[app.id] = app;
    });

    // Compute diff
    const changes = [];
    let updateCount = 0;
    let clearCount = 0;
    let unchangedCount = 0;
    let notFoundCount = 0;
    let invalidEmailCount = 0;

    csvData.forEach(row => {
        const app = appLookup[row.applicationId];
        if (!app) {
            changes.push({
                applicationId: row.applicationId,
                displayName: '(Not found)',
                currentSponsor: '',
                newSponsor: row.sponsorEmail,
                action: 'skip',
                reason: 'App not found'
            });
            notFoundCount++;
            return;
        }

        const currentSponsor = (app.sponsor || '').trim();
        const newSponsor = row.sponsorEmail.trim();

        if (currentSponsor.toLowerCase() === newSponsor.toLowerCase()) {
            unchangedCount++;
            return;
        }

        if (newSponsor === '') {
            changes.push({
                applicationId: row.applicationId,
                displayName: app.displayName,
                currentSponsor,
                newSponsor: '(clear)',
                action: 'clear'
            });
            clearCount++;
        } else {
            // Email validation using standard pattern
            if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(newSponsor)) {
                changes.push({
                    applicationId: row.applicationId,
                    displayName: app.displayName,
                    currentSponsor,
                    newSponsor,
                    action: 'skip',
                    reason: 'Invalid email'
                });
                invalidEmailCount++;
                return;
            }
            changes.push({
                applicationId: row.applicationId,
                displayName: app.displayName,
                currentSponsor,
                newSponsor,
                action: 'update'
            });
            updateCount++;
        }
    });

    if (changes.length === 0) {
        showSuccess('No changes detected. All sponsors are already up to date.');
        return;
    }

    // Show preview modal
    pendingBulkUpdates = changes.filter(c => c.action !== 'skip');

    const summaryParts = [];
    if (updateCount > 0) summaryParts.push(`<strong>${updateCount}</strong> will be updated`);
    if (clearCount > 0) summaryParts.push(`<strong>${clearCount}</strong> will be cleared`);
    if (unchangedCount > 0) summaryParts.push(`<strong>${unchangedCount}</strong> unchanged`);
    if (notFoundCount > 0) summaryParts.push(`<strong>${notFoundCount}</strong> not found (skipped)`);
    if (invalidEmailCount > 0) summaryParts.push(`<strong>${invalidEmailCount}</strong> invalid email (skipped)`);

    document.getElementById('bulkSponsorSummary').innerHTML = summaryParts.join(' &middot; ');

    const tbody = document.getElementById('bulkSponsorPreviewBody');
    tbody.innerHTML = changes.map(c => {
        const actionColor = c.action === 'update' ? '#0078d4' : c.action === 'clear' ? '#d83b01' : '#a19f9d';
        const actionLabel = c.action === 'update' ? 'Update' : c.action === 'clear' ? 'Clear' : `Skip (${c.reason})`;
        return `<tr>
            <td style="padding:6px 10px;border-bottom:1px solid #edebe9;">${escapeHtml(c.displayName)}</td>
            <td style="padding:6px 10px;border-bottom:1px solid #edebe9;">${escapeHtml(c.currentSponsor) || '<em style="color:#a19f9d;">Not Set</em>'}</td>
            <td style="padding:6px 10px;border-bottom:1px solid #edebe9;">${c.action === 'clear' ? '<em style="color:#d83b01;">Clear</em>' : escapeHtml(c.newSponsor)}</td>
            <td style="padding:6px 10px;border-bottom:1px solid #edebe9;color:${actionColor};font-weight:500;">${actionLabel}</td>
        </tr>`;
    }).join('');

    const applyBtn = document.getElementById('btn-bulk-apply');
    applyBtn.disabled = pendingBulkUpdates.length === 0;
    applyBtn.textContent = pendingBulkUpdates.length > 0 ? `Apply ${pendingBulkUpdates.length} Change${pendingBulkUpdates.length > 1 ? 's' : ''}` : 'No Changes';

    document.getElementById('bulkSponsorModal').classList.add('show');
}

function closeBulkSponsorModal() {
    document.getElementById('bulkSponsorModal').classList.remove('show');
    pendingBulkUpdates = [];
}

async function applyBulkSponsorUpdates() {
    if (pendingBulkUpdates.length === 0) return;

    const applyBtn = document.getElementById('btn-bulk-apply');
    applyBtn.disabled = true;
    applyBtn.textContent = 'Applying...';

    try {
        const payload = pendingBulkUpdates.map(c => ({
            applicationId: c.applicationId,
            sponsorEmail: c.action === 'clear' ? '' : c.newSponsor
        }));

        const result = await apiCall('applications/bulk-update-sponsors', {
            method: 'POST',
            body: JSON.stringify(payload)
        });

        closeBulkSponsorModal();
        showSuccess(result.message || 'Bulk update complete.');
        // Reload apps to reflect changes
        invalidateAllCaches();
        loadData();
    } catch (error) {
        showError('Bulk update failed: ' + error.message);
        applyBtn.disabled = false;
        applyBtn.textContent = `Apply ${pendingBulkUpdates.length} Changes`;
    }
}

// ── Event listener wiring (CSP-safe, no inline handlers) ──

// Header
document.getElementById('btn-sign-out').addEventListener('click', signOut);

// Applications tab buttons
document.getElementById('btn-export-apps').addEventListener('click', function(e) { toggleExportAppsDropdown(e); });
document.getElementById('btn-export-apps-csv').addEventListener('click', function() { document.getElementById('export-apps-dropdown').classList.remove('show'); exportApplicationsCsv(); });
document.getElementById('btn-export-apps-json').addEventListener('click', function() { document.getElementById('export-apps-dropdown').classList.remove('show'); exportApplicationsJson(); });
document.getElementById('btn-refresh-apps').addEventListener('click', loadData);

// My SAML Apps tab buttons
const btnRefreshMyApps = document.getElementById('btn-refresh-myapps');
if (btnRefreshMyApps) btnRefreshMyApps.addEventListener('click', loadMyApps);
const myAppSearch = document.getElementById('myapp-search');
if (myAppSearch) myAppSearch.addEventListener('input', debounce(applyMyAppsFilter));

// My SAML Apps export
const btnExportMyApps = document.getElementById('btn-export-myapps');
if (btnExportMyApps) btnExportMyApps.addEventListener('click', function(e) { toggleExportMyAppsDropdown(e); });
const btnExportMyAppsCsv = document.getElementById('btn-export-myapps-csv');
if (btnExportMyAppsCsv) btnExportMyAppsCsv.addEventListener('click', function() { document.getElementById('export-myapps-dropdown').classList.remove('show'); exportMyAppsCsv(); });
const btnExportMyAppsJson = document.getElementById('btn-export-myapps-json');
if (btnExportMyAppsJson) btnExportMyAppsJson.addEventListener('click', function() { document.getElementById('export-myapps-dropdown').classList.remove('show'); exportMyAppsJson(); });

// My SAML Apps filters
const myAppSortBy = document.getElementById('myapp-sort-by');
if (myAppSortBy) myAppSortBy.addEventListener('change', applyMyAppsFilter);
const myAppSortDir = document.getElementById('myapp-sort-direction');
if (myAppSortDir) myAppSortDir.addEventListener('change', applyMyAppsFilter);
const btnToggleMyAppFilters = document.getElementById('btn-toggle-myapp-filters');
if (btnToggleMyAppFilters) btnToggleMyAppFilters.addEventListener('click', toggleMyAppFilterPanel);
const btnClearMyAppFilters = document.getElementById('btn-clear-myapp-filters');
if (btnClearMyAppFilters) btnClearMyAppFilters.addEventListener('click', clearMyAppFilters);

const myAppAutoRotateToggle = document.getElementById('myapp-auto-rotate-filter-toggle');
if (myAppAutoRotateToggle) myAppAutoRotateToggle.addEventListener('click', function(e) { toggleMyAppAutoRotateFilterDropdown(e); });
const myAppAutoRotateDropdown = document.getElementById('myapp-auto-rotate-filter-dropdown');
if (myAppAutoRotateDropdown) myAppAutoRotateDropdown.addEventListener('click', function(e) { e.stopPropagation(); });
document.querySelectorAll('.myapp-auto-rotate-filter-option-input').forEach(function(cb) { cb.addEventListener('change', onMyAppFilterChanged); });

const myAppStatusToggle = document.getElementById('myapp-status-filter-toggle');
if (myAppStatusToggle) myAppStatusToggle.addEventListener('click', function(e) { toggleMyAppStatusFilterDropdown(e); });
const myAppStatusDropdown = document.getElementById('myapp-status-filter-dropdown');
if (myAppStatusDropdown) myAppStatusDropdown.addEventListener('click', function(e) { e.stopPropagation(); });
document.querySelectorAll('.myapp-status-filter-option-input').forEach(function(cb) { cb.addEventListener('change', onMyAppFilterChanged); });

const myAppPolicyTypeToggle = document.getElementById('myapp-policy-type-filter-toggle');
if (myAppPolicyTypeToggle) myAppPolicyTypeToggle.addEventListener('click', function(e) { toggleMyAppPolicyTypeFilterDropdown(e); });
const myAppPolicyTypeDropdown = document.getElementById('myapp-policy-type-filter-dropdown');
if (myAppPolicyTypeDropdown) myAppPolicyTypeDropdown.addEventListener('click', function(e) { e.stopPropagation(); });
document.querySelectorAll('.myapp-policy-type-filter-option-input').forEach(function(cb) { cb.addEventListener('change', onMyAppFilterChanged); });

// My SAML Apps columns filter
const myAppColumnsToggle = document.getElementById('myapp-columns-filter-toggle');
if (myAppColumnsToggle) myAppColumnsToggle.addEventListener('click', function(e) { e.stopPropagation(); document.getElementById('myapp-columns-filter-dropdown').classList.toggle('show'); });
const myAppColumnsDropdown = document.getElementById('myapp-columns-filter-dropdown');
if (myAppColumnsDropdown) myAppColumnsDropdown.addEventListener('click', function(e) { e.stopPropagation(); });
document.querySelectorAll('.myapp-columns-filter-option-input').forEach(function(cb) { cb.addEventListener('change', updateMyAppsColumnVisibility); });

// My Stale Certs tab buttons
const btnRefreshMyStaleCerts = document.getElementById('btn-refresh-mystalecerts');
if (btnRefreshMyStaleCerts) btnRefreshMyStaleCerts.addEventListener('click', loadMyStaleCerts);
const btnExportMyStaleCerts = document.getElementById('btn-export-mystalecerts');
if (btnExportMyStaleCerts) btnExportMyStaleCerts.addEventListener('click', function(e) { toggleExportMyStaleCertsDropdown(e); });
const btnExportMyStaleCertsCsv = document.getElementById('btn-export-mystalecerts-csv');
if (btnExportMyStaleCertsCsv) btnExportMyStaleCertsCsv.addEventListener('click', function() { document.getElementById('export-mystalecerts-dropdown').classList.remove('show'); exportMyStaleCertsCsv(); });
const btnExportMyStaleCertsJson = document.getElementById('btn-export-mystalecerts-json');
if (btnExportMyStaleCertsJson) btnExportMyStaleCertsJson.addEventListener('click', function() { document.getElementById('export-mystalecerts-dropdown').classList.remove('show'); exportMyStaleCertsJson(); });

document.getElementById('btn-report-only').addEventListener('click', triggerReportOnlyRun);
document.getElementById('btn-prod-run').addEventListener('click', triggerProdRun);
document.getElementById('btn-bulk-sponsors').addEventListener('click', function(e) { e.stopPropagation(); toggleBulkSponsorsDropdown(); });
document.getElementById('btn-bulk-upload-csv').addEventListener('click', triggerBulkUpload);
document.getElementById('btn-download-empty-csv').addEventListener('click', downloadEmptyCsv);
document.getElementById('btn-download-filled-csv').addEventListener('click', downloadFilledCsv);
document.getElementById('bulk-csv-file-input').addEventListener('change', handleBulkCsvUpload);
document.getElementById('btn-bulk-cancel').addEventListener('click', closeBulkSponsorModal);
document.getElementById('btn-bulk-apply').addEventListener('click', applyBulkSponsorUpdates);

// Applications tab filters
document.getElementById('app-search').addEventListener('input', debounce(applyFilters));
document.getElementById('app-sponsor-search').addEventListener('input', debounce(applyFilters));
document.getElementById('app-sort-by').addEventListener('change', applyFilters);
document.getElementById('app-sort-direction').addEventListener('change', applyFilters);
document.getElementById('btn-toggle-app-filters').addEventListener('click', toggleAppFilterPanel);
document.getElementById('btn-clear-app-filters').addEventListener('click', clearAppFilters);
document.getElementById('app-auto-rotate-filter-toggle').addEventListener('click', function (e) { toggleAppAutoRotateFilterDropdown(e); });
document.getElementById('app-auto-rotate-filter-dropdown').addEventListener('click', function (e) { e.stopPropagation(); });
document.querySelectorAll('.app-auto-rotate-filter-option-input').forEach(function (cb) { cb.addEventListener('change', onAppFilterChanged); });
document.getElementById('app-status-filter-toggle').addEventListener('click', function (e) { toggleAppStatusFilterDropdown(e); });
document.getElementById('app-status-filter-dropdown').addEventListener('click', function (e) { e.stopPropagation(); });
document.querySelectorAll('.app-status-filter-option-input').forEach(function (cb) { cb.addEventListener('change', onAppFilterChanged); });
document.getElementById('app-policy-type-filter-toggle').addEventListener('click', function (e) { toggleAppPolicyTypeFilterDropdown(e); });
document.getElementById('app-policy-type-filter-dropdown').addEventListener('click', function (e) { e.stopPropagation(); });
document.querySelectorAll('.app-policy-type-filter-option-input').forEach(function (cb) { cb.addEventListener('change', onAppFilterChanged); });

// Columns filter
document.getElementById('app-columns-filter-toggle').addEventListener('click', function (e) {
    e.stopPropagation();
    document.getElementById('app-columns-filter-dropdown').classList.toggle('show');
});
document.getElementById('app-columns-filter-dropdown').addEventListener('click', function (e) { e.stopPropagation(); });
document.querySelectorAll('.app-columns-filter-option-input').forEach(function (cb) { cb.addEventListener('change', updateColumnVisibility); });

// Edit policy modal
document.getElementById('btn-edit-policy-cancel').addEventListener('click', closeEditPolicyModal);
document.getElementById('btn-edit-policy-save').addEventListener('click', saveAppPolicy);

// Cleanup tab buttons
document.getElementById('btn-export-cleanup').addEventListener('click', function(e) { toggleExportCleanupDropdown(e); });
document.getElementById('btn-export-cleanup-csv').addEventListener('click', function() { document.getElementById('export-cleanup-dropdown').classList.remove('show'); exportCleanupListCsv(); });
document.getElementById('btn-export-cleanup-json').addEventListener('click', function() { document.getElementById('export-cleanup-dropdown').classList.remove('show'); exportCleanupListJson(); });
document.getElementById('btn-refresh-cleanup').addEventListener('click', loadCleanupData);

// Policy tab
document.getElementById('btn-save-policy').addEventListener('click', savePolicy);

// Reports tab
document.getElementById('btn-refresh-reports').addEventListener('click', loadReports);
document.getElementById('btn-back-to-reports').addEventListener('click', backToReportList);

// Audit tab
document.getElementById('btn-export-audit').addEventListener('click', function(e) { toggleExportAuditDropdown(e); });
document.getElementById('btn-export-audit-csv').addEventListener('click', function() { document.getElementById('export-audit-dropdown').classList.remove('show'); exportAuditLogCsv(); });
document.getElementById('btn-export-audit-json').addEventListener('click', function() { document.getElementById('export-audit-dropdown').classList.remove('show'); exportAuditLogJson(); });
document.getElementById('btn-refresh-audit').addEventListener('click', loadAuditLog);
document.getElementById('audit-from-date').addEventListener('change', loadAuditLog);
document.getElementById('audit-to-date').addEventListener('change', loadAuditLog);
document.getElementById('btn-toggle-audit-filters').addEventListener('click', toggleAuditFilterPanel);
document.getElementById('btn-clear-audit-filters').addEventListener('click', clearAuditFilters);
document.getElementById('audit-action-filter-toggle').addEventListener('click', function (e) { toggleAuditActionFilterDropdown(e); });
document.getElementById('audit-action-filter-dropdown').addEventListener('click', function (e) { e.stopPropagation(); });
document.querySelectorAll('.audit-action-filter-option-input').forEach(function (cb) { cb.addEventListener('change', onAuditActionFilterChanged); });
document.getElementById('audit-result-filter-toggle').addEventListener('click', function (e) { toggleAuditResultFilterDropdown(e); });
document.getElementById('audit-result-filter-dropdown').addEventListener('click', function (e) { e.stopPropagation(); });
document.querySelectorAll('.audit-result-filter-option-input').forEach(function (cb) { cb.addEventListener('change', onAuditResultFilterChanged); });
document.getElementById('audit-initiated-by-search').addEventListener('input', debounce(applyAuditFilters));
document.getElementById('audit-application-search').addEventListener('input', debounce(applyAuditFilters));
document.getElementById('audit-details-search').addEventListener('input', debounce(applyAuditFilters));
document.getElementById('audit-sort-by').addEventListener('change', applyAuditFilters);
document.getElementById('audit-sort-direction').addEventListener('change', applyAuditFilters);
document.getElementById('audit-columns-filter-toggle').addEventListener('click', function (e) {
    e.stopPropagation();
    document.getElementById('audit-columns-filter-dropdown').classList.toggle('show');
});
document.getElementById('audit-columns-filter-dropdown').addEventListener('click', function (e) { e.stopPropagation(); });
document.querySelectorAll('.audit-columns-filter-option-input').forEach(function (cb) { cb.addEventListener('change', updateAuditColumnVisibility); });

// Settings tab
document.getElementById('btn-save-settings').addEventListener('click', saveSettings);
document.getElementById('sponsorRemindersEnabled').addEventListener('change', toggleSponsorReminderSettings);
document.getElementById('sponsorReminderCount').addEventListener('change', toggleSponsorReminderCount);

// Confirm modal
document.getElementById('btn-modal-cancel').addEventListener('click', closeModal);
document.getElementById('modalConfirmBtn').addEventListener('click', confirmModalAction);

// Sponsor edit modal
document.getElementById('btn-add-sponsor-row').addEventListener('click', () => addSponsorRow(''));
document.getElementById('btn-sponsor-cancel').addEventListener('click', () => {
    document.getElementById('editSponsorModal').classList.remove('show');
    sponsorEditSponsorMode = false;
    sponsorEditSponsorState = { appId: null, appName: null };
});
document.getElementById('btn-sponsor-save').addEventListener('click', saveSponsorModal);

// Auth metadata button
document.getElementById('btn-view-auth-metadata')?.addEventListener('click', () => window.open('/.auth/me', '_blank'));

// Session timeout modal
document.getElementById('btn-timeout-signout').addEventListener('click', endAppSession);
document.getElementById('btn-timeout-renew').addEventListener('click', renewSession);

// ============================
// Testing Tab – Send Test Email
// ============================
let testEmailTemplates = [];

async function loadTestEmailTemplates() {
    const templateSelect = document.getElementById('testEmailTemplate');
    if (testEmailTemplates.length > 0) return; // already loaded

    try {
        const result = await apiCall('testing/email-templates');
        if (result && result.templates) {
            testEmailTemplates = result.templates;
            templateSelect.innerHTML = '<option value="">— Select a template —</option>';
            result.templates.forEach(t => {
                const opt = document.createElement('option');
                opt.value = t.name;
                opt.textContent = formatTemplateName(t.name);
                opt.dataset.description = t.description || '';
                templateSelect.appendChild(opt);
            });
        }
    } catch (err) {
        console.error('Failed to load test email templates:', err);
    }
}

function formatTemplateName(name) {
    const displayNames = {
        CertificateCreated: 'Certificate Created',
        CertificateActivated: 'Certificate Activated',
        Error: 'Error',
        DailySummary: 'Daily Summary',
        NotifyReminder: 'Reminders',
        SponsorExpirationExpired: 'Certificate Expiration',
        SponsorExpirationCritical: 'Manual Reminder – Critical',
        SponsorExpirationWarning: 'Manual Reminder – Warning',
        ConsolidatedSponsor: 'Sponsor Summary – Prod Runs'
    };
    return displayNames[name] || name.replace(/([A-Z])/g, ' $1').trim();
}

function updateTestEmailSendButton() {
    const btn = document.getElementById('btn-send-test-email');
    const template = document.getElementById('testEmailTemplate').value;
    const toEmail = document.getElementById('testEmailTo').value.trim();
    const ready = template && toEmail && toEmail.includes('@');

    if (ready) {
        btn.disabled = false;
        btn.style.background = '#0078d4';
        btn.style.color = 'white';
        btn.style.cursor = 'pointer';
    } else {
        btn.disabled = true;
        btn.style.background = '#d2d0ce';
        btn.style.color = '#666';
        btn.style.cursor = 'not-allowed';
    }
}

const testEmailExplanations = {
    CertificateCreated: {
        description: 'Sent to the app sponsor when a new certificate is created.',
        when: 'Sent automatically during the daily rotation run when an app\'s active certificate is within the "Create cert days before expiry" window and no newer inactive certificate exists. Also triggered when an admin manually creates a certificate from the dashboard.'
    },
    CertificateActivated: {
        description: 'Sent to the app sponsor when a certificate is activated.',
        when: 'Sent automatically during the daily rotation run when an app\'s active certificate is within the "Activate cert days before expiry" window and a newer inactive certificate is ready. Also triggered when an admin manually activates a certificate from the dashboard.'
    },
    Error: {
        description: 'Sent when a certificate operation fails.',
        when: 'Sent automatically during the daily rotation run if a certificate creation or activation operation throws an error. Includes the error details and affected application.'
    },
    DailySummary: {
        description: 'Daily rotation summary sent to admin notification recipients.',
        when: 'Sent automatically at the end of every daily rotation run (both production and report-only modes). Contains an overview of all SAML apps, stats, and a table of all actions taken during the run.'
    },
    NotifyReminder: {
        description: 'Expiration reminder for apps marked as Notify.',
        when: 'Sent automatically during the daily rotation run for apps with AutoRotate set to Notify. Triggered at the configurable sponsor reminder milestones (1st, 2nd, 3rd reminder days) as the active certificate approaches expiry. Each milestone is sent only once per certificate. Only fires when the certificate has not yet expired.'
    },
    SponsorExpirationExpired: {
        description: 'Sponsor notification for an expired certificate.',
        when: 'Sent automatically during the daily rotation run for apps (AutoRotate = On or Notify) whose active certificate has already expired. Also sent manually when an admin clicks "Resend Reminder" from the dashboard for an expired app. Sent only once per certificate automatically.'
    },
    SponsorExpirationCritical: {
        description: 'Sponsor notification for critical certificate status.',
        when: 'Sent manually only — triggered when an admin clicks "Resend Reminder" from the dashboard for an app whose active certificate is in Critical status (days remaining ≤ Activate cert days threshold). There is no automatic trigger for this template.'
    },
    SponsorExpirationWarning: {
        description: 'Sponsor notification for warning certificate status.',
        when: 'Sent manually only — triggered when an admin clicks "Resend Reminder" from the dashboard for an app whose active certificate is in Warning status (days remaining ≤ Create cert days threshold but above Activate cert days). There is no automatic trigger for this template.'
    },
    ConsolidatedSponsor: {
        description: 'Consolidated sponsor summary sent after production runs.',
        when: 'Sent automatically at the end of each Prod Run (timer-triggered or manual) when one or more certificate actions (Created, Created for Notify-App, Activated) were performed on apps that share the same sponsor. Groups all actions into a single email per sponsor rather than sending individual notifications.'
    }
};

document.getElementById('testEmailTemplate').addEventListener('change', () => {
    updateTestEmailSendButton();
    const select = document.getElementById('testEmailTemplate');
    const descEl = document.getElementById('testEmailTemplateDescription');
    const templateName = select.value;
    const info = testEmailExplanations[templateName];
    if (info) {
        descEl.innerHTML = `<strong>${info.description}</strong><br><span style="color:#555;">${info.when}</span>`;
    } else {
        descEl.innerHTML = '';
    }
});

document.getElementById('testEmailTo').addEventListener('input', updateTestEmailSendButton);

document.getElementById('btn-send-test-email').addEventListener('click', async () => {
    const template = document.getElementById('testEmailTemplate').value;
    const toEmail = document.getElementById('testEmailTo').value.trim();
    const statusEl = document.getElementById('testEmailStatus');
    const btn = document.getElementById('btn-send-test-email');

    if (!template || !toEmail) return;

    btn.disabled = true;
    btn.textContent = 'Sending...';
    btn.style.background = '#d2d0ce';
    btn.style.color = '#666';
    btn.style.cursor = 'not-allowed';
    statusEl.style.display = 'none';

    try {
        const result = await apiCall('testing/send-test-email', {
            method: 'POST',
            body: JSON.stringify({ template, toEmail })
        });

        statusEl.style.display = 'block';
        statusEl.style.background = '#dff6dd';
        statusEl.style.border = '1px solid #107c10';
        statusEl.style.color = '#107c10';
        statusEl.textContent = `✓ Test email "${formatTemplateName(template)}" sent to ${toEmail}`;
    } catch (err) {
        statusEl.style.display = 'block';
        statusEl.style.background = '#fde7e9';
        statusEl.style.border = '1px solid #d13438';
        statusEl.style.color = '#d13438';
        statusEl.textContent = `✗ Failed to send test email: ${err.message || 'Unknown error'}`;
    } finally {
        btn.textContent = 'Send';
        updateTestEmailSendButton();
    }
});

// Delegated event handler for dynamically rendered app table action buttons
document.addEventListener('click', function (e) {
    const btn = e.target.closest('[data-action]');
    if (!btn) return;
    const action = btn.dataset.action;
    const appId = btn.dataset.appId;
    const appName = btn.dataset.appName;
    switch (action) {
        case 'toggle-menu':
            toggleActionsMenu(e, btn.dataset.appIdToken);
            break;
        case 'create-cert':
            createNewCert(appId, appName);
            break;
        case 'activate-cert':
            activateNewestCert(appId, appName);
            break;
        case 'edit-sponsor':
            editSponsor(appId, appName, btn.dataset.sponsor || '');
            break;
        case 'edit-policy':
            editPolicy(appId, appName);
            break;
        case 'resend-reminder':
            resendReminderEmail(appId, appName);
            break;
        case 'sponsor-create-cert':
            sponsorCreateCert(appId, appName);
            break;
        case 'sponsor-activate-cert':
            sponsorActivateCert(appId, appName);
            break;
        case 'sponsor-edit-policy':
            sponsorEditPolicy(appId, appName);
            break;
        case 'sponsor-edit-sponsor':
            sponsorEditSponsor(appId, appName, btn.dataset.sponsor || '');
            break;
        case 'view-report':
            viewReport(btn.dataset.reportId);
            break;
    }
});

// Initial load
(async function initializeDashboard() {
    updateAuditActionFilterLabel();
    updateAppAutoRotateFilterLabel();
    updateAppStatusFilterLabel();
    updateAppPolicyTypeFilterLabel();
    setDefaultAuditDateRange();
    await loadCurrentUserRoles();
    if (!enforceRoleAccessOrRedirect()) {
        return;
    }
    applyRoleBasedAccess();
    if (!isSponsorOnly()) {
        loadData();
    }
})();
