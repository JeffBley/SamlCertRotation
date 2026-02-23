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
const ADMIN_APP_ROLE_VALUE = 'SamlCertRotation.Admin';
const READER_APP_ROLE_VALUE = 'SamlCertRotation.Reader';

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
    return div.innerHTML;
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

        currentUserRoles = [...new Set(normalizedRoles)];
        currentUserUpn = principal?.userDetails || '';
    } catch {
        currentUserRoles = [];
        currentUserUpn = '';
    }
}

function hasDashboardAccess() {
    return currentUserRoles.includes('admin') || currentUserRoles.includes('reader');
}

function applyRoleBasedAccess() {
    // Display UPN
    const upnEl = document.getElementById('user-upn');
    if (upnEl) upnEl.textContent = currentUserUpn;

    const readOnly = !isAdminUser();

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
        await loadData();
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
        await loadData();
    } catch (error) {
        showError(`Failed to activate certificate: ${error.message}`);
    }
}

// Edit sponsor tag for an app
async function editSponsor(appId, appName, currentSponsor) {
    closeAllDropdowns();

    const enteredValue = prompt(`Enter sponsor email for ${appName}:`, currentSponsor || '');
    if (enteredValue === null) {
        return;
    }

    const sponsorEmail = enteredValue.trim();
    if (!sponsorEmail) {
        showError('Sponsor email is required.');
        return;
    }

    const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailPattern.test(sponsorEmail)) {
        showError('Please enter a valid sponsor email address.');
        return;
    }

    try {
        showLoading('Updating sponsor...');
        await apiCall(`applications/${appId}/sponsor`, {
            method: 'PUT',
            body: JSON.stringify({ sponsorEmail })
        });
        showSuccess(`Sponsor updated for ${appName}`);
        await loadData();
    } catch (error) {
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
        await apiCall(`policy/app/${editPolicyAppId}`, {
            method: 'PUT',
            body: JSON.stringify({
                appDisplayName: editPolicyAppName,
                createCertDaysBeforeExpiry: createDays,
                activateCertDaysBeforeExpiry: activateDays,
                createCertsForNotifyOverride: createCertsForNotifyOverride
            })
        });
        showSuccess(`Policy updated for ${editPolicyAppName}`);
        await loadData();
    } catch (error) {
        showError(`Failed to update app policy: ${error.message}`);
    }
}

function closeEditPolicyModal() {
    document.getElementById('editPolicyModal').classList.remove('show');
    editPolicyAppId = null;
    editPolicyAppName = null;
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
            await loadData();
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
            loadAuditLog();
        } else if (tab.dataset.tab === 'policy') {
            loadPolicy();
        } else if (tab.dataset.tab === 'settings') {
            loadSettings();
        } else if (tab.dataset.tab === 'cleanup') {
            loadCleanupData();
        } else if (tab.dataset.tab === 'testing') {
            loadTestEmailTemplates();
        }
    });
});

// API and state-loading helpers
// API helper
async function apiCall(endpoint, options = {}) {
    try {
        const method = (options.method || 'GET').toUpperCase();
        if (method !== 'GET' && !isAdminUser()) {
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
async function loadData() {
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
        document.getElementById('stat-expiring-30').textContent = stats.appsExpiringIn30Days;
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

    } catch (error) {
        document.getElementById('apps-table-container').innerHTML = 
            `<div class="error">Failed to load data: ${escapeHtml(error.message)}</div>`;
    }
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
                    const appIdToken = toDomIdToken(app.id, 'app');
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
async function loadPolicy() {
    try {
        const policy = await apiCall('policy');
        document.getElementById('createDays').value = policy.createCertDaysBeforeExpiry;
        document.getElementById('activateDays').value = policy.activateCertDaysBeforeExpiry;

        const settings = await apiCall('settings');
        document.getElementById('createCertsForNotifyApps').value = settings.createCertsForNotifyApps === false ? 'disabled' : 'enabled';
    } catch (error) {
        console.error('Failed to load policy:', error);
    }
}

// Save policy settings
async function savePolicy() {
    try {
        const createDays = parseInt(document.getElementById('createDays').value);
        const activateDays = parseInt(document.getElementById('activateDays').value);

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
    } catch (error) {
        showError('Failed to save policy: ' + error.message);
    }
}

// Load settings
async function loadSettings() {
    try {
        const settings = await apiCall('settings');
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
        toggleSponsorReminderSettings();
        toggleSponsorReminderCount();
    } catch (error) {
        console.error('Failed to load settings:', error);
    }
}

// Format CRON schedule to human-readable string
function formatCronSchedule(cron) {
    // CRON format: second minute hour dayOfMonth month dayOfWeek
    const parts = cron.split(' ');
    if (parts.length !== 6) return cron;
    
    const hour = parseInt(parts[2]);
    const minute = parseInt(parts[1]);
    
    // Check if it's a daily schedule
    if (parts[3] === '*' && parts[4] === '*' && parts[5] === '*') {
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
            sessionTimeoutMinutes: parseInt(document.getElementById('sessionTimeoutMinutes').value, 10) || 0
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

// Audit log filters and rendering
// Load audit log
async function loadAuditLog() {
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

// Load certificate cleanup data
async function loadCleanupData() {
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
function exportCleanupList() {
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

// Export currently visible applications to JSON
function exportApplications() {
    // Get current filter state to export only visible apps
    const searchTerm = (document.getElementById('app-search')?.value || '').trim().toLowerCase();
    const selectedAutoRotateFilters = getSelectedAppAutoRotateFilters();
    const selectedStatusFilters = getSelectedAppStatusFilters();

    const filteredApps = getFilteredApps();

    if (filteredApps.length === 0) {
        showError('No applications to export');
        return;
    }
    
    const exportData = {
        exportDate: new Date().toISOString(),
        exportType: 'saml-applications',
        filters: {
            search: searchTerm,
            autoRotate: selectedAutoRotateFilters,
            status: selectedStatusFilters
        },
        totalApps: filteredApps.length,
        applications: filteredApps.map(app => ({
            displayName: app.displayName,
            id: app.id,
            sponsor: app.sponsor,
            autoRotateStatus: app.autoRotateStatus,
            certExpiryDate: app.certExpiryDate,
            daysUntilExpiry: app.daysUntilExpiry,
            expiryCategory: app.expiryCategory
        }))
    };
    
    downloadJson(exportData, `saml-applications-${formatDateForFilename()}.json`);
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
            // Basic email validation
            if (!newSponsor.includes('@') || !newSponsor.includes('.')) {
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
document.getElementById('btn-export-apps').addEventListener('click', exportApplications);
document.getElementById('btn-refresh-apps').addEventListener('click', loadData);
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
document.getElementById('app-search').addEventListener('input', applyFilters);
document.getElementById('app-sponsor-search').addEventListener('input', applyFilters);
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
document.getElementById('btn-export-cleanup').addEventListener('click', exportCleanupList);
document.getElementById('btn-refresh-cleanup').addEventListener('click', loadCleanupData);

// Policy tab
document.getElementById('btn-save-policy').addEventListener('click', savePolicy);

// Audit tab
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
document.getElementById('audit-initiated-by-search').addEventListener('input', applyAuditFilters);
document.getElementById('audit-application-search').addEventListener('input', applyAuditFilters);
document.getElementById('audit-details-search').addEventListener('input', applyAuditFilters);
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
        const result = await apiCall('/testing/email-templates');
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
    // CertificateCreated -> Certificate Created, SponsorExpirationExpired -> Sponsor Expiration Expired
    return name.replace(/([A-Z])/g, ' $1').trim();
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
        const result = await apiCall('/testing/send-test-email', {
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
    loadData();
})();
