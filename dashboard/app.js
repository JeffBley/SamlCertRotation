// Configuration
// Leave empty for same-origin (SWA linked backend), set for standalone API testing.
const API_BASE_URL = ''; // Leave empty for same-origin, or set to your Function App URL

// Store apps data for filtering
let allApps = [];
let allAuditEntries = [];
let nextAuditFilterId = 1;
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
const auditFilterColumns = [
    { value: 'application', label: 'Application' },
    { value: 'initiatedBy', label: 'Initiated By' },
    { value: 'result', label: 'Result' },
    { value: 'details', label: 'Details' }
];

// Current action for confirmation modal
let pendingAction = null;

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

function getSelectedAppAutoRotateFilters() {
    return Array.from(document.querySelectorAll('.app-auto-rotate-filter-option-input:checked'))
        .map(input => input.value);
}

function getSelectedAppStatusFilters() {
    return Array.from(document.querySelectorAll('.app-status-filter-option-input:checked'))
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
            if (value === 'notify') return 'Notify Only';
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

function onAppFilterChanged() {
    updateAppAutoRotateFilterLabel();
    updateAppStatusFilterLabel();
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
        const nameMatch = !searchTerm || (app.displayName || '').toLowerCase().includes(searchTerm);
        const sponsorMatch = !sponsorTerm || (app.sponsor || '').toLowerCase().includes(sponsorTerm);

        return autoRotateMatch && statusMatch && nameMatch && sponsorMatch;
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
            throw new Error(`API error: ${response.status}`);
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

    const tableHtml = `
        <table>
            <thead>
                <tr>
                    <th>Application</th>
                    <th>Sponsor</th>
                    <th>Auto-Rotate</th>
                    <th>Certificate Expiry</th>
                    <th>Days Remaining</th>
                    <th>Status</th>
                    <th style="width:60px;">Actions</th>
                </tr>
            </thead>
            <tbody>
                ${apps.map(app => {
                    const computedStatus = getComputedAppStatus(app);
                    const appIdToken = toDomIdToken(app.id, 'app');
                    const autoRotateStatusClass = toSafeClassToken(app.autoRotateStatus || 'null', 'null');
                    const computedStatusClass = toSafeClassToken(computedStatus, 'ok');
                    return `
                    <tr>
                        <td>${escapeHtml(app.displayName)}</td>
                        <td>${escapeHtml(app.sponsor) || 'Not Set'}</td>
                        <td>
                            <span class="status-badge status-${autoRotateStatusClass}">
                                ${((app.autoRotateStatus || '').toLowerCase() === 'notify') ? 'Notify Only' : (escapeHtml(app.autoRotateStatus) || 'Not Set')}
                            </span>
                        </td>
                        <td>${app.certExpiryDate ? new Date(app.certExpiryDate).toLocaleDateString() : 'N/A'}</td>
                        <td>${app.daysUntilExpiry ?? 'N/A'}</td>
                        <td>
                            <span class="expiry-badge expiry-${computedStatusClass}">
                                ${formatComputedStatus(computedStatus)}
                            </span>
                        </td>
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
    } catch (error) {
        console.error('Failed to load policy:', error);
    }
}

// Save policy settings
async function savePolicy() {
    try {
        const policy = {
            createCertDaysBeforeExpiry: parseInt(document.getElementById('createDays').value),
            activateCertDaysBeforeExpiry: parseInt(document.getElementById('activateDays').value),
            isEnabled: true
        };
        await apiCall('policy', {
            method: 'PUT',
            body: JSON.stringify(policy)
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
        document.getElementById('sponsorFirstReminderDays').value = Number.isInteger(settings.sponsorFirstReminderDays) ? settings.sponsorFirstReminderDays : 30;
        document.getElementById('sponsorSecondReminderDays').value = Number.isInteger(settings.sponsorSecondReminderDays) ? settings.sponsorSecondReminderDays : 7;
        document.getElementById('sponsorThirdReminderDays').value = Number.isInteger(settings.sponsorThirdReminderDays) ? settings.sponsorThirdReminderDays : 1;
        document.getElementById('notifySponsorsOnExpiration').value = settings.notifySponsorsOnExpiration === true ? 'enabled' : 'disabled';
        document.getElementById('sessionTimeoutMinutes').value = typeof settings.sessionTimeoutMinutes === 'number' ? settings.sessionTimeoutMinutes : 0;
        toggleSponsorReminderSettings();
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

        const sponsorFirstReminderDays = parseInt(document.getElementById('sponsorFirstReminderDays').value, 10);
        const sponsorSecondReminderDays = parseInt(document.getElementById('sponsorSecondReminderDays').value, 10);
        const sponsorThirdReminderDays = parseInt(document.getElementById('sponsorThirdReminderDays').value, 10);

        const reminderValues = [sponsorFirstReminderDays, sponsorSecondReminderDays, sponsorThirdReminderDays];
        const invalidReminderValue = reminderValues.some(value => !Number.isInteger(value) || value < 1 || value > 180);

        if (invalidReminderValue) {
            showError('Sponsor reminder values must be whole numbers between 1 and 180.');
            return;
        }

        const settings = {
            notificationEmails: document.getElementById('notificationEmails').value.trim(),
            reportOnlyModeEnabled: document.getElementById('reportOnlyMode').value === 'enabled',
            sponsorsReceiveNotifications: document.getElementById('sponsorsReceiveNotifications').value === 'enabled',
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
    const select = document.getElementById('sponsorsReceiveNotifications');
    const reminderContainer = document.getElementById('sponsor-reminder-settings');

    if (!select || !reminderContainer) {
        return;
    }

    reminderContainer.style.display = select.value === 'enabled' ? 'block' : 'none';
}

// Audit log filters and rendering
// Load audit log
async function loadAuditLog() {
    try {
        const fromDate = document.getElementById('audit-from-date')?.value;
        const toDate = document.getElementById('audit-to-date')?.value;

        let endpoint = 'audit?days=30';
        if (fromDate && toDate) {
            endpoint = `audit?from=${encodeURIComponent(fromDate)}&to=${encodeURIComponent(toDate)}`;
        }

        allAuditEntries = await apiCall(endpoint);
        applyAuditFilters();

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

function getAuditFilterPlaceholder(column) {
    if (column === 'result') return 'success or failed';
    if (column === 'time') return 'contains date/time text';
    return 'contains text';
}

function getAuditFieldValue(entry, column) {
    switch (column) {
        case 'time':
            return `${new Date(entry.timestamp || 0).toLocaleString()} ${entry.timestamp || ''}`;
        case 'application':
            return entry.appDisplayName || '';
        case 'initiatedBy':
            return entry.performedBy || 'System';
        case 'action':
            return entry.actionType || '';
        case 'result':
            return entry.isSuccess ? 'success' : 'failed';
        case 'details':
            return `${entry.description || ''} ${entry.errorMessage || ''}`;
        default:
            return '';
    }
}

function getUsedAuditColumns(excludeFilterId = null) {
    const rows = Array.from(document.querySelectorAll('#audit-dynamic-filters .audit-filter-row'));
    return rows
        .filter(row => row.dataset.filterId !== String(excludeFilterId))
        .map(row => row.querySelector('.audit-filter-column')?.value)
        .filter(Boolean);
}

function buildAuditColumnOptions(selectedColumn, excludeFilterId = null) {
    const usedColumns = new Set(getUsedAuditColumns(excludeFilterId));
    return auditFilterColumns.map(column => {
        const isSelected = column.value === selectedColumn;
        const isDisabled = usedColumns.has(column.value) && !isSelected;
        return {
            value: column.value,
            label: column.label,
            selected: isSelected,
            disabled: isDisabled
        };
    });
}

function populateAuditColumnOptions(select, selectedColumn, excludeFilterId = null) {
    if (!select) return;

    const options = buildAuditColumnOptions(selectedColumn, excludeFilterId);
    select.replaceChildren();

    options.forEach(optionDef => {
        const option = document.createElement('option');
        option.value = optionDef.value;
        option.textContent = optionDef.label;
        option.selected = optionDef.selected;
        option.disabled = optionDef.disabled;
        select.appendChild(option);
    });
}

function refreshAuditFilterColumnOptions() {
    const rows = Array.from(document.querySelectorAll('#audit-dynamic-filters .audit-filter-row'));
    rows.forEach(row => {
        const filterId = row.dataset.filterId;
        const select = row.querySelector('.audit-filter-column');
        const selectedColumn = select?.value || 'application';
        if (select) {
            populateAuditColumnOptions(select, selectedColumn, filterId);
        }
    });
}

function onAuditFilterColumnChanged(filterId) {
    const row = document.querySelector(`#audit-filter-row-${filterId}`);
    if (!row) return;

    const column = row.querySelector('.audit-filter-column')?.value || 'application';
    const input = row.querySelector('.audit-filter-value');
    if (input) {
        input.placeholder = getAuditFilterPlaceholder(column);
    }

    refreshAuditFilterColumnOptions();
    applyAuditFilters();
}

function addAuditFilterRow() {
    const usedColumns = new Set(getUsedAuditColumns());
    const firstAvailableColumn = auditFilterColumns.find(column => !usedColumns.has(column.value));

    if (!firstAvailableColumn) {
        showError('All available audit columns already have filters.');
        return;
    }

    const filterId = nextAuditFilterId++;
    const row = document.createElement('div');
    row.id = `audit-filter-row-${filterId}`;
    row.className = 'audit-filter-row';
    row.dataset.filterId = String(filterId);
    row.style.display = 'flex';
    row.style.gap = '8px';
    row.style.alignItems = 'center';

    const select = document.createElement('select');
    select.className = 'audit-filter-column';
    select.style.padding = '6px 10px';
    select.style.border = '1px solid #d2d0ce';
    select.style.borderRadius = '4px';
    populateAuditColumnOptions(select, firstAvailableColumn.value, filterId);
    select.addEventListener('change', () => onAuditFilterColumnChanged(filterId));

    const input = document.createElement('input');
    input.className = 'audit-filter-value';
    input.type = 'text';
    input.placeholder = getAuditFilterPlaceholder(firstAvailableColumn.value);
    input.style.padding = '6px 10px';
    input.style.border = '1px solid #d2d0ce';
    input.style.borderRadius = '4px';
    input.style.minWidth = '220px';
    input.addEventListener('input', () => applyAuditFilters());

    const removeButton = document.createElement('button');
    removeButton.className = 'btn btn-secondary';
    removeButton.textContent = 'Remove';
    removeButton.addEventListener('click', () => removeAuditFilterRow(filterId));

    row.appendChild(select);
    row.appendChild(input);
    row.appendChild(removeButton);

    document.getElementById('audit-dynamic-filters').appendChild(row);
    refreshAuditFilterColumnOptions();
    applyAuditFilters();
}

function removeAuditFilterRow(filterId) {
    const row = document.getElementById(`audit-filter-row-${filterId}`);
    if (row) {
        row.remove();
        refreshAuditFilterColumnOptions();
        applyAuditFilters();
    }
}

function clearAuditFilters() {
    document.getElementById('audit-dynamic-filters').innerHTML = '';
    document.querySelectorAll('.audit-action-filter-option-input').forEach(input => {
        input.checked = false;
    });
    updateAuditActionFilterLabel();
    applyAuditFilters();
}

function applyAuditFilters() {
    const sortBy = (document.getElementById('audit-sort-by')?.value || 'time').toLowerCase();
    const sortDirection = (document.getElementById('audit-sort-direction')?.value || 'desc').toLowerCase();
    const selectedActionFilters = getSelectedAuditActionFilters();

    const activeFilters = Array.from(document.querySelectorAll('#audit-dynamic-filters .audit-filter-row'))
        .map(row => {
            const column = row.querySelector('.audit-filter-column')?.value;
            const value = (row.querySelector('.audit-filter-value')?.value || '').trim().toLowerCase();
            return { column, value };
        })
        .filter(filter => filter.column && filter.value);

    let filtered = allAuditEntries.filter(entry => {
        const actionMatch = selectedActionFilters.length === 0 || selectedActionFilters.includes(entry.actionType || '');
        if (!actionMatch) {
            return false;
        }

        return activeFilters.every(filter => {
            const fieldValue = getAuditFieldValue(entry, filter.column).toLowerCase();

            if (filter.column === 'result') {
                if (filter.value === 'success') return entry.isSuccess === true;
                if (filter.value === 'failed') return entry.isSuccess === false;
            }

            return fieldValue.includes(filter.value);
        });
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

    const tableHtml = `
        <table>
            <thead>
                <tr>
                    <th>Time</th>
                    <th>Application</th>
                    <th>Initiated By</th>
                    <th>Action</th>
                    <th>Result</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
                ${entries.map(entry => `
                    <tr>
                        <td>${new Date(entry.timestamp).toLocaleString()}</td>
                        <td>${escapeHtml(entry.appDisplayName)}</td>
                        <td>${escapeHtml(entry.performedBy || 'System')}</td>
                        <td>${escapeHtml(entry.actionType)}</td>
                        <td>
                            <span class="status-badge ${entry.isSuccess ? 'status-on' : 'status-off'}">
                                ${entry.isSuccess ? 'Success' : 'Failed'}
                            </span>
                        </td>
                        <td>${escapeHtml(entry.description)}${entry.errorMessage ? ` - ${escapeHtml(entry.errorMessage)}` : ''}</td>
                    </tr>
                `).join('')}
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

// ── Event listener wiring (CSP-safe, no inline handlers) ──

// Header
document.getElementById('btn-sign-out').addEventListener('click', signOut);

// Applications tab buttons
document.getElementById('btn-export-apps').addEventListener('click', exportApplications);
document.getElementById('btn-refresh-apps').addEventListener('click', loadData);
document.getElementById('btn-report-only').addEventListener('click', triggerReportOnlyRun);
document.getElementById('btn-prod-run').addEventListener('click', triggerProdRun);

// Applications tab filters
document.getElementById('app-search').addEventListener('input', applyFilters);
document.getElementById('app-sponsor-search').addEventListener('input', applyFilters);
document.getElementById('app-sort-by').addEventListener('change', applyFilters);
document.getElementById('app-sort-direction').addEventListener('change', applyFilters);
document.getElementById('app-auto-rotate-filter-toggle').addEventListener('click', function (e) { toggleAppAutoRotateFilterDropdown(e); });
document.getElementById('app-auto-rotate-filter-dropdown').addEventListener('click', function (e) { e.stopPropagation(); });
document.querySelectorAll('.app-auto-rotate-filter-option-input').forEach(function (cb) { cb.addEventListener('change', onAppFilterChanged); });
document.getElementById('app-status-filter-toggle').addEventListener('click', function (e) { toggleAppStatusFilterDropdown(e); });
document.getElementById('app-status-filter-dropdown').addEventListener('click', function (e) { e.stopPropagation(); });
document.querySelectorAll('.app-status-filter-option-input').forEach(function (cb) { cb.addEventListener('change', onAppFilterChanged); });

// Cleanup tab buttons
document.getElementById('btn-export-cleanup').addEventListener('click', exportCleanupList);
document.getElementById('btn-refresh-cleanup').addEventListener('click', loadCleanupData);

// Policy tab
document.getElementById('btn-save-policy').addEventListener('click', savePolicy);

// Audit tab
document.getElementById('btn-refresh-audit').addEventListener('click', loadAuditLog);
document.getElementById('audit-from-date').addEventListener('change', loadAuditLog);
document.getElementById('audit-to-date').addEventListener('change', loadAuditLog);
document.getElementById('audit-action-filter-toggle').addEventListener('click', function (e) { toggleAuditActionFilterDropdown(e); });
document.getElementById('audit-action-filter-dropdown').addEventListener('click', function (e) { e.stopPropagation(); });
document.querySelectorAll('.audit-action-filter-option-input').forEach(function (cb) { cb.addEventListener('change', onAuditActionFilterChanged); });
document.getElementById('btn-add-audit-filter').addEventListener('click', addAuditFilterRow);
document.getElementById('btn-clear-audit-filters').addEventListener('click', clearAuditFilters);
document.getElementById('audit-sort-by').addEventListener('change', applyAuditFilters);
document.getElementById('audit-sort-direction').addEventListener('change', applyAuditFilters);

// Settings tab
document.getElementById('btn-save-settings').addEventListener('click', saveSettings);
document.getElementById('sponsorsReceiveNotifications').addEventListener('change', toggleSponsorReminderSettings);

// Confirm modal
document.getElementById('btn-modal-cancel').addEventListener('click', closeModal);
document.getElementById('modalConfirmBtn').addEventListener('click', confirmModalAction);

// Session timeout modal
document.getElementById('btn-timeout-signout').addEventListener('click', endAppSession);
document.getElementById('btn-timeout-renew').addEventListener('click', renewSession);

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
    setDefaultAuditDateRange();
    await loadCurrentUserRoles();
    if (!enforceRoleAccessOrRedirect()) {
        return;
    }
    applyRoleBasedAccess();
    loadData();
})();
