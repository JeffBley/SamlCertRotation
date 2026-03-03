# Operationalize the SAML Dashboard

This runbook is for post-deployment operational setup of the SAML Certificate Rotation Dashboard.

## Goal

Move from a newly deployed solution to a controlled production operating model by:

1. Deciding sponsor source and management plane
2. Configuring global rotation policy and operational settings
3. Populating sponsor ownership data at scale
4. Classifying SAML apps with Custom Security Attribute (CSA) values
5. Switching run mode from report-only to production

---

## Recommended Rollout Sequence

- **Week 0 (safe mode):** Keep **Run Mode = Report-only**, configure settings, populate sponsors, set CSA values.
- **Week 1 (validation):** Run report-only on demand and review results with app owners.
- **Week 2 (go-live):** Switch to **Production** only after sponsor coverage and CSA tagging are complete.

---
## 1) Decide on Sponsor Source and Management Plane

Consider the following questions:
- Who should handle SAML App certification rotation? App Sponsor vs Central team
- Which interface should the admin/sponsor primarily use to manage the certificates? App portal vs Entra ID
- Do you want to use Entra ID email notifications where possible and send additional notifications only if needed? Should all cert-related notifications come from the same source? Sponsor source as custom tag vs built-in Notification Email


## 2) Configure Global Rotation Policy and Settings

Based on your decisions from section #1, configure the app with appropriate settings. 

### Field-by-field considerations

Navigate to **Policy Settings** → **Global Rotation Policy**.

| Field | What it controls | Recommended starting point | Considerations |
|---|---|---|---|
| **Create Certificate Threshold (days)** | When a new cert is generated before expiry | `60` | Set high enough for app owner lead time and change windows. Must be greater than Activate threshold. |
| **Activate Certificate Threshold (days)** | When newest cert is made active | `30` | Leave room for testing and rollback. For tightly controlled apps, use a larger gap from create threshold. |
| **New certificate lifespan (days)** | Validity length for newly generated certs | `1095` (about 3 years) | Shorter lifespan improves cryptographic hygiene but increases operational cadence. Align with internal PKI/security policy. |
| **Auto-Create Certificates for Notify Apps** | For apps tagged `Notify`, whether to pre-create certs (without activating) | Enabled (default) | By enabling this setting, the scheduled runs will pre-create the SAML certs for apps that don't support auto-rotation. App Sponsors can then manually download and activate the cert when ready. |

<br />
<br />

Navigate to **Settings** → **Notification Settings**.
| Field | What it controls | Recommended value | Considerations |
|---|---|---|---|
| **Daily Summary Recipients** | Who receives daily run summary emails | Ops/security shared mailbox(es) | Use group aliases instead of individuals; separate addresses with commas. |
| **Notify Sponsors on Certificate Changes** | Sends sponsor emails when certs are created/activated | **Enabled** | Recommended for transparency; applies to apps configured for `On` or `Notify`. |
| **Pre-Expiry Reminders (Notify Apps)** | Sends reminder emails before certificate expiry | **Enabled** | Core control for `Notify` apps; disable only if reminders are handled elsewhere. Consider disabling is using Entra ID notification email as sponsor source to avoid duplicate notifications. |
| **Number of Reminders** | Number of pre-expiry reminder events | `3` | `1` is minimal noise; `3` provides better escalation path. |
| **1st / 2nd / 3rd reminder (days before expiry)** | Timing of reminder sequence | `60 / 30 / 7` | Keep values descending and operationally meaningful for owner response windows. |
| **Notify Sponsors After Certificate Expiry** | Sends one-time post-expiry notification | **Enabled** | Useful for escalation and incident visibility. |
| **Stale Certificate Cleanup Reminders** | Sends consolidated reminders for expired inactive certs | **Enabled** | Helps keep old cert inventory clean; pair with periodic owner follow-up. |

<br />
<br />

Navigate to **Settings** → **Automation Schedule**.
| Field | What it controls | Recommended value | Considerations |
|---|---|---|---|
| **Audit Log Retention (days)** | How long audit entries are kept | `180` | Increase for stricter compliance needs; validate storage impact. |
| **Run Reports Retention (days)** | How long run report payloads are kept | `14` | Increase if teams need longer troubleshooting history. |

Navigate to **Settings** → **Run Settings**.
| Field | What it controls | Recommended value | Considerations |
|---|---|---|---|
| **Run Mode** | Whether automation is simulation or active | **Report-only** during onboarding | Switch to **Production** only after a sufficient number of apps are popluated with sponsor and Custom Security Attribute data. |
| **Sponsor Source** | Where sponsor emails are read/stored | `Entra ID` if already maintained; else `Custom App Tags` | Choose one source of truth and avoid mixed ownership patterns. Note: Entra ID already sends notification emails to the Notification Emails if populated. |

<br />
<br />

Navigate to **Settings** → **Security**.
| Field | What it controls | Recommended value | Considerations |
|---|---|---|---|
| **Idle Session Timeout (minutes)** | Inactivity window before re-prompt/sign-out behavior | `15` | Set lower for privileged admin environments; `0` disables timeout. |
| **Allow Sponsors to Create Certificates** | Sponsor ability to generate new certs | **Enabled** | Disabled by default. Enable after sponsor training and SOP readiness. |
| **Allow Sponsors to Activate Certificates** | Sponsor ability to activate newest cert | **Enabled** | Disabled by default - highest-impact sponsor action. Enable after sponsor training and SOP readiness. |
| **Allow Sponsors to Edit Rotation Policy** | Sponsor ability to change app-level policy thresholds | **Disabled** | Allows sponsors to set the `Cert Creation`, `Cert Activation`, `New Cert Lifespan`, and `Auto-create for Notify Apps` settings to app-specific values, overriding the global settings. |
| **Allow Sponsors to Manage Sponsors** | Sponsor ability to add/remove sponsor ownership | Depends | Enable for enabling self-service sponsor updates; disable for centralized control of sponsor fields. Enabled by default. |

---

## 3) Populate Sponsors at Scale (in Tandem with Step 4)

In order to properly notify sponsors, you must ensure you have identified and stored the person's email address in Entra ID on the appropriate application.

### Workflow

1. In **Applications**, use **Export** (CSV/JSON) to identify apps with missing sponsor
2. Use **Bulk update sponsors**:
   - **Download filled CSV** then add sponsors to the existing apps
3. Upload via **Bulk Update Sponsors - CSV upload**
4. Re-export and verify missing-sponsor count is trending down

### Data quality checks

- No shared personal mailboxes unless intentionally used for support coverage
- Use team-owned aliases where possible
- Validate sponsor addresses for critical apps first

---

## 4) Set CSA Values on SAML Apps (in Tandem with Step 3)

Review and classify your SAML apps using your configured Custom Security Attributes.

### Practical approach

- Start broad with **Notify** to establish ownership and communications
- Promote to **On** app-by-app after validation with sponsors and app teams
- Track remaining **Not Set** and **Off** apps as explicit backlog/governance items

---

## 5) Cut Over to Production Run Mode

When sponsor coverage and CSA tagging are complete:

1. Navigate to **Settings** → **Run Settings**
2. Change **Run Mode** from **Report-only** to **Production**
3. Save settings
4. Trigger one controlled **Run - Prod**
5. Review **Reports** and **Audit Log** for any failed actions

### Production readiness checklist

- [ ] Global policy values approved
- [ ] Sponsor source selected and applied consistently
- [ ] Notification settings finalized
- [ ] Sponsor population complete 
- [ ] CSA classification complete 
- [ ] Report-only results validated across representative app sets

---

## Ongoing Operations (After Go-Live)

- Review **Reports** after each run for failures/skips
- Monitor **Audit Log** for drift and unauthorized changes
- Periodically export app inventory and reconcile missing sponsors/CSA gaps
- Revisit policy thresholds quarterly or after major app portfolio changes
- Monitor expired certificates and update sponsorship as needed.

---