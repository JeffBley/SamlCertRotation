# SAML Certificate Rotation Tool

Automated SAML certificate lifecycle management for Microsoft Entra ID Enterprise Applications, with a web dashboard for monitoring, policy management, and manual operations.

## What This Does

- Rotates SAML signing certificates using a two-phase lifecycle (create, then activate).
- Supports report-only mode for safe validation before production changes.
- Provides Admin / Reader / Sponsor role-based dashboard access.
- Sends sponsor and admin notifications through Logic App + Office 365.
- Persists policies, audit logs, and run reports in Azure Table Storage.

## Architecture

This project is hosted as a serverless Azure stack:

- Static Web App (dashboard + auth)
- Azure Functions (.NET 8 API + timers)
- Microsoft Graph (SAML app/certificate operations)
- Table Storage (policy/audit/report persistence)
- Key Vault (secrets)
- Logic App (email dispatch)
- App Insights + Log Analytics (monitoring)

Detailed diagrams and runtime flows: [docs/AZURE_ARCHITECTURE.md](docs/AZURE_ARCHITECTURE.md)

## Quick Start

Full deployment guide: [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md)

### Prerequisites

- Azure subscription with **Owner** access
- Microsoft Entra ID with:
  - **Global Administrator**, or
  - **Application Administrator** + **Attribute Definition Administrator**
- Azure Cloud Shell (recommended) or local tools:
  - Azure CLI
  - .NET 8 SDK
  - Node.js 18+
  - Microsoft Graph PowerShell module

## Documentation Map

- Deployment walkthrough: [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md)
- Azure architecture diagrams/sequences: [docs/AZURE_ARCHITECTURE.md](docs/AZURE_ARCHITECTURE.md)
- API endpoints, settings, security notes, project structure: [docs/TECHNICAL_REFERENCE.md](docs/TECHNICAL_REFERENCE.md)
- Dashboard screenshots: [Screenshots.md](Screenshots.md)

## Feedback
If you'd like to report a bug, request a new feature, or provide general feedback, please fill out [this form](https://forms.microsoft.com/Pages/ResponsePage.aspx?id=v4j5cvGGr0GRqy180BHbRzJPxA9VE9lOj9XpVW39Gy9UOThENFFLMUY2UVZHNTRBQUFNNVNDWU05Ny4u).

## License

MIT
