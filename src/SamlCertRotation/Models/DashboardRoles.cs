namespace SamlCertRotation.Models;

/// <summary>
/// Centralized role name constants used across the application.
/// To add a new role, define a new constant here and update:
///   1. RoleFunctions.cs — role assignment logic
///   2. DashboardFunctions.AuthorizeRequestAsync — authorization checks
///   3. dashboard/index.html — JS role constants and UI gating
/// </summary>
public static class DashboardRoles
{
    /// <summary>Full administrative access — can modify settings, run rotations, create/activate certs</summary>
    public const string Admin = "admin";

    /// <summary>Read-only access — can view apps, audit logs, settings</summary>
    public const string Reader = "reader";

    /// <summary>Sponsor access — can view their own sponsored apps, optionally create/activate certs</summary>
    public const string Sponsor = "sponsor";

    /// <summary>Base role assigned by SWA to any logged-in user</summary>
    public const string Authenticated = "authenticated";
}
