namespace SamlCertRotation.Helpers;

/// <summary>
/// Shared URL-building helpers used across services and functions.
/// </summary>
public static class UrlHelper
{
    /// <summary>
    /// Builds a deep-link to the managed app SAML sign-on blade in Entra admin center.
    /// </summary>
    public static string BuildEntraManagedAppUrl(string servicePrincipalObjectId, string appId)
    {
        return $"https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/SignOn/objectId/{Uri.EscapeDataString(servicePrincipalObjectId)}/appId/{Uri.EscapeDataString(appId)}/preferredSingleSignOnMode/saml/servicePrincipalType/Application/fromNav/";
    }
}
