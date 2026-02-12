namespace SamlCertRotation.Models;

/// <summary>
/// Request model for updating settings
/// </summary>
public class SettingsUpdateRequest
{
    /// <summary>
    /// Comma-separated list of notification email addresses
    /// </summary>
    public string? NotificationEmails { get; set; }
}
