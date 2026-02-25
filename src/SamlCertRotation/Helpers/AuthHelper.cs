using System.Text;
using Microsoft.Azure.Functions.Worker.Http;

namespace SamlCertRotation.Helpers;

/// <summary>
/// Shared authentication utility methods used by DashboardFunctions and RoleFunctions.
/// </summary>
public static class AuthHelper
{
    /// <summary>
    /// Reads header values with a case-insensitive fallback scan.
    /// </summary>
    public static string? GetHeaderValue(HttpRequestData req, string headerName)
    {
        if (req.Headers.TryGetValues(headerName, out var values))
        {
            var value = values.FirstOrDefault();
            if (!string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        foreach (var header in req.Headers)
        {
            if (!string.Equals(header.Key, headerName, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var value = header.Value?.FirstOrDefault();
            if (!string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        return null;
    }

    /// <summary>
    /// Decodes URL-safe base64 principal payloads and returns JSON text when valid.
    /// </summary>
    public static string? DecodePrincipalPayload(string payload)
    {
        if (string.IsNullOrWhiteSpace(payload))
        {
            return null;
        }

        var decoded = Uri.UnescapeDataString(payload.Trim());
        try
        {
            return Encoding.UTF8.GetString(Convert.FromBase64String(NormalizeBase64(decoded)));
        }
        catch
        {
            if (decoded.StartsWith("{", StringComparison.Ordinal) || decoded.StartsWith("[", StringComparison.Ordinal))
            {
                return decoded;
            }

            return null;
        }
    }

    /// <summary>
    /// Normalizes URL-safe base64 into standard padded base64.
    /// </summary>
    public static string NormalizeBase64(string value)
    {
        var normalized = value.Replace('-', '+').Replace('_', '/');
        var padding = normalized.Length % 4;
        if (padding > 0)
        {
            normalized = normalized.PadRight(normalized.Length + (4 - padding), '=');
        }

        return normalized;
    }
}
