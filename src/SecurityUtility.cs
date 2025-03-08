using System;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

public static class SecurityUtility
{
    private static string SecretKey = "supersecretkey";

    /// <summary>
    /// Creates a SAS token url. Note that permissions can be set via bit-shifting if you want multiple permissions,
    /// so for example, Read, Write, Delete would be (SasPermissions.Read | SasPermissions.Write | SasPermissions.Delete).
    /// </summary>
    /// <param name="resourceUri">The base URI to be used.</param>
    /// <param name="permissions">The SasPermissions for the Url.</param>
    /// <param name="expiry">The expiration timespan of the Url in minutes.</param>
    /// <param name="payload">The payload to use in the signature.</param>
    /// <returns>A SAS url with token created with data provided.</returns>
    public static string CreateSasTokenUrl(string resourceUri, SasPermissions permissions, TimeSpan expiry, string payload)
    {
        string expiryTimeString = DateTimeOffset.UtcNow
            .Add(expiry)
            .ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture);

        string signature = GetHmacSignature(
            SecretKey,
            permissions,
            expiry,
            resourceUri,
            payload);

        return $"{resourceUri}?sp={(int)permissions}&se={expiryTimeString}&payload={payload}&sig={Uri.EscapeDataString(signature)}";
    }

    public static bool ValidateSasTokenUrl(string sasTokenUrl, string resourceUri, SasPermissions permissions, string payload)
    {
        var uri = new Uri(sasTokenUrl);
        var queryParams = System.Web.HttpUtility.ParseQueryString(uri.Query);

        if (!int.TryParse(queryParams["sp"], out int tokenPermissions) || tokenPermissions != (int)permissions)
        {
            return false;
        }

        string tokenExpiry = queryParams["se"];
        string tokenpayload = queryParams["payload"];
        string tokenSignature = queryParams["sig"];

        if (tokenpayload != payload)
        {
            return false;
        }

        if (tokenExpiry == null)
        {
            return false;
        }

        var timeSpan = DateTime.Parse(tokenExpiry) - DateTimeOffset.UtcNow;

        string expectedSignature = GetHmacSignature(
            SecretKey,
            permissions,
            timeSpan,
            resourceUri,
            payload);

        return tokenSignature == expectedSignature;
    }

    public static string GetHmacSignature(
        string secretKey,
        SasPermissions permissions,
        TimeSpan expiry,
        string resourceUri,
        string payload)
    {
        string expiryTimeString = DateTime.UtcNow
            .Add(expiry)
            .ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture);
        string stringToSign = $"{(int)permissions}\n{expiryTimeString}\n{resourceUri}\n{payload}\n{secretKey}";
        return CreateHmacSignature(stringToSign, secretKey);
    }

    internal static string CreateHmacSignature(string stringToSign, string key)
    {
        using (var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(key)))
        {
            byte[] dataToHmac = Encoding.UTF8.GetBytes(stringToSign);
            return Convert.ToBase64String(hmac.ComputeHash(dataToHmac));
        }
    }
}