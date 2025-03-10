using System;
using System.Linq;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Internal;

namespace MyConsoleApp
{
    class Program
    {
        static void Main(string[] args)
        {
            // Generate a valid SAS Url
            var sasUrl = SecurityUtility.CreateSasTokenUrl(
                    "https://www.example.com/api/",
                    SasPermissions.Read,
                    TimeSpan.FromMinutes(5),
                    "MyPayload");

            // Simulate an HttpRequest coming in to some API endpoint
            var request = CreateHttpRequestFromUrl(sasUrl);

            // Extract the components of the SAS Url
            var sasLinkComponents = GetSasUrlComponents(request);

            PrintSasUrlComponents(sasLinkComponents);

            // Optional check on permissions to demonstrate bit shifting
            Console.WriteLine("Permissions Checking:");
            Console.WriteLine($"Permissions Binary: {ConvertToBinaryString(sasLinkComponents.Permissions)}");
            Console.WriteLine($"Has Read Permission Binary: {ConvertToBinaryString(sasLinkComponents.Permissions & (int)SasPermissions.Read)}");
            var hasReadPermissions = HasPermission(sasLinkComponents.Permissions, SasPermissions.Read);
            Console.WriteLine($"Has Read Permissions: {hasReadPermissions}");
            Console.WriteLine($"Has Write Permission Binary: {ConvertToBinaryString((int)SasPermissions.Write)}");
            var hasWritePermissions = HasPermission(sasLinkComponents.Permissions, SasPermissions.Write);
            Console.WriteLine($"Has Write Permissions: {hasWritePermissions}");
            Console.WriteLine($"Has Read and Write permissions Binary: {ConvertToBinaryString((int)(SasPermissions.Read | SasPermissions.Write))}");
            var hasReadWritePermissions = HasPermission(sasLinkComponents.Permissions, SasPermissions.Read | SasPermissions.Write);
            Console.WriteLine($"Has Read and Write Permissions: {hasReadWritePermissions}");
            Console.WriteLine("****************************************");


            // Validate the Url
            var isValid = SecurityUtility.ValidateSasTokenUrl(
                sasLinkComponents.Url,
                "https://www.example.com/api/",
                (SasPermissions)sasLinkComponents.Permissions,
                sasLinkComponents.Payload);

            Console.WriteLine("Validation Checks:");
            Console.WriteLine($"Valid Sas Url: {sasUrl}");
            Console.WriteLine($"Is valid: {isValid}");

            // Alter the Url so the payload is different and thus invalid
            sasUrl = sasUrl.Replace("MyPayload", "HaxxoredPayload");

            Console.WriteLine($"Altered Sas Url: {sasUrl}");

            request = CreateHttpRequestFromUrl(sasUrl);
            sasLinkComponents = GetSasUrlComponents(request);

            // Attempt to validate the altered Url
            isValid = SecurityUtility.ValidateSasTokenUrl(
                sasLinkComponents.Url,
                "https://www.example.com/api/",
                (SasPermissions)sasLinkComponents.Permissions,
                sasLinkComponents.Payload);

            Console.WriteLine($"Is valid: {isValid}");
        }

        private static SasLinkComponents GetSasUrlComponents(HttpRequest request)
        {
            var url = $"{request.Scheme}://{request.Host}{request.Path}{request.QueryString}";
            var payload = request.Query["payload"].ToString();
            var expirationString = request.Query["se"].ToString();
            var permissions = int.Parse(request.Query["sp"].ToString());

            return new SasLinkComponents
            {
                Url = url,
                Payload = payload,
                Expiration = expirationString,
                Permissions = permissions
            };
        }

        // Helper functions for demonstration purposes

        private static string GetSasPermissionsString(int permissions)
        {
            var result = Enum.GetValues(typeof(SasPermissions))
                             .Cast<SasPermissions>()
                             .Where(p => (permissions & (int)p) != 0)
                             .Select(p => p.ToString());

            return string.Join(", ", result);
        }

        private static HttpRequest CreateHttpRequestFromUrl(string url)
        {
            var uri = new Uri(url);
            var context = new DefaultHttpContext();
            var request = context.Request;

            request.Scheme = uri.Scheme;
            request.Host = new HostString(uri.Host, uri.Port);
            request.Path = uri.AbsolutePath;
            request.QueryString = new QueryString(uri.Query);

            var query = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(uri.Query);
            foreach (var kvp in query)
            {
                request.Query = new QueryCollection(query);
            }

            return request;
        }

        private static void PrintSasUrlComponents(SasLinkComponents sasLinkComponents)
        {
            Console.WriteLine("SAS Url Components:");
            Console.WriteLine($"Url: {sasLinkComponents.Url}");
            Console.WriteLine($"Payload: {sasLinkComponents.Payload}");
            Console.WriteLine($"Expiration: {sasLinkComponents.Expiration}");
            Console.WriteLine($"Permissions: {GetSasPermissionsString(sasLinkComponents.Permissions)}");
            Console.WriteLine("****************************************");
        }

        private static string ConvertToBinaryString(int number)
        {
            return Convert.ToString(number, 2).PadLeft(32, '0');
        }

        private static bool HasPermission(int permissions, SasPermissions permissionToCheck)
        {
            return (permissions & (int)permissionToCheck) == (int)permissionToCheck;
        }
    }
}