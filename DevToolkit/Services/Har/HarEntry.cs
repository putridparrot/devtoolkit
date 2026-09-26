using System.Text;

namespace DevToolkit.Services.Har;

public sealed class HarEntry
{
    public int Index { get; set; }
    public string Method { get; set; } = string.Empty;
    public string Url { get; set; } = string.Empty;
    public string Host => Uri.TryCreate(Url, UriKind.Absolute, out var uri) ? uri.Host : string.Empty;
    public string Path => Uri.TryCreate(Url, UriKind.Absolute, out var uri) ? uri.AbsolutePath : Url;
    public int Status { get; set; }
    public string? StatusText { get; set; }
    public int Time { get; set; }
    public string MimeType { get; set; } = string.Empty;
    public double TransferSize { get; set; }
    public DateTime StartedDateTime { get; set; }
    public string? RequestBody { get; set; }
    public string? ResponseBody { get; set; }
    public string? ResponseBodyEncoding { get; set; }
    public List<HarHeader> RequestHeaders { get; } = new();
    public List<HarHeader> ResponseHeaders { get; } = new();

    /// <summary>The IP address the browser connected to (HAR <c>serverIPAddress</c>).</summary>
    public string? ServerIpAddress { get; set; }

    /// <summary>Browser network error for requests without a response, e.g. <c>net::ERR_TUNNEL_CONNECTION_FAILED</c> (Chrome <c>_error</c>).</summary>
    public string? Error { get; set; }

    public string? RedirectUrl { get; set; }

    /// <summary>Browser resource type such as document, xhr, fetch, script (Chrome <c>_resourceType</c>).</summary>
    public string? ResourceType { get; set; }

    public bool FromCache { get; set; }
    public HarTimings? Timings { get; set; }

    /// <summary>No response (status 0) or an HTTP error status.</summary>
    public bool IsFailure => Status == 0 || Status >= 400;

    public string? GetRequestHeader(string name) =>
        RequestHeaders.FirstOrDefault(h => h.Name.Equals(name, StringComparison.OrdinalIgnoreCase))?.Value;

    public string? GetResponseHeader(string name) =>
        ResponseHeaders.FirstOrDefault(h => h.Name.Equals(name, StringComparison.OrdinalIgnoreCase))?.Value;

    /// <summary>The response redirect target, from <c>redirectURL</c> or the Location header.</summary>
    public string? RedirectTarget =>
        !string.IsNullOrEmpty(RedirectUrl) ? RedirectUrl : GetResponseHeader("Location");

    /// <summary>The response body as text (decoding base64 content), truncated to <paramref name="maxLength"/> characters.</summary>
    public string GetResponseText(int maxLength = 64 * 1024)
    {
        if (string.IsNullOrEmpty(ResponseBody))
        {
            return string.Empty;
        }

        var text = ResponseBody;
        if (string.Equals(ResponseBodyEncoding, "base64", StringComparison.OrdinalIgnoreCase))
        {
            if (!IsTextMimeType(MimeType))
            {
                return string.Empty;
            }

            try
            {
                text = Encoding.UTF8.GetString(Convert.FromBase64String(ResponseBody));
            }
            catch (FormatException)
            {
                return string.Empty;
            }
        }

        return text.Length > maxLength ? text[..maxLength] : text;
    }

    private static bool IsTextMimeType(string mimeType) =>
        mimeType.StartsWith("text/", StringComparison.OrdinalIgnoreCase) ||
        mimeType.Contains("json", StringComparison.OrdinalIgnoreCase) ||
        mimeType.Contains("xml", StringComparison.OrdinalIgnoreCase) ||
        mimeType.Contains("javascript", StringComparison.OrdinalIgnoreCase);
}

public sealed class HarHeader
{
    public string Name { get; set; } = string.Empty;
    public string Value { get; set; } = string.Empty;
}

/// <summary>HAR timing phases in milliseconds; -1 means not applicable.</summary>
public sealed class HarTimings
{
    public double Blocked { get; set; } = -1;
    public double Dns { get; set; } = -1;
    public double Connect { get; set; } = -1;
    public double Ssl { get; set; } = -1;
    public double Send { get; set; } = -1;
    public double Wait { get; set; } = -1;
    public double Receive { get; set; } = -1;
}
