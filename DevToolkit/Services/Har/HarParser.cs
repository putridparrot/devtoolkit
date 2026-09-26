using System.Text.Json;

namespace DevToolkit.Services.Har;

public static class HarParser
{
    /// <summary>Parses HAR JSON into entries. Throws <see cref="FormatException"/> if there is no <c>log.entries</c>.</summary>
    public static List<HarEntry> Parse(string json)
    {
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;

        if (!root.TryGetProperty("log", out var log) || !log.TryGetProperty("entries", out var entriesElement))
        {
            throw new FormatException("Invalid HAR format. Could not find 'log.entries' in the JSON.");
        }

        var entries = new List<HarEntry>();
        foreach (var entry in entriesElement.EnumerateArray())
        {
            var request = entry.GetProperty("request");
            var response = entry.GetProperty("response");

            var harEntry = new HarEntry
            {
                Index = entries.Count,
                Method = request.GetProperty("method").GetString() ?? string.Empty,
                Url = request.GetProperty("url").GetString() ?? string.Empty,
                Status = response.GetProperty("status").GetInt32(),
                StatusText = GetString(response, "statusText"),
                Time = entry.TryGetProperty("time", out var timeElement) ? (int)timeElement.GetDouble() : 0,
                MimeType = response.TryGetProperty("content", out var content) ? GetString(content, "mimeType") ?? string.Empty : string.Empty,
                TransferSize = entry.TryGetProperty("_transferSize", out var transfer) ? transfer.GetDouble() : 0,
                ServerIpAddress = GetString(entry, "serverIPAddress"),
                Error = GetString(response, "_error") ?? GetString(entry, "_error"),
                RedirectUrl = GetString(response, "redirectURL"),
                ResourceType = GetString(entry, "_resourceType"),
                // Chrome records "memory" or "disk" for responses served from cache
                FromCache = entry.TryGetProperty("_fromCache", out var fromCache) && fromCache.ValueKind == JsonValueKind.String
            };

            if (GetString(entry, "startedDateTime") is { } started && DateTime.TryParse(started, out var startedDateTime))
            {
                harEntry.StartedDateTime = startedDateTime;
            }

            ReadHeaders(request, harEntry.RequestHeaders);
            ReadHeaders(response, harEntry.ResponseHeaders);

            if (request.TryGetProperty("postData", out var postData))
            {
                harEntry.RequestBody = GetString(postData, "text");
            }

            if (response.TryGetProperty("content", out var responseContent))
            {
                harEntry.ResponseBody = GetString(responseContent, "text");
                harEntry.ResponseBodyEncoding = GetString(responseContent, "encoding");
            }

            if (entry.TryGetProperty("timings", out var timings) && timings.ValueKind == JsonValueKind.Object)
            {
                harEntry.Timings = new HarTimings
                {
                    Blocked = GetDouble(timings, "blocked"),
                    Dns = GetDouble(timings, "dns"),
                    Connect = GetDouble(timings, "connect"),
                    Ssl = GetDouble(timings, "ssl"),
                    Send = GetDouble(timings, "send"),
                    Wait = GetDouble(timings, "wait"),
                    Receive = GetDouble(timings, "receive")
                };
            }

            entries.Add(harEntry);
        }

        return entries;
    }

    private static void ReadHeaders(JsonElement element, List<HarHeader> headers)
    {
        if (!element.TryGetProperty("headers", out var headersElement) || headersElement.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        foreach (var header in headersElement.EnumerateArray())
        {
            headers.Add(new HarHeader
            {
                Name = GetString(header, "name") ?? string.Empty,
                Value = GetString(header, "value") ?? string.Empty
            });
        }
    }

    private static string? GetString(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    private static double GetDouble(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Number ? value.GetDouble() : -1;
}
