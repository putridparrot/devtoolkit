using System.Globalization;

namespace DevToolkit.Services.Har;

public enum HarFindingSeverity
{
    Error,
    Warning,
    Info
}

public sealed record HarFinding(HarFindingSeverity Severity, string Title, string Detail, IReadOnlyList<HarEntry> Evidence);

/// <summary>
/// Rule-based analysis of a HAR capture, looking for common causes of failures
/// (proxies, WAFs, browser network errors, rate limiting) without needing AI.
/// </summary>
public static class HarAnalyzer
{
    // Headers that vary per response or are added by almost any hop, so say little about who generated a response
    private static readonly HashSet<string> GenericHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "date", "content-length", "content-type", "connection", "keep-alive", "transfer-encoding", "content-encoding",
        "vary", "cache-control", "expires", "pragma", "etag", "last-modified", "age", "accept-ranges", "set-cookie",
        "alt-svc", "via", "x-cache", "server-timing", "nel", "report-to"
    };

    private static readonly string[] CorrelationHeaders =
    [
        "x-request-id", "x-correlation-id", "request-id", "x-ms-request-id", "x-amzn-requestid", "x-amz-cf-id",
        "cf-ray", "x-azure-ref", "traceparent", "x-b3-traceid", "x-trace-id", "x-cloud-trace-context", "x-datadog-trace-id"
    ];

    private static readonly string[] TelemetryHosts =
    [
        "google-analytics.com", "analytics.google.com", "googletagmanager.com", "doubleclick.net", "sentry.io",
        "datadoghq.com", "datadoghq.eu", "nr-data.net", "newrelic.com", "hotjar.com", "hotjar.io", "segment.io",
        "segment.com", "clarity.ms", "dc.services.visualstudio.com", "applicationinsights.azure.com", "mixpanel.com",
        "amplitude.com", "fullstory.com", "optimizely.com", "bing.com", "facebook.net"
    ];

    private static readonly string[] StaticExtensions =
    [
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif", ".bmp", ".woff", ".woff2", ".ttf", ".otf",
        ".eot", ".css", ".js", ".mjs", ".map", ".mp4", ".webm", ".mp3"
    ];

    private static readonly string[] StaticResourceTypes = ["image", "font", "stylesheet", "script", "media", "manifest"];

    /// <summary>
    /// Successful requests that rarely matter when troubleshooting: static assets, telemetry, cached responses,
    /// CORS preflights and browser-internal URLs. Failed requests are never treated as noise.
    /// </summary>
    public static bool IsNoise(HarEntry entry)
    {
        if (entry.IsFailure)
        {
            return false;
        }

        if (entry.Url.StartsWith("data:", StringComparison.OrdinalIgnoreCase) ||
            entry.Url.StartsWith("blob:", StringComparison.OrdinalIgnoreCase) ||
            entry.Url.Contains("-extension://", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (entry.FromCache || entry.Status == 304 || entry.Method.Equals("OPTIONS", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (entry.ResourceType is { } type && StaticResourceTypes.Contains(type, StringComparer.OrdinalIgnoreCase))
        {
            return true;
        }

        if (entry.MimeType.StartsWith("image/", StringComparison.OrdinalIgnoreCase) ||
            entry.MimeType.StartsWith("font/", StringComparison.OrdinalIgnoreCase) ||
            entry.MimeType.Contains("css", StringComparison.OrdinalIgnoreCase) ||
            entry.MimeType.Contains("javascript", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var path = entry.Path;
        if (StaticExtensions.Any(ext => path.EndsWith(ext, StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        var host = entry.Host;
        return TelemetryHosts.Any(t => host.Equals(t, StringComparison.OrdinalIgnoreCase) ||
                                       host.EndsWith("." + t, StringComparison.OrdinalIgnoreCase));
    }

    public static List<HarFinding> Analyze(IReadOnlyList<HarEntry> entries)
    {
        var findings = new List<HarFinding>();
        var failures = entries.Where(e => e.IsFailure).ToList();

        findings.AddRange(DetectIntermediaries(entries));
        findings.AddRange(DetectProxyAuthentication(failures));
        findings.AddRange(DetectBrowserErrors(failures));
        findings.AddRange(DetectHeaderFingerprintMismatch(entries));
        findings.AddRange(DetectHtmlErrorPages(entries));
        findings.AddRange(DetectServerIpMismatch(entries));
        findings.AddRange(DetectRateLimiting(failures));
        findings.AddRange(DescribeFirstFailure(failures));
        findings.AddRange(CollectCorrelationIds(failures));

        return findings
            .Select((finding, order) => (finding, order))
            .OrderBy(f => f.finding.Severity)
            .ThenBy(f => f.order)
            .Select(f => f.finding)
            .ToList();
    }

    private static IEnumerable<HarFinding> DetectIntermediaries(IReadOnlyList<HarEntry> entries)
    {
        foreach (var signature in HarSignatures.All)
        {
            var blocked = new List<(HarEntry Entry, string Reason)>();
            var present = 0;

            foreach (var entry in entries)
            {
                // Only responses that failed or redirected can have been "answered" by the intermediary
                if (entry.IsFailure || entry.Status is >= 300 and < 400)
                {
                    if (signature.MatchBlock(entry) is { } reason)
                    {
                        blocked.Add((entry, reason));
                        continue;
                    }
                }

                if (signature.MatchPresence(entry) is not null)
                {
                    present++;
                }
            }

            if (blocked.Count > 0)
            {
                var reasons = blocked.Select(b => b.Reason).Distinct().Take(3);
                var advice = signature.Kind == IntermediaryKind.Proxy
                    ? $"This is a corporate proxy / secure web gateway on the user's network, so the request probably never reached the server. Check the {signature.Vendor} policy for these URLs (URL category, TLS inspection bypass, authentication) with the user's network team."
                    : $"The response was generated at the {signature.Vendor} edge in front of the origin, typically by a WAF rule, bot protection or rate limit. Check the {signature.Vendor} security events for these requests.";

                yield return new HarFinding(
                    HarFindingSeverity.Error,
                    $"{blocked.Count} response(s) appear to come from {signature.Vendor}, not the target server",
                    $"Matched {string.Join("; ", reasons)}. {advice}",
                    blocked.Select(b => b.Entry).ToList());
            }
            else if (present > 0)
            {
                yield return new HarFinding(
                    HarFindingSeverity.Info,
                    $"Traffic passes through {signature.Vendor}",
                    $"{present} response(s) carry {signature.Vendor} headers. None of the failures look like they were generated by it, but it is part of the request path.",
                    []);
            }
        }
    }

    private static IEnumerable<HarFinding> DetectProxyAuthentication(List<HarEntry> failures)
    {
        var proxyAuth = failures.Where(e => e.Status == 407).ToList();
        if (proxyAuth.Count > 0)
        {
            var scheme = proxyAuth.Select(e => e.GetResponseHeader("Proxy-Authenticate")).FirstOrDefault(v => !string.IsNullOrEmpty(v));
            yield return new HarFinding(
                HarFindingSeverity.Error,
                "Proxy authentication required (407)",
                "A proxy between the browser and the server rejected the request because the user isn't authenticated to it." +
                (scheme is null ? string.Empty : $" It asked for: {scheme}."),
                proxyAuth);
        }
    }

    private static IEnumerable<HarFinding> DetectBrowserErrors(List<HarEntry> failures)
    {
        foreach (var group in failures.Where(e => e.Status == 0).GroupBy(e => e.Error ?? string.Empty))
        {
            var error = group.Key;
            var (severity, hint) = DescribeBrowserError(error);
            yield return new HarFinding(
                severity,
                string.IsNullOrEmpty(error)
                    ? $"{group.Count()} request(s) got no response"
                    : $"{group.Count()} request(s) failed with {error}",
                hint,
                group.ToList());
        }
    }

    private static (HarFindingSeverity Severity, string Hint) DescribeBrowserError(string error)
    {
        var code = error.Replace("net::", string.Empty).Trim().ToUpperInvariant();
        return code switch
        {
            "" => (HarFindingSeverity.Warning, "The browser recorded no response and no error (status 0). The request was blocked, cancelled, or failed a CORS check. Firefox doesn't record the reason, so check the console log from the same session."),
            "ERR_TUNNEL_CONNECTION_FAILED" or "ERR_PROXY_CONNECTION_FAILED" or "ERR_PROXY_AUTH_UNSUPPORTED" or
                "ERR_PROXY_AUTH_REQUESTED" or "ERR_PROXY_CERTIFICATE_INVALID" or "ERR_MANDATORY_PROXY_CONFIGURATION_FAILED" =>
                (HarFindingSeverity.Error, "The browser couldn't get through the configured proxy. The proxy refused the CONNECT tunnel (often a blocked destination or policy) or was unreachable. Check the user's proxy/PAC configuration and the proxy's policy for this host."),
            _ when code.StartsWith("ERR_CERT_") || code.StartsWith("ERR_SSL_") || code == "ERR_BAD_SSL_CLIENT_AUTH_CERT" =>
                (HarFindingSeverity.Error, "TLS failed. On corporate networks this is usually TLS inspection by a proxy whose root certificate isn't trusted by this browser or device. Otherwise the server's certificate is invalid, expired or doesn't match the host."),
            "ERR_BLOCKED_BY_CLIENT" =>
                (HarFindingSeverity.Warning, "Blocked inside the browser, almost always by an ad-blocker or privacy extension. Retry in a clean profile or with extensions disabled."),
            "ERR_BLOCKED_BY_ADMINISTRATOR" =>
                (HarFindingSeverity.Error, "Blocked by browser policy set by the user's administrator (URL blocklist)."),
            "ERR_BLOCKED_BY_RESPONSE" or "ERR_BLOCKED_BY_ORB" =>
                (HarFindingSeverity.Warning, "The browser discarded the response because of a security header or cross-origin read blocking (e.g. Cross-Origin-Resource-Policy, X-Frame-Options, or a wrong Content-Type)."),
            "ERR_NAME_NOT_RESOLVED" or "ERR_NAME_RESOLUTION_FAILED" =>
                (HarFindingSeverity.Error, "DNS lookup failed. The host name is wrong, or internal/split DNS isn't available on the user's network (e.g. off VPN)."),
            "ERR_CONNECTION_REFUSED" or "ERR_CONNECTION_RESET" or "ERR_CONNECTION_CLOSED" or "ERR_CONNECTION_TIMED_OUT" or
                "ERR_TIMED_OUT" or "ERR_ADDRESS_UNREACHABLE" or "ERR_EMPTY_RESPONSE" =>
                (HarFindingSeverity.Error, "The connection was refused, reset or timed out. Common causes are a firewall or proxy dropping the connection, the server being down, or a load balancer idle timeout."),
            "ERR_INTERNET_DISCONNECTED" or "ERR_NETWORK_CHANGED" =>
                (HarFindingSeverity.Warning, "The device's network dropped or changed during the request (Wi-Fi switch, VPN connect/disconnect)."),
            "ERR_ABORTED" =>
                (HarFindingSeverity.Info, "Cancelled by the browser or page, e.g. by navigation or a superseded fetch. Usually not the root cause."),
            "ERR_FAILED" =>
                (HarFindingSeverity.Warning, "A generic failure. For cross-origin requests this is typically a CORS rejection (check the preflight OPTIONS response and Access-Control-Allow-* headers)."),
            _ => (HarFindingSeverity.Warning, "The browser reported a network error with no HTTP response.")
        };
    }

    private static IEnumerable<HarFinding> DetectHeaderFingerprintMismatch(IReadOnlyList<HarEntry> entries)
    {
        foreach (var host in entries.GroupBy(e => e.Host).Where(g => g.Key.Length > 0))
        {
            var failed = host.Where(e => e.Status >= 400).ToList();
            if (failed.Count == 0)
            {
                continue;
            }

            // Compare against the host's normal responses; prefer API-like traffic over static assets
            var successes = host.Where(e => e.Status is >= 200 and < 300 && !e.FromCache).ToList();
            var meaningful = successes.Where(e => !IsNoise(e)).ToList();
            if (meaningful.Count >= 2)
            {
                successes = meaningful;
            }

            if (successes.Count < 2)
            {
                continue;
            }

            var baseline = successes
                .SelectMany(e => e.ResponseHeaders.Select(h => h.Name.ToLowerInvariant()).Distinct())
                .Where(name => !GenericHeaders.Contains(name))
                .GroupBy(name => name)
                .Where(g => g.Count() >= Math.Ceiling(successes.Count * 0.8))
                .Select(g => g.Key)
                .ToList();

            var usualServer = successes
                .Select(e => e.GetResponseHeader("Server"))
                .Where(v => !string.IsNullOrEmpty(v))
                .GroupBy(v => v)
                .OrderByDescending(g => g.Count())
                .FirstOrDefault()?.Key;

            var mismatched = new List<HarEntry>();
            var missingHeaders = new HashSet<string>();
            var otherServers = new HashSet<string>();

            foreach (var entry in failed)
            {
                var names = entry.ResponseHeaders.Select(h => h.Name.ToLowerInvariant()).ToHashSet();
                var missing = baseline.Where(b => !names.Contains(b)).ToList();
                var server = entry.GetResponseHeader("Server");
                var serverDiffers = usualServer is not null && !string.IsNullOrEmpty(server) && server != usualServer;

                if ((baseline.Count >= 2 && missing.Count >= Math.Max(2, (baseline.Count + 1) / 2)) || serverDiffers)
                {
                    mismatched.Add(entry);
                    missingHeaders.UnionWith(missing);
                    if (serverDiffers)
                    {
                        otherServers.Add(server!);
                    }
                }
            }

            if (mismatched.Count == 0)
            {
                continue;
            }

            var detail = $"{mismatched.Count} failed response(s) from {host.Key} don't look like the {successes.Count} successful ones.";
            if (missingHeaders.Count > 0)
            {
                detail += $" They're missing headers this host normally returns: {string.Join(", ", missingHeaders.Take(8))}.";
            }

            if (otherServers.Count > 0)
            {
                detail += $" The Server header was \"{string.Join("\", \"", otherServers)}\" instead of the usual \"{usualServer}\".";
            }

            detail += " This usually means the error was generated by a proxy, gateway or WAF rather than the application.";

            yield return new HarFinding(
                HarFindingSeverity.Warning,
                $"Errors from {host.Key} look like they came from a different hop",
                detail,
                mismatched);
        }
    }

    private static IEnumerable<HarFinding> DetectHtmlErrorPages(IReadOnlyList<HarEntry> entries)
    {
        var jsonHosts = entries
            .Where(e => e.Status is >= 200 and < 300)
            .GroupBy(e => e.Host)
            .Where(g => g.Count(IsJson) * 2 >= g.Count())
            .Select(g => g.Key)
            .ToHashSet();

        var htmlErrors = entries
            .Where(e => e.Status >= 400 && e.MimeType.Contains("html", StringComparison.OrdinalIgnoreCase))
            .Where(e => !string.Equals(e.ResourceType, "document", StringComparison.OrdinalIgnoreCase))
            .Where(e =>
            {
                var accept = e.GetRequestHeader("Accept") ?? string.Empty;
                var wantsJson = accept.Contains("json", StringComparison.OrdinalIgnoreCase) &&
                                !accept.Contains("html", StringComparison.OrdinalIgnoreCase);
                return wantsJson || jsonHosts.Contains(e.Host);
            })
            .ToList();

        if (htmlErrors.Count > 0)
        {
            yield return new HarFinding(
                HarFindingSeverity.Warning,
                $"{htmlErrors.Count} API call(s) got an HTML error page",
                "These requests expected JSON but received HTML. APIs rarely return HTML errors, so these pages were most likely served by a proxy, gateway, WAF or login redirect. Open the response body to see who generated it.",
                htmlErrors);
        }

        static bool IsJson(HarEntry e) => e.MimeType.Contains("json", StringComparison.OrdinalIgnoreCase);
    }

    private static IEnumerable<HarFinding> DetectServerIpMismatch(IReadOnlyList<HarEntry> entries)
    {
        foreach (var host in entries.Where(e => !string.IsNullOrEmpty(e.ServerIpAddress)).GroupBy(e => e.Host))
        {
            var goodIps = host.Where(e => e.Status is >= 200 and < 300).Select(e => NormalizeIp(e.ServerIpAddress!)).ToHashSet();
            if (goodIps.Count == 0)
            {
                continue;
            }

            var odd = host.Where(e => e.IsFailure && !goodIps.Contains(NormalizeIp(e.ServerIpAddress!))).ToList();
            if (odd.Count > 0)
            {
                var badIps = odd.Select(e => NormalizeIp(e.ServerIpAddress!)).Distinct();
                yield return new HarFinding(
                    HarFindingSeverity.Warning,
                    $"Failed requests to {host.Key} went to a different server IP",
                    $"Failures connected to {string.Join(", ", badIps)} while successful requests used {string.Join(", ", goodIps.Take(4))}. The failing traffic may have been routed through a proxy or a different edge/region.",
                    odd);
            }
        }

        static string NormalizeIp(string ip) => ip.Trim('[', ']');
    }

    private static IEnumerable<HarFinding> DetectRateLimiting(List<HarEntry> failures)
    {
        var limited = failures.Where(e => e.Status == 429).ToList();
        if (limited.Count > 0)
        {
            var retryAfter = limited.Select(e => e.GetResponseHeader("Retry-After")).FirstOrDefault(v => !string.IsNullOrEmpty(v));
            yield return new HarFinding(
                HarFindingSeverity.Warning,
                $"Rate limited ({limited.Count} × 429)",
                "The server or an edge service throttled these requests." +
                (retryAfter is null ? string.Empty : $" Retry-After: {retryAfter}."),
                limited);
        }
    }

    private static IEnumerable<HarFinding> DescribeFirstFailure(List<HarEntry> failures)
    {
        // Cancelled requests are rarely the root cause, so start from the first "real" failure
        var first = failures
            .Where(e => !string.Equals(e.Error, "net::ERR_ABORTED", StringComparison.OrdinalIgnoreCase))
            .OrderBy(e => e.StartedDateTime)
            .ThenBy(e => e.Index)
            .FirstOrDefault();

        if (first is not null && failures.Count > 1)
        {
            var status = first.Status == 0 ? first.Error ?? "no response" : $"{first.Status} {first.StatusText}".Trim();
            yield return new HarFinding(
                HarFindingSeverity.Info,
                "First failure in the capture",
                $"{first.StartedDateTime.ToString("HH:mm:ss.fff", CultureInfo.InvariantCulture)} {first.Method} {first.Host}{first.Path} → {status}. Later failures are often a knock-on effect of the first one.",
                [first]);
        }
    }

    private static IEnumerable<HarFinding> CollectCorrelationIds(List<HarEntry> failures)
    {
        var lines = new List<string>();
        var evidence = new List<HarEntry>();

        foreach (var entry in failures.Where(e => e.Status > 0))
        {
            var ids = CorrelationHeaders
                .Select(name => (Name: name, Value: entry.GetResponseHeader(name) ?? entry.GetRequestHeader(name)))
                .Where(id => !string.IsNullOrEmpty(id.Value))
                .Select(id => $"{id.Name}={id.Value}")
                .ToList();

            if (ids.Count > 0)
            {
                lines.Add($"{entry.Status} {entry.Method} {entry.Path}: {string.Join(", ", ids)}");
                evidence.Add(entry);
            }
        }

        if (lines.Count > 0)
        {
            yield return new HarFinding(
                HarFindingSeverity.Info,
                "Correlation IDs for failed requests",
                "Give these to the backend or vendor support team to find the matching server-side logs:\n" + string.Join("\n", lines.Take(15)),
                evidence);
        }
    }
}
