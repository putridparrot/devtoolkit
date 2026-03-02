using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace DevToolkit.Services;

public sealed class JwtTokenCodec
{
    public JwtDecodeResult Decode(string token)
    {
        if (string.IsNullOrWhiteSpace(token))
            throw new ArgumentException("Token is empty.");

        var parts = token.Trim().Split('.');
        var decodedParts = new List<JwtTokenPart>(parts.Length);

        for (var i = 0; i < parts.Length; i++)
        {
            var partName = i switch
            {
                0 => "Header",
                1 => "Payload",
                2 => "Signature",
                _ => $"Part {i + 1}"
            };

            var raw = parts[i];
            var decoded = TryDecodeBase64Url(raw, out var text) ? text : string.Empty;
            var formatted = decoded;

            if (!string.IsNullOrWhiteSpace(decoded) && TryFormatJson(decoded, out var pretty))
                formatted = pretty;

            decodedParts.Add(new JwtTokenPart(partName, raw, formatted, !string.IsNullOrWhiteSpace(decoded)));
        }

        var claims = ExtractClaims(decodedParts.FirstOrDefault(p => p.Name == "Payload")?.Decoded);

        return new JwtDecodeResult(decodedParts, claims);
    }

    public string Encode(IDictionary<string, object?> header, IDictionary<string, object?> payload, string? signature = null)
    {
        var encodedHeader = EncodeBase64Url(JsonSerializer.Serialize(header));
        var encodedPayload = EncodeBase64Url(JsonSerializer.Serialize(payload));

        return string.IsNullOrWhiteSpace(signature)
            ? $"{encodedHeader}.{encodedPayload}."
            : $"{encodedHeader}.{encodedPayload}.{signature}";
    }

    public string EncodeHs256(IDictionary<string, object?> header, IDictionary<string, object?> payload, string secret)
    {
        if (string.IsNullOrWhiteSpace(secret))
            throw new ArgumentException("Secret is required for HS256 encoding.");

        var finalHeader = new Dictionary<string, object?>(header, StringComparer.OrdinalIgnoreCase)
        {
            ["alg"] = "HS256"
        };

        finalHeader.TryAdd("typ", "JWT");

        var encodedHeader = EncodeBase64Url(JsonSerializer.Serialize(finalHeader));
        var encodedPayload = EncodeBase64Url(JsonSerializer.Serialize(payload));
        var signingInput = $"{encodedHeader}.{encodedPayload}";

        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
        var signatureBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(signingInput));
        var signature = Convert.ToBase64String(signatureBytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

        return $"{signingInput}.{signature}";
    }

    private static bool TryDecodeBase64Url(string base64Url, out string decoded)
    {
        decoded = string.Empty;

        if (string.IsNullOrWhiteSpace(base64Url))
            return false;

        try
        {
            var base64 = base64Url.Replace('-', '+').Replace('_', '/');
            base64 = base64.PadRight(base64.Length + ((4 - base64.Length % 4) % 4), '=');
            var bytes = Convert.FromBase64String(base64);
            decoded = Encoding.UTF8.GetString(bytes);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static bool TryFormatJson(string input, out string formatted)
    {
        formatted = input;

        try
        {
            using var jsonDocument = JsonDocument.Parse(input);
            formatted = JsonSerializer.Serialize(jsonDocument, new JsonSerializerOptions { WriteIndented = true });
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static IReadOnlyDictionary<string, string> ExtractClaims(string? payload)
    {
        var claims = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        if (string.IsNullOrWhiteSpace(payload))
            return claims;

        try
        {
            using var jsonDocument = JsonDocument.Parse(payload);
            if (jsonDocument.RootElement.ValueKind != JsonValueKind.Object)
                return claims;

            foreach (var property in jsonDocument.RootElement.EnumerateObject())
            {
                claims[property.Name] = property.Value.ValueKind switch
                {
                    JsonValueKind.String => property.Value.GetString() ?? string.Empty,
                    _ => property.Value.ToString()
                };
            }
        }
        catch
        {
            // ignore claim extraction failures
        }

        return claims;
    }

    private static string EncodeBase64Url(string text)
    {
        var bytes = Encoding.UTF8.GetBytes(text);
        return Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }
}

public sealed record JwtDecodeResult(IReadOnlyList<JwtTokenPart> Parts, IReadOnlyDictionary<string, string> Claims);

public sealed record JwtTokenPart(string Name, string Raw, string Decoded, bool CanDecode);
