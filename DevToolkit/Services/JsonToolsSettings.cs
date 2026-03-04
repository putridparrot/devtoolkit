using System;

namespace DevToolkit.Services;

public class JsonToolsSettings
{
    public string? LastInput { get; set; }
    public string? LastOutput { get; set; }
    public DateTimeOffset? LastUpdated { get; set; }
}
