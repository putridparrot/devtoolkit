using System;

namespace DevToolkit.Services;

public class JsonYamlSettings
{
    public string? ConvertJsonInput { get; set; }
    public string? ConvertYamlInput { get; set; }
    public string? SchemaInput { get; set; }
    public string? SchemaDataInput { get; set; }
    public DateTimeOffset? LastUpdated { get; set; }
}
