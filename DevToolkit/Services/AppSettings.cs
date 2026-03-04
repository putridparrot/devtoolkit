namespace DevToolkit.Services;

public class AppSettings
{
    public SnippetsSettings Snippets { get; set; } = new();
    public JwtSettings Jwt { get; set; } = new();
    public HarSettings Har { get; set; } = new();
    public GeneralSettings General { get; set; } = new();
    public JsonToolsSettings Json { get; set; } = new();
    public JsonYamlSettings JsonYaml { get; set; } = new();
}