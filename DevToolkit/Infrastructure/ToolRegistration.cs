namespace DevToolkit.Infrastructure;

public sealed record ToolRegistration(
    string Name,
    string Route,
    string Icon,
    string Description,
    int Order,
    Type ComponentType,
    Type? SettingsComponentType = null);
