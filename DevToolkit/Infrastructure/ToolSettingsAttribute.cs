namespace DevToolkit.Infrastructure;

[AttributeUsage(AttributeTargets.Class, AllowMultiple = false, Inherited = false)]
public sealed class ToolSettingsAttribute(string toolRoute) : Attribute
{
    public string ToolRoute { get; } = toolRoute;
}
