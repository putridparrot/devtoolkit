namespace DevToolkit.Shared.Infrastructure;

[AttributeUsage(AttributeTargets.Class, AllowMultiple = false, Inherited = false)]
public sealed class ToolPageAttribute(string name, string icon, string description, int order = 100) : Attribute
{
    public string Name { get; } = name;
    public string Icon { get; } = icon;
    public string Description { get; } = description;
    public int Order { get; } = order;
}
