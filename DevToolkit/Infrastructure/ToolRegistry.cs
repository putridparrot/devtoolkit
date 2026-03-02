using System.Reflection;
using Microsoft.AspNetCore.Components;

namespace DevToolkit.Infrastructure;

public static class ToolRegistry
{
    private static IReadOnlyList<ToolRegistration>? _tools;

    public static IReadOnlyList<ToolRegistration> Tools => _tools ??= Discover();

    private static IReadOnlyList<ToolRegistration> Discover()
    {
        var assembly = typeof(ToolRegistry).Assembly;

        var settingsByRoute = assembly.GetTypes()
            .Where(t => t.GetCustomAttribute<ToolSettingsAttribute>() is not null)
            .ToDictionary(
                t => t.GetCustomAttribute<ToolSettingsAttribute>()!.ToolRoute,
                t => t);

        return assembly.GetTypes()
            .Where(t => t.GetCustomAttribute<ToolPageAttribute>() is not null)
            .Select(t =>
            {
                var toolAttr = t.GetCustomAttribute<ToolPageAttribute>()!;
                var route = t.GetCustomAttribute<RouteAttribute>()?.Template ?? "/";
                settingsByRoute.TryGetValue(route, out var settingsType);
                return new ToolRegistration(
                    toolAttr.Name,
                    route,
                    toolAttr.Icon,
                    toolAttr.Description,
                    toolAttr.Order,
                    t,
                    settingsType);
            })
            .OrderBy(r => r.Order)
            .ToList()
            .AsReadOnly();
    }
}
