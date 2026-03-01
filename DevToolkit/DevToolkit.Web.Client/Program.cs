using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using Microsoft.FluentUI.AspNetCore.Components;
using DevToolkit.Shared.Services;

namespace DevToolkit.Web.Client;

internal class Program
{
    static async Task Main(string[] args)
    {
        var builder = WebAssemblyHostBuilder.CreateDefault(args);

        builder.Services.AddFluentUIComponents();
        builder.Services.AddScoped<ISettingsService, SettingsService>();
        builder.Services.AddSingleton<IThemeService, ThemeService>();

        await builder.Build().RunAsync();
    }
}
