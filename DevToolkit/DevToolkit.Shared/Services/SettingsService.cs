using System.Text.Json;
using Microsoft.JSInterop;

namespace DevToolkit.Shared.Services;

public class SettingsService(IJSRuntime jsRuntime) : ISettingsService
{
    private const string StorageKey = "DevToolkit.Settings";
    private AppSettings? _cachedSettings;

    public async Task<AppSettings> LoadSettingsAsync()
    {
        if (_cachedSettings != null)
            return _cachedSettings;

        try
        {
            var json = await jsRuntime.InvokeAsync<string>("localStorage.getItem", StorageKey);
            
            if (!string.IsNullOrWhiteSpace(json))
            {
                _cachedSettings = JsonSerializer.Deserialize<AppSettings>(json) ?? new AppSettings();
            }
            else
            {
                _cachedSettings = new AppSettings();
            }
        }
        catch
        {
            _cachedSettings = new AppSettings();
        }

        return _cachedSettings;
    }

    public async Task SaveSettingsAsync(AppSettings settings)
    {
        _cachedSettings = settings;
        var json = JsonSerializer.Serialize(settings);
        await jsRuntime.InvokeVoidAsync("localStorage.setItem", StorageKey, json);
    }
}
