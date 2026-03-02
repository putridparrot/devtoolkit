namespace DevToolkit.Services;

public class ThemeService : IThemeService
{
    public event Action<string>? ThemeChanged;

    public void SetTheme(string theme)
    {
        ThemeChanged?.Invoke(theme);
    }
}
