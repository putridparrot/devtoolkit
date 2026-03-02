namespace DevToolkit.Services;

public interface IThemeService
{
    event Action<string>? ThemeChanged;
    void SetTheme(string theme);
}