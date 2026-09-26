namespace DevToolkit.Services;

/// <summary>
/// Keeps each tool page's state in memory for the lifetime of the app, so that
/// navigating away from a tool and back leaves everything as it was.
/// </summary>
public class ToolStateStore
{
    private readonly Dictionary<Type, object> _states = new();

    public T Get<T>(out bool isNew) where T : class, new()
    {
        if (_states.TryGetValue(typeof(T), out var existing))
        {
            isNew = false;
            return (T)existing;
        }

        var state = new T();
        _states[typeof(T)] = state;
        isNew = true;
        return state;
    }
}
