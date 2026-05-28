namespace AuthBroker.Core;

/// <summary>
/// Non-generic result interface for operations that don't return data.
/// </summary>
public interface IAuthResult
{
    bool IsSuccess { get; }
    int StatusCode { get; }
    string? ErrorMessage { get; }
}

/// <summary>
/// Generic result interface for operations that return typed data.
/// </summary>
public interface IAuthResult<T> : IAuthResult
{
    T? Data { get; }
}

/// <summary>
/// Successful result carrying typed data.
/// </summary>
public record AuthSuccessResult<T>(T Data, int StatusCode = 200) : IAuthResult<T>
{
    public bool IsSuccess => true;
    public string? ErrorMessage => null;
}

/// <summary>
/// Successful result for operations that don't return data (e.g. logout).
/// </summary>
public record AuthSuccessResult(int StatusCode = 200) : IAuthResult
{
    public bool IsSuccess => true;
    public string? ErrorMessage => null;
}

/// <summary>
/// Error result with status code and message (non-generic, for operations that don't return data).
/// </summary>
public record AuthErrorResult(int StatusCode, string? ErrorMessage) : IAuthResult
{
    public bool IsSuccess => false;
}

/// <summary>
/// Error result with status code and message (generic, for typed operations).
/// </summary>
public record AuthErrorResult<T>(int StatusCode, string? ErrorMessage) : IAuthResult<T>
{
    public bool IsSuccess => false;
    public T? Data => default;
}
