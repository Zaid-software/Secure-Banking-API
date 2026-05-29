using System.Net;
using System.Text.Json;

namespace SecureBankingAPI.Middleware;

// ── Security Headers Middleware ────────────────────────────────────────────
/// <summary>
/// Adds security headers to every response:
/// CSP, X-Frame-Options, X-XSS-Protection, HSTS, etc.
/// </summary>
public class SecurityHeadersMiddleware
{
    private readonly RequestDelegate _next;

    public SecurityHeadersMiddleware(RequestDelegate next) => _next = next;

    public async Task InvokeAsync(HttpContext context)
    {
        var headers = context.Response.Headers;

        // Prevent clickjacking
        headers["X-Frame-Options"] = "DENY";

        // XSS protection for older browsers
        headers["X-XSS-Protection"] = "1; mode=block";

        // Prevent MIME sniffing
        headers["X-Content-Type-Options"] = "nosniff";

        // HSTS — force HTTPS for 1 year
        headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains";

        // Referrer policy
        headers["Referrer-Policy"] = "strict-origin-when-cross-origin";

        // Content Security Policy — restrict sources
        headers["Content-Security-Policy"] =
            "default-src 'self'; " +
            "script-src 'self'; " +
            "style-src 'self'; " +
            "img-src 'self' data:; " +
            "font-src 'self'; " +
            "connect-src 'self'; " +
            "frame-ancestors 'none';";

        // Remove server header to avoid fingerprinting
        headers.Remove("Server");
        headers.Remove("X-Powered-By");

        await _next(context);
    }
}

// ── Global Exception Middleware ────────────────────────────────────────────
/// <summary>
/// Catches all unhandled exceptions and returns a generic error.
/// Never leaks stack traces or internal details to the client.
/// </summary>
public class GlobalExceptionMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<GlobalExceptionMiddleware> _logger;

    public GlobalExceptionMiddleware(RequestDelegate next,
                                     ILogger<GlobalExceptionMiddleware> logger)
    {
        _next   = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await _next(context);
        }
        catch (Exception ex)
        {
            // Log full exception internally
            _logger.LogError(ex, "Unhandled exception: {Message}", ex.Message);

            // Return generic error — never expose details
            context.Response.StatusCode  = (int)HttpStatusCode.InternalServerError;
            context.Response.ContentType = "application/json";

            var response = new
            {
                success = false,
                message = "An internal error occurred. Please try again later."
                // No stack trace, no exception type, no inner exception
            };

            await context.Response.WriteAsync(JsonSerializer.Serialize(response));
        }
    }
}

// ── Audit Middleware ───────────────────────────────────────────────────────
/// <summary>
/// Logs all authenticated API requests to the audit trail.
/// </summary>
public class AuditMiddleware
{
    private readonly RequestDelegate _next;

    public AuditMiddleware(RequestDelegate next) => _next = next;

    public async Task InvokeAsync(HttpContext context,
                                  SecureBankingAPI.Services.IAuditService auditService)
    {
        await _next(context);

        // Only log authenticated requests (not anonymous)
        if (context.User?.Identity?.IsAuthenticated == true)
        {
            var userId    = context.User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
            var ipAddress = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            var path      = context.Request.Path;
            var method    = context.Request.Method;
            var status    = context.Response.StatusCode;

            // Don't log health checks or swagger
            if (!path.StartsWithSegments("/health") && !path.StartsWithSegments("/swagger"))
            {
                await auditService.LogAsync(
                    userId is not null ? int.Parse(userId) : null,
                    $"{method} {path}",
                    "HttpRequest",
                    null, null, null,
                    ipAddress,
                    status < 400,
                    status >= 400 ? $"HTTP {status}" : null,
                    context.Request.Headers.UserAgent
                );
            }
        }
    }
}
