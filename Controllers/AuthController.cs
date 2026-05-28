using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SecureBankingAPI.DTOs;
using SecureBankingAPI.Services;
using System.Security.Claims;

namespace SecureBankingAPI.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IAuthService  _auth;
    private readonly ITokenService _token;
    private readonly ITotpService  _totp;
    private readonly IAuditService _audit;

    public AuthController(IAuthService auth, ITokenService token,
                          ITotpService totp, IAuditService audit)
    {
        _auth  = auth;
        _token = token;
        _totp  = totp;
        _audit = audit;
    }

    private string IpAddress =>
        HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";

    [HttpPost("register")]
    [AllowAnonymous]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        if (!ModelState.IsValid)
            return BadRequest(ApiResponse<object>.Fail("Invalid input."));

        var (success, message, user) = await _auth.RegisterAsync(request);

        if (!success)
            return BadRequest(ApiResponse<object>.Fail(message));

        return Ok(ApiResponse<object>.Ok(new { message }));
    }

    [HttpPost("login")]
    [AllowAnonymous]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        if (!ModelState.IsValid)
            return BadRequest(ApiResponse<object>.Fail("Invalid input."));

        var (success, message, user, mfaRequired) =
            await _auth.LoginAsync(request, IpAddress);

        if (mfaRequired)
            return Ok(ApiResponse<object>.Ok(new { mfaRequired = true }, "MFA code required."));

        if (!success || user is null)
            return Unauthorized(ApiResponse<object>.Fail(message));

        var jwtToken  = _token.GenerateToken(user);
        var expiresAt = DateTime.UtcNow.AddMinutes(30);

        return Ok(ApiResponse<LoginResponse>.Ok(new LoginResponse
        {
            Token       = jwtToken,
            Role        = user.Role,
            ExpiresAt   = expiresAt,
            MfaRequired = false,
        }));
    }

    [HttpPost("mfa/setup")]
    [Authorize]
    public async Task<IActionResult> SetupMfa()
    {
        var username = User.FindFirst(ClaimTypes.Name)?.Value ?? "";
        var (secret, qrUri) = _totp.GenerateSecret(username);

        return Ok(ApiResponse<MfaSetupResponse>.Ok(new MfaSetupResponse
        {
            QrCodeUri = qrUri,
            ManualKey = secret,
        }));
    }

    [HttpPost("mfa/verify")]
    [Authorize]
    public async Task<IActionResult> VerifyMfa([FromBody] VerifyMfaRequest request)
    {
        return Ok(ApiResponse<object>.Ok(new { mfaEnabled = true }, "MFA enabled."));
    }
}
