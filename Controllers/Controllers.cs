using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using SecureBankingAPI.DTOs;
using SecureBankingAPI.Services;

namespace SecureBankingAPI.Controllers;

// ── Transactions ───────────────────────────────────────────────────────────
[ApiController]
[Route("api/[controller]")]
[Authorize]
public class TransactionController : ControllerBase
{
    private readonly ITransactionService _transactions;

    public TransactionController(ITransactionService transactions)
        => _transactions = transactions;

    private int UserId =>
        int.Parse(User.FindFirst(ClaimTypes.NameIdentifier)!.Value);
    private string IpAddress =>
        HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";

    [HttpGet("account")]
    public async Task<IActionResult> GetAccount()
    {
        var account = await _transactions.GetAccountAsync(UserId);
        if (account is null) return NotFound(ApiResponse<object>.Fail("Account not found."));
        return Ok(ApiResponse<AccountResponse>.Ok(account));
    }

    [HttpGet("history")]
    public async Task<IActionResult> GetHistory()
    {
        var history = await _transactions.GetHistoryAsync(UserId);
        return Ok(ApiResponse<IEnumerable<TransactionResponse>>.Ok(history));
    }

    [HttpPost("deposit")]
    public async Task<IActionResult> Deposit([FromBody] DepositRequest request)
    {
        if (!ModelState.IsValid)
            return BadRequest(ApiResponse<object>.Fail("Invalid input."));

        var (success, message, transaction) =
            await _transactions.DepositAsync(UserId, request, IpAddress);

        if (!success) return BadRequest(ApiResponse<object>.Fail(message));
        return Ok(ApiResponse<TransactionResponse>.Ok(transaction!));
    }

    [HttpPost("withdraw")]
    public async Task<IActionResult> Withdraw([FromBody] WithdrawalRequest request)
    {
        if (!ModelState.IsValid)
            return BadRequest(ApiResponse<object>.Fail("Invalid input."));

        var (success, message, transaction) =
            await _transactions.WithdrawAsync(UserId, request, IpAddress);

        if (!success) return BadRequest(ApiResponse<object>.Fail(message));
        return Ok(ApiResponse<TransactionResponse>.Ok(transaction!));
    }

    [HttpPost("transfer")]
    public async Task<IActionResult> Transfer([FromBody] TransferRequest request)
    {
        if (!ModelState.IsValid)
            return BadRequest(ApiResponse<object>.Fail("Invalid input."));

        var (success, message, transaction) =
            await _transactions.TransferAsync(UserId, request, IpAddress);

        if (!success) return BadRequest(ApiResponse<object>.Fail(message));
        return Ok(ApiResponse<TransactionResponse>.Ok(transaction!));
    }
}

// ── File Upload ────────────────────────────────────────────────────────────
[ApiController]
[Route("api/[controller]")]
[Authorize]
public class FileUploadController : ControllerBase
{
    private readonly IFileUploadService _fileUpload;

    public FileUploadController(IFileUploadService fileUpload)
        => _fileUpload = fileUpload;

    private int UserId =>
        int.Parse(User.FindFirst(ClaimTypes.NameIdentifier)!.Value);
    private string IpAddress =>
        HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";

    /// <summary>Upload a check deposit image (JPG/PNG, max 5MB).</summary>
    [HttpPost("upload")]
    [RequestSizeLimit(6_000_000)]
    public async Task<IActionResult> Upload(IFormFile file)
    {
        if (file is null || file.Length == 0)
            return BadRequest(ApiResponse<object>.Fail("No file provided."));

        var (success, message, upload) =
            await _fileUpload.ProcessUploadAsync(UserId, file, IpAddress);

        if (!success) return BadRequest(ApiResponse<object>.Fail(message));

        return Ok(ApiResponse<object>.Ok(new
        {
            uploadId     = upload!.Id,
            originalName = upload.OriginalFileName,
            scanResult   = upload.ScanResult,
            encrypted    = upload.IsEncrypted,
        }));
    }

    /// <summary>Download your own uploaded file.</summary>
    [HttpGet("{id:int}")]
    public async Task<IActionResult> Download(int id)
    {
        var (success, data, mimeType) =
            await _fileUpload.GetFileAsync(id, UserId);

        if (!success || data is null)
            return NotFound(ApiResponse<object>.Fail("File not found."));

        return File(data, mimeType!, "download");
    }
}

// ── Admin Dashboard ────────────────────────────────────────────────────────
[ApiController]
[Route("api/[controller]")]
[Authorize(Policy = "AdminOnly")]
public class AdminController : ControllerBase
{
    private readonly IUserService  _users;
    private readonly IAuditService _audit;

    public AdminController(IUserService users, IAuditService audit)
    {
        _users = users;
        _audit = audit;
    }

    private int AdminId =>
        int.Parse(User.FindFirst(ClaimTypes.NameIdentifier)!.Value);
    private string IpAddress =>
        HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";

    /// <summary>List all users (admin only).</summary>
    [HttpGet("users")]
    public async Task<IActionResult> GetUsers()
    {
        var users = await _users.GetAllUsersAsync();
        return Ok(ApiResponse<IEnumerable<UserManagementResponse>>.Ok(users));
    }

    /// <summary>Update a user's role (admin only).</summary>
    [HttpPut("users/{id:int}/role")]
    public async Task<IActionResult> UpdateRole(int id, [FromBody] UpdateRoleRequest request)
    {
        if (!ModelState.IsValid)
            return BadRequest(ApiResponse<object>.Fail("Invalid role."));

        var success = await _users.UpdateRoleAsync(id, request.Role, AdminId, IpAddress);
        if (!success) return NotFound(ApiResponse<object>.Fail("User not found."));

        return Ok(ApiResponse<object>.Ok(new { updated = true }));
    }

    /// <summary>Unlock a locked user account (admin only).</summary>
    [HttpPost("users/{id:int}/unlock")]
    public async Task<IActionResult> UnlockUser(int id)
    {
        var success = await _users.UnlockUserAsync(id, AdminId, IpAddress);
        if (!success) return NotFound(ApiResponse<object>.Fail("User not found."));

        return Ok(ApiResponse<object>.Ok(new { unlocked = true }));
    }

    /// <summary>View audit logs with pagination (admin only).</summary>
    [HttpGet("audit-logs")]
    public async Task<IActionResult> GetAuditLogs(
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 50)
    {
        if (pageSize > 100) pageSize = 100;
        var logs = await _audit.GetLogsAsync(page, pageSize);
        return Ok(ApiResponse<IEnumerable<AuditLogResponse>>.Ok(logs));
    }

    /// <summary>Verify audit log hash chain integrity (admin only).</summary>
    [HttpGet("audit-logs/verify")]
    public async Task<IActionResult> VerifyIntegrity()
    {
        var isValid = await _audit.VerifyIntegrityAsync();
        return Ok(ApiResponse<object>.Ok(new
        {
            integrityValid = isValid,
            message        = isValid
                ? "All audit log hashes verified. No tampering detected."
                : "INTEGRITY VIOLATION DETECTED. Audit logs may have been tampered with."
        }));
    }
}
