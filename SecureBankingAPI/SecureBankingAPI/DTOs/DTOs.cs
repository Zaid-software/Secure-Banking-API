using System.ComponentModel.DataAnnotations;

namespace SecureBankingAPI.DTOs;

// ── Auth DTOs ──────────────────────────────────────────────────────────────
public class RegisterRequest
{
    [Required, MaxLength(100)]
    public string Username { get; set; } = string.Empty;

    [Required, EmailAddress, MaxLength(256)]
    public string Email    { get; set; } = string.Empty;

    [Required, MinLength(12),
     RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).+$",
         ErrorMessage = "Password must contain uppercase, lowercase, digit, and special character.")]
    public string Password { get; set; } = string.Empty;
}

public class LoginRequest
{
    [Required] public string Username { get; set; } = string.Empty;
    [Required] public string Password { get; set; } = string.Empty;
    public string? TotpCode           { get; set; }    // required if MFA enabled
}

public class LoginResponse
{
    public string  Token       { get; set; } = string.Empty;
    public string  Role        { get; set; } = string.Empty;
    public DateTime ExpiresAt  { get; set; }
    public bool    MfaRequired { get; set; }
}

public class MfaSetupResponse
{
    public string QrCodeUri   { get; set; } = string.Empty;
    public string ManualKey   { get; set; } = string.Empty;
}

public class VerifyMfaRequest
{
    [Required] public string TotpCode { get; set; } = string.Empty;
}

// ── Transaction DTOs ───────────────────────────────────────────────────────
public class DepositRequest
{
    [Required, Range(0.01, 50000)]
    public decimal Amount      { get; set; }
    public string? Description { get; set; }
}

public class WithdrawalRequest
{
    [Required, Range(0.01, 50000)]
    public decimal Amount      { get; set; }
    public string? Description { get; set; }
}

public class TransferRequest
{
    [Required, Range(0.01, 50000)]
    public decimal Amount             { get; set; }

    [Required, MaxLength(20)]
    public string  DestinationAccount { get; set; } = string.Empty;

    public string? Description        { get; set; }
}

public class TransactionResponse
{
    public int      Id           { get; set; }
    public string   Type         { get; set; } = string.Empty;
    public decimal  Amount       { get; set; }
    public decimal  BalanceAfter { get; set; }
    public string?  Description  { get; set; }
    public string   Signature    { get; set; } = string.Empty;
    public DateTime CreatedAt    { get; set; }
}

// ── Account DTOs ───────────────────────────────────────────────────────────
public class AccountResponse
{
    public int     Id            { get; set; }
    public string  AccountNumber { get; set; } = string.Empty;
    public decimal Balance       { get; set; }
    public string  AccountType   { get; set; } = string.Empty;
}

// ── Admin DTOs ─────────────────────────────────────────────────────────────
public class UserManagementResponse
{
    public int      Id                  { get; set; }
    public string   Username            { get; set; } = string.Empty;
    public string   Email               { get; set; } = string.Empty;
    public string   Role                { get; set; } = string.Empty;
    public bool     IsLocked            { get; set; }
    public int      FailedLoginAttempts { get; set; }
    public bool     MfaEnabled          { get; set; }
    public DateTime CreatedAt           { get; set; }
    public DateTime? LastLoginAt        { get; set; }
}

public class UpdateRoleRequest
{
    [Required, RegularExpression("Customer|Teller|Admin")]
    public string Role { get; set; } = string.Empty;
}

// ── Audit DTOs ─────────────────────────────────────────────────────────────
public class AuditLogResponse
{
    public int      Id            { get; set; }
    public string?  Username      { get; set; }
    public string   Action        { get; set; } = string.Empty;
    public string   EntityType    { get; set; } = string.Empty;
    public string   IpAddress     { get; set; } = string.Empty;
    public bool     Success       { get; set; }
    public string?  FailureReason { get; set; }
    public string   CurrentHash   { get; set; } = string.Empty;
    public DateTime CreatedAt     { get; set; }
}

// ── Generic Responses ──────────────────────────────────────────────────────
public class ApiResponse<T>
{
    public bool   Success { get; set; }
    public string Message { get; set; } = string.Empty;
    public T?     Data    { get; set; }

    public static ApiResponse<T> Ok(T data, string message = "Success")
        => new() { Success = true, Message = message, Data = data };

    public static ApiResponse<T> Fail(string message)
        => new() { Success = false, Message = message };
}
