using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace SecureBankingAPI.Models;

// ── User ───────────────────────────────────────────────────────────────────
public class User
{
    public int      Id                  { get; set; }

    [Required, MaxLength(100)]
    public string   Username            { get; set; } = string.Empty;

    [Required, MaxLength(256)]
    public string   Email               { get; set; } = string.Empty;

    [Required]
    public string   PasswordHash        { get; set; } = string.Empty;  // bcrypt hash

    [Required, MaxLength(20)]
    public string   Role                { get; set; } = "Customer";    // Customer | Teller | Admin

    public bool     IsLocked            { get; set; } = false;
    public int      FailedLoginAttempts { get; set; } = 0;
    public DateTime? LockedUntil        { get; set; }
    public bool     MfaEnabled          { get; set; } = false;
    public string?  TotpSecret          { get; set; }                  // encrypted TOTP secret
    public DateTime CreatedAt           { get; set; } = DateTime.UtcNow;
    public DateTime? LastLoginAt        { get; set; }

    public ICollection<Transaction> Transactions { get; set; } = new List<Transaction>();
    public ICollection<AuditLog>    AuditLogs    { get; set; } = new List<AuditLog>();
}

// ── Account ────────────────────────────────────────────────────────────────
public class Account
{
    public int     Id            { get; set; }
    public int     UserId        { get; set; }

    [Required, MaxLength(20)]
    public string  AccountNumber { get; set; } = string.Empty;

    [Column(TypeName = "decimal(18,2)")]
    public decimal Balance       { get; set; } = 0;

    [Required, MaxLength(20)]
    public string  AccountType   { get; set; } = "Checking";   // Checking | Savings
    public bool    IsActive      { get; set; } = true;
    public DateTime CreatedAt    { get; set; } = DateTime.UtcNow;

    public User                  User         { get; set; } = null!;
    public ICollection<Transaction> Transactions { get; set; } = new List<Transaction>();
}

// ── Transaction ────────────────────────────────────────────────────────────
public class Transaction
{
    public int     Id                { get; set; }
    public int     AccountId         { get; set; }
    public int     UserId            { get; set; }

    [Required, MaxLength(20)]
    public string  Type              { get; set; } = string.Empty;   // Deposit | Withdrawal | Transfer

    [Column(TypeName = "decimal(18,2)")]
    public decimal Amount            { get; set; }

    [Column(TypeName = "decimal(18,2)")]
    public decimal BalanceAfter      { get; set; }

    public string? Description       { get; set; }
    public string? DestinationAccount { get; set; }

    // Cryptographic signature for tamper detection
    public string  Signature         { get; set; } = string.Empty;

    public DateTime CreatedAt        { get; set; } = DateTime.UtcNow;

    public Account Account           { get; set; } = null!;
    public User    User              { get; set; } = null!;
}

// ── FileUpload ─────────────────────────────────────────────────────────────
public class FileUpload
{
    public int      Id               { get; set; }
    public int      UserId           { get; set; }
    public string   OriginalFileName { get; set; } = string.Empty;
    public string   StoredFileName   { get; set; } = string.Empty;  // server-generated UUID name
    public string   MimeType         { get; set; } = string.Empty;
    public long     FileSizeBytes    { get; set; }
    public string   StoragePath      { get; set; } = string.Empty;
    public bool     IsEncrypted      { get; set; } = true;
    public string   ScanResult       { get; set; } = "Pending";
    public DateTime UploadedAt       { get; set; } = DateTime.UtcNow;

    public User     User             { get; set; } = null!;
}

// ── AuditLog ───────────────────────────────────────────────────────────────
public class AuditLog
{
    public int      Id          { get; set; }
    public int?     UserId      { get; set; }
    public string   Action      { get; set; } = string.Empty;
    public string   EntityType  { get; set; } = string.Empty;
    public string?  EntityId    { get; set; }
    public string?  OldValues   { get; set; }
    public string?  NewValues   { get; set; }
    public string   IpAddress   { get; set; } = string.Empty;
    public string?  UserAgent   { get; set; }
    public bool     Success     { get; set; }
    public string?  FailureReason { get; set; }

    // Hash of previous log entry — forms integrity chain
    public string   PreviousHash { get; set; } = string.Empty;
    public string   CurrentHash  { get; set; } = string.Empty;

    public DateTime CreatedAt   { get; set; } = DateTime.UtcNow;

    public User?    User        { get; set; }
}
