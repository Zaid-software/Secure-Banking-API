using OtpNet;
using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using SecureBankingAPI.Data;
using SecureBankingAPI.DTOs;
using SecureBankingAPI.Models;

namespace SecureBankingAPI.Services;

// ── TOTP / MFA Service ────────────────────────────────────────────────────
public interface ITotpService
{
    (string Secret, string QrUri) GenerateSecret(string username);
    bool Verify(string encryptedSecret, string code);
    string EncryptSecret(string secret);
    string DecryptSecret(string encryptedSecret);
}

public class TotpService : ITotpService
{
    private readonly byte[] _encryptionKey;

    public TotpService(IConfiguration config)
    {
        // Derive encryption key from JWT secret
        var jwtKey  = config["JwtSettings:SecretKey"] ?? "fallback";
        _encryptionKey = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(jwtKey));
    }

    public (string Secret, string QrUri) GenerateSecret(string username)
    {
        var secretBytes = KeyGeneration.GenerateRandomKey(20);
        var secret      = Base32Encoding.ToString(secretBytes);
        var qrUri       = $"otpauth://totp/SecureBank:{username}?secret={secret}&issuer=SecureBank";
        return (secret, qrUri);
    }

    public bool Verify(string encryptedSecret, string code)
    {
        try
        {
            var secret      = DecryptSecret(encryptedSecret);
            var secretBytes = Base32Encoding.ToBytes(secret);
            var totp        = new Totp(secretBytes);

            // Allow 1 window tolerance (30s before/after)
            return totp.VerifyTotp(code, out _, new VerificationWindow(1, 1));
        }
        catch
        {
            return false;
        }
    }

    public string EncryptSecret(string secret)
    {
        using var aes = Aes.Create();
        aes.Key = _encryptionKey;
        aes.GenerateIV();

        using var encryptor = aes.CreateEncryptor();
        var bytes     = System.Text.Encoding.UTF8.GetBytes(secret);
        var encrypted = encryptor.TransformFinalBlock(bytes, 0, bytes.Length);

        var result = new byte[aes.IV.Length + encrypted.Length];
        Buffer.BlockCopy(aes.IV, 0, result, 0, aes.IV.Length);
        Buffer.BlockCopy(encrypted, 0, result, aes.IV.Length, encrypted.Length);
        return Convert.ToBase64String(result);
    }

    public string DecryptSecret(string encryptedSecret)
    {
        var data = Convert.FromBase64String(encryptedSecret);
        using var aes = Aes.Create();
        aes.Key = _encryptionKey;

        var iv        = new byte[16];
        var encrypted = new byte[data.Length - 16];
        Buffer.BlockCopy(data, 0,  iv,        0, 16);
        Buffer.BlockCopy(data, 16, encrypted, 0, encrypted.Length);

        aes.IV = iv;
        using var decryptor = aes.CreateDecryptor();
        var decrypted = decryptor.TransformFinalBlock(encrypted, 0, encrypted.Length);
        return System.Text.Encoding.UTF8.GetString(decrypted);
    }
}

// ── User Management Service ───────────────────────────────────────────────
public interface IUserService
{
    Task<IEnumerable<UserManagementResponse>> GetAllUsersAsync();
    Task<bool> UpdateRoleAsync(int userId, string role, int adminId, string ipAddress);
    Task<bool> UnlockUserAsync(int userId, int adminId, string ipAddress);
}

public class UserService : IUserService
{
    private readonly ApplicationDbContext _db;
    private readonly IAuditService        _audit;

    public UserService(ApplicationDbContext db, IAuditService audit)
    {
        _db    = db;
        _audit = audit;
    }

    public async Task<IEnumerable<UserManagementResponse>> GetAllUsersAsync()
    {
        return await _db.Users
            .Select(u => new UserManagementResponse
            {
                Id                  = u.Id,
                Username            = u.Username,
                Email               = u.Email,
                Role                = u.Role,
                IsLocked            = u.IsLocked,
                FailedLoginAttempts = u.FailedLoginAttempts,
                MfaEnabled          = u.MfaEnabled,
                CreatedAt           = u.CreatedAt,
                LastLoginAt         = u.LastLoginAt,
            })
            .ToListAsync();
    }

    public async Task<bool> UpdateRoleAsync(int userId, string role, int adminId, string ipAddress)
    {
        var user = await _db.Users.FindAsync(userId);
        if (user is null) return false;

        var oldRole  = user.Role;
        user.Role    = role;
        await _db.SaveChangesAsync();

        await _audit.LogAsync(adminId, "UpdateRole", "User", userId.ToString(),
                              oldRole, role, ipAddress, true);
        return true;
    }

    public async Task<bool> UnlockUserAsync(int userId, int adminId, string ipAddress)
    {
        var user = await _db.Users.FindAsync(userId);
        if (user is null) return false;

        user.IsLocked            = false;
        user.FailedLoginAttempts = 0;
        user.LockedUntil         = null;
        await _db.SaveChangesAsync();

        await _audit.LogAsync(adminId, "UnlockUser", "User", userId.ToString(),
                              null, null, ipAddress, true);
        return true;
    }
}
