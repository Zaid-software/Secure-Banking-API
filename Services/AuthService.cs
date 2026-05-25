using Microsoft.EntityFrameworkCore;
using SecureBankingAPI.Data;
using SecureBankingAPI.DTOs;
using SecureBankingAPI.Models;
using SecureBankingAPI.Configuration;
using BC = BCrypt.Net.BCrypt;

namespace SecureBankingAPI.Services;

public interface IAuthService
{
    Task<(bool Success, string Message, User? User)> RegisterAsync(RegisterRequest request);
    Task<(bool Success, string Message, User? User, bool MfaRequired)> LoginAsync(LoginRequest request, string ipAddress);
    Task<bool> UnlockAccountAsync(int userId);
}

public class AuthService : IAuthService
{
    private readonly ApplicationDbContext _db;
    private readonly AppSettings _settings;
    private readonly IAuditService _audit;
    private readonly ITotpService _totp;

    public AuthService(ApplicationDbContext db,
                       IConfiguration config,
                       IAuditService audit,
                       ITotpService totp)
    {
        _db = db;
        _settings = config.GetSection("AppSettings").Get<AppSettings>()!;
        _audit = audit;
        _totp = totp;
    }

    public async Task<(bool Success, string Message, User? User)> RegisterAsync(RegisterRequest request)
    {
        // Check duplicate username/email
        if (await _db.Users.AnyAsync(u => u.Username == request.Username))
            return (false, "Username already exists.", null);

        if (await _db.Users.AnyAsync(u => u.Email == request.Email))
            return (false, "Email already registered.", null);

        // Hash password with bcrypt (work factor 12)
        var passwordHash = BC.HashPassword(request.Password, workFactor: 12);

        var user = new User
        {
            Username = request.Username,
            Email = request.Email,
            PasswordHash = passwordHash,
            Role = "Customer",
        };

        _db.Users.Add(user);
        await _db.SaveChangesAsync();

        // Create default checking account
        var account = new Account
        {
            UserId = user.Id,
            AccountNumber = GenerateAccountNumber(),
            AccountType = "Checking",
            Balance = 0
        };
        _db.Accounts.Add(account);
        await _db.SaveChangesAsync();

        await _audit.LogAsync(user.Id, "Register", "User", user.Id.ToString(),
                              null, null, "system", true);

        return (true, "Registration successful.", user);
    }

    public async Task<(bool Success, string Message, User? User, bool MfaRequired)>
        LoginAsync(LoginRequest request, string ipAddress)
    {
        var user = await _db.Users
            .FirstOrDefaultAsync(u => u.Username == request.Username);

        // User not found — generic message (don't reveal existence)
        if (user is null)
        {
            await _audit.LogAsync(null, "Login", "User", request.Username,
                                  null, null, ipAddress, false, "User not found");
            return (false, "Invalid username or password.", null, false);
        }

        // Account lockout check
        if (user.IsLocked)
        {
            if (user.LockedUntil.HasValue && user.LockedUntil > DateTime.UtcNow)
            {
                await _audit.LogAsync(user.Id, "Login", "User", user.Id.ToString(),
                                      null, null, ipAddress, false, "Account locked");
                return (false, "Account is locked. Please try again later.", null, false);
            }
            // Lockout expired — unlock
            user.IsLocked = false;
            user.FailedLoginAttempts = 0;
            user.LockedUntil = null;
        }

        // Verify password using bcrypt
        if (!BC.Verify(request.Password, user.PasswordHash))
        {
            user.FailedLoginAttempts++;

            if (user.FailedLoginAttempts >= _settings.MaxLoginAttempts)
            {
                user.IsLocked = true;
                user.LockedUntil = DateTime.UtcNow.AddMinutes(_settings.LockoutMinutes);
                await _db.SaveChangesAsync();
                await _audit.LogAsync(user.Id, "Login", "User", user.Id.ToString(),
                                      null, null, ipAddress, false,
                                      $"Account locked after {_settings.MaxLoginAttempts} failed attempts");
                return (false, "Account locked due to too many failed attempts.", null, false);
            }

            await _db.SaveChangesAsync();
            await _audit.LogAsync(user.Id, "Login", "User", user.Id.ToString(),
                                  null, null, ipAddress, false, "Invalid password");
            return (false, "Invalid username or password.", null, false);
        }

        // MFA check
        if (user.MfaEnabled)
        {
            if (string.IsNullOrEmpty(request.TotpCode))
                return (true, "MFA code required.", user, true);

            if (!_totp.Verify(user.TotpSecret!, request.TotpCode))
            {
                await _audit.LogAsync(user.Id, "Login", "User", user.Id.ToString(),
                                      null, null, ipAddress, false, "Invalid MFA code");
                return (false, "Invalid MFA code.", null, false);
            }
        }

        // Successful login — reset failed attempts
        user.FailedLoginAttempts = 0;
        user.IsLocked = false;
        user.LastLoginAt = DateTime.UtcNow;
        await _db.SaveChangesAsync();

        await _audit.LogAsync(user.Id, "Login", "User", user.Id.ToString(),
                              null, null, ipAddress, true);

        return (true, "Login successful.", user, false);
    }

    public async Task<bool> UnlockAccountAsync(int userId)
    {
        var user = await _db.Users.FindAsync(userId);
        if (user is null) return false;

        user.IsLocked = false;
        user.FailedLoginAttempts = 0;
        user.LockedUntil = null;
        await _db.SaveChangesAsync();
        return true;
    }

    private static string GenerateAccountNumber()
    {
        // Cryptographically random 10-digit account number
        var bytes = new byte[8];
        System.Security.Cryptography.RandomNumberGenerator.Fill(bytes);
        var number = Math.Abs(BitConverter.ToInt64(bytes, 0)) % 9_000_000_000L + 1_000_000_000L;
        return number.ToString();
    }
}
