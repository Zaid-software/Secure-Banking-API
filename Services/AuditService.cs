using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SecureBankingAPI.Data;
using SecureBankingAPI.DTOs;
using SecureBankingAPI.Models;

namespace SecureBankingAPI.Services;

public interface IAuditService
{
    Task LogAsync(int? userId, string action, string entityType, string? entityId,
                  string? oldValues, string? newValues, string ipAddress,
                  bool success, string? failureReason = null, string? userAgent = null);

    Task<IEnumerable<AuditLogResponse>> GetLogsAsync(int page, int pageSize);
    Task<bool> VerifyIntegrityAsync();
}

public class AuditService : IAuditService
{
    private readonly ApplicationDbContext _db;

    public AuditService(ApplicationDbContext db)
    {
        _db = db;
    }

    public async Task LogAsync(int? userId, string action, string entityType,
                               string? entityId, string? oldValues, string? newValues,
                               string ipAddress, bool success,
                               string? failureReason = null, string? userAgent = null)
    {
        // Get hash of the last log entry (hash chain for tamper detection)
        var lastLog      = await _db.AuditLogs.OrderByDescending(l => l.Id).FirstOrDefaultAsync();
        var previousHash = lastLog?.CurrentHash ?? "GENESIS";

        var entry = new AuditLog
        {
            UserId        = userId,
            Action        = action,
            EntityType    = entityType,
            EntityId      = entityId,
            OldValues     = oldValues,
            NewValues     = newValues,
            IpAddress     = ipAddress,
            UserAgent     = userAgent,
            Success       = success,
            FailureReason = failureReason,
            PreviousHash  = previousHash,
            CreatedAt     = DateTime.UtcNow,
        };

        // Compute hash of this entry (includes previous hash — forms a chain)
        entry.CurrentHash = ComputeHash(entry);

        _db.AuditLogs.Add(entry);
        await _db.SaveChangesAsync();
    }

    public async Task<IEnumerable<AuditLogResponse>> GetLogsAsync(int page, int pageSize)
    {
        return await _db.AuditLogs
            .Include(l => l.User)
            .OrderByDescending(l => l.CreatedAt)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(l => new AuditLogResponse
            {
                Id            = l.Id,
                Username      = l.User != null ? l.User.Username : null,
                Action        = l.Action,
                EntityType    = l.EntityType,
                IpAddress     = l.IpAddress,
                Success       = l.Success,
                FailureReason = l.FailureReason,
                CurrentHash   = l.CurrentHash,
                CreatedAt     = l.CreatedAt,
            })
            .ToListAsync();
    }

    /// <summary>
    /// Verify the hash chain — detects any tampered log entries.
    /// </summary>
    public async Task<bool> VerifyIntegrityAsync()
    {
        var logs = await _db.AuditLogs
            .OrderBy(l => l.Id)
            .ToListAsync();

        for (int i = 0; i < logs.Count; i++)
        {
            var expectedHash = ComputeHash(logs[i]);
            if (logs[i].CurrentHash != expectedHash)
                return false;

            if (i > 0 && logs[i].PreviousHash != logs[i - 1].CurrentHash)
                return false;
        }
        return true;
    }

    private static string ComputeHash(AuditLog entry)
    {
        var payload = $"{entry.UserId}|{entry.Action}|{entry.EntityType}|" +
                      $"{entry.EntityId}|{entry.IpAddress}|{entry.Success}|" +
                      $"{entry.CreatedAt:O}|{entry.PreviousHash}";

        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(payload));
        return Convert.ToHexString(bytes);
    }
}
