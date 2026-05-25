using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SecureBankingAPI.Data;
using SecureBankingAPI.DTOs;
using SecureBankingAPI.Models;

namespace SecureBankingAPI.Services;

public interface ITransactionService
{
    Task<(bool Success, string Message, TransactionResponse? Transaction)>
        DepositAsync(int userId, DepositRequest request, string ipAddress);

    Task<(bool Success, string Message, TransactionResponse? Transaction)>
        WithdrawAsync(int userId, WithdrawalRequest request, string ipAddress);

    Task<(bool Success, string Message, TransactionResponse? Transaction)>
        TransferAsync(int userId, TransferRequest request, string ipAddress);

    Task<IEnumerable<TransactionResponse>> GetHistoryAsync(int userId);
    Task<AccountResponse?> GetAccountAsync(int userId);
}

public class TransactionService : ITransactionService
{
    private readonly ApplicationDbContext _db;
    private readonly IAuditService        _audit;
    private readonly IConfiguration       _config;

    public TransactionService(ApplicationDbContext db, IAuditService audit, IConfiguration config)
    {
        _db     = db;
        _audit  = audit;
        _config = config;
    }

    public async Task<(bool Success, string Message, TransactionResponse? Transaction)>
        DepositAsync(int userId, DepositRequest request, string ipAddress)
    {
        // All DB access via EF Core — parameterized queries by default (no raw SQL)
        var account = await _db.Accounts
            .FirstOrDefaultAsync(a => a.UserId == userId && a.IsActive);

        if (account is null)
            return (false, "Account not found.", null);

        account.Balance += request.Amount;

        var transaction = CreateTransaction(account, userId, "Deposit",
                                            request.Amount, request.Description);
        _db.Transactions.Add(transaction);
        await _db.SaveChangesAsync();

        await _audit.LogAsync(userId, "Deposit", "Transaction",
                              transaction.Id.ToString(), null,
                              JsonSerializer.Serialize(new { request.Amount }),
                              ipAddress, true);

        return (true, "Deposit successful.", MapToResponse(transaction));
    }

    public async Task<(bool Success, string Message, TransactionResponse? Transaction)>
        WithdrawAsync(int userId, WithdrawalRequest request, string ipAddress)
    {
        var account = await _db.Accounts
            .FirstOrDefaultAsync(a => a.UserId == userId && a.IsActive);

        if (account is null)
            return (false, "Account not found.", null);

        if (account.Balance < request.Amount)
        {
            await _audit.LogAsync(userId, "Withdrawal", "Transaction", null, null, null,
                                  ipAddress, false, "Insufficient funds");
            return (false, "Insufficient funds.", null);
        }

        account.Balance -= request.Amount;

        var transaction = CreateTransaction(account, userId, "Withdrawal",
                                            request.Amount, request.Description);
        _db.Transactions.Add(transaction);
        await _db.SaveChangesAsync();

        await _audit.LogAsync(userId, "Withdrawal", "Transaction",
                              transaction.Id.ToString(), null,
                              JsonSerializer.Serialize(new { request.Amount }),
                              ipAddress, true);

        return (true, "Withdrawal successful.", MapToResponse(transaction));
    }

    public async Task<(bool Success, string Message, TransactionResponse? Transaction)>
        TransferAsync(int userId, TransferRequest request, string ipAddress)
    {
        var sourceAccount = await _db.Accounts
            .FirstOrDefaultAsync(a => a.UserId == userId && a.IsActive);

        if (sourceAccount is null)
            return (false, "Source account not found.", null);

        // Parameterized query via EF Core — safe from SQL injection
        var destAccount = await _db.Accounts
            .FirstOrDefaultAsync(a => a.AccountNumber == request.DestinationAccount && a.IsActive);

        if (destAccount is null)
            return (false, "Destination account not found.", null);

        if (sourceAccount.Id == destAccount.Id)
            return (false, "Cannot transfer to the same account.", null);

        if (sourceAccount.Balance < request.Amount)
            return (false, "Insufficient funds.", null);

        // Atomic transfer
        sourceAccount.Balance -= request.Amount;
        destAccount.Balance   += request.Amount;

        var transaction = CreateTransaction(sourceAccount, userId, "Transfer",
                                            request.Amount, request.Description,
                                            request.DestinationAccount);
        _db.Transactions.Add(transaction);
        await _db.SaveChangesAsync();

        await _audit.LogAsync(userId, "Transfer", "Transaction",
                              transaction.Id.ToString(), null,
                              JsonSerializer.Serialize(new { request.Amount, request.DestinationAccount }),
                              ipAddress, true);

        return (true, "Transfer successful.", MapToResponse(transaction));
    }

    public async Task<IEnumerable<TransactionResponse>> GetHistoryAsync(int userId)
    {
        var account = await _db.Accounts
            .FirstOrDefaultAsync(a => a.UserId == userId && a.IsActive);

        if (account is null) return Enumerable.Empty<TransactionResponse>();

        return await _db.Transactions
            .Where(t => t.AccountId == account.Id)
            .OrderByDescending(t => t.CreatedAt)
            .Take(50)
            .Select(t => MapToResponse(t))
            .ToListAsync();
    }

    public async Task<AccountResponse?> GetAccountAsync(int userId)
    {
        var account = await _db.Accounts
            .FirstOrDefaultAsync(a => a.UserId == userId && a.IsActive);

        if (account is null) return null;

        return new AccountResponse
        {
            Id            = account.Id,
            AccountNumber = account.AccountNumber,
            Balance       = account.Balance,
            AccountType   = account.AccountType
        };
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    private Transaction CreateTransaction(Account account, int userId, string type,
                                          decimal amount, string? description,
                                          string? destination = null)
    {
        var balanceAfter = account.Balance;
        var signature    = SignTransaction(account.AccountNumber, type, amount, balanceAfter);

        return new Transaction
        {
            AccountId          = account.Id,
            UserId             = userId,
            Type               = type,
            Amount             = amount,
            BalanceAfter       = balanceAfter,
            Description        = description,
            DestinationAccount = destination,
            Signature          = signature,
            CreatedAt          = DateTime.UtcNow
        };
    }

    /// <summary>
    /// HMAC-SHA256 transaction signature for tamper detection.
    /// </summary>
    private string SignTransaction(string accountNumber, string type,
                                   decimal amount, decimal balanceAfter)
    {
        var signingKey = _config["JwtSettings:SecretKey"] ?? "fallback-key";
        var payload    = $"{accountNumber}|{type}|{amount}|{balanceAfter}|{DateTime.UtcNow:yyyyMMddHH}";

        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(signingKey));
        var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(payload));
        return Convert.ToBase64String(hash);
    }

    private static TransactionResponse MapToResponse(Transaction t) => new()
    {
        Id           = t.Id,
        Type         = t.Type,
        Amount       = t.Amount,
        BalanceAfter = t.BalanceAfter,
        Description  = t.Description,
        Signature    = t.Signature,
        CreatedAt    = t.CreatedAt
    };
}
