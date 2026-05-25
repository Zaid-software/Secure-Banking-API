using Microsoft.EntityFrameworkCore;
using SecureBankingAPI.Models;

namespace SecureBankingAPI.Data;

public class ApplicationDbContext : DbContext
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options) { }

    public DbSet<User>        Users        { get; set; }
    public DbSet<Account>     Accounts     { get; set; }
    public DbSet<Transaction> Transactions { get; set; }
    public DbSet<FileUpload>  FileUploads  { get; set; }
    public DbSet<AuditLog>    AuditLogs    { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // User — unique constraints
        modelBuilder.Entity<User>()
            .HasIndex(u => u.Username).IsUnique();
        modelBuilder.Entity<User>()
            .HasIndex(u => u.Email).IsUnique();

        // Account — unique account number
        modelBuilder.Entity<Account>()
            .HasIndex(a => a.AccountNumber).IsUnique();

        // Account → User (one user, many accounts)
        modelBuilder.Entity<Account>()
            .HasOne(a => a.User)
            .WithMany()
            .HasForeignKey(a => a.UserId)
            .OnDelete(DeleteBehavior.Restrict);

        // Transaction → Account
        modelBuilder.Entity<Transaction>()
            .HasOne(t => t.Account)
            .WithMany(a => a.Transactions)
            .HasForeignKey(t => t.AccountId)
            .OnDelete(DeleteBehavior.Restrict);

        // Transaction → User
        modelBuilder.Entity<Transaction>()
            .HasOne(t => t.User)
            .WithMany(u => u.Transactions)
            .HasForeignKey(t => t.UserId)
            .OnDelete(DeleteBehavior.Restrict);

        // AuditLog — append-only, no cascade deletes
        modelBuilder.Entity<AuditLog>()
            .HasOne(a => a.User)
            .WithMany(u => u.AuditLogs)
            .HasForeignKey(a => a.UserId)
            .OnDelete(DeleteBehavior.SetNull);

        // Decimal precision
        modelBuilder.Entity<Transaction>()
            .Property(t => t.Amount).HasPrecision(18, 2);
        modelBuilder.Entity<Transaction>()
            .Property(t => t.BalanceAfter).HasPrecision(18, 2);
        modelBuilder.Entity<Account>()
            .Property(a => a.Balance).HasPrecision(18, 2);
    }
}
