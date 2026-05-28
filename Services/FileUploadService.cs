using System.Security.Cryptography;
using SecureBankingAPI.Configuration;
using SecureBankingAPI.Data;
using SecureBankingAPI.Models;

namespace SecureBankingAPI.Services;

public interface IFileUploadService
{
    Task<(bool Success, string Message, FileUpload? Upload)>
        ProcessUploadAsync(int userId, IFormFile file, string ipAddress);

    Task<(bool Success, byte[]? FileData, string? MimeType)>
        GetFileAsync(int fileId, int userId);
}

public class FileUploadService : IFileUploadService
{
    private readonly ApplicationDbContext _db;
    private readonly AppSettings          _settings;
    private readonly IAuditService        _audit;
    private readonly IWebHostEnvironment  _env;

    // Magic number signatures for allowed file types
    private static readonly Dictionary<string, byte[]> MagicNumbers = new()
    {
        { "image/jpeg", new byte[] { 0xFF, 0xD8, 0xFF } },
        { "image/png",  new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A } },
    };

    public FileUploadService(ApplicationDbContext db, IConfiguration config,
                             IAuditService audit, IWebHostEnvironment env)
    {
        _db       = db;
        _settings = config.GetSection("AppSettings").Get<AppSettings>()!;
        _audit    = audit;
        _env      = env;
    }

    public async Task<(bool Success, string Message, FileUpload? Upload)>
        ProcessUploadAsync(int userId, IFormFile file, string ipAddress)
    {
        // 1. File size validation
        var maxBytes = _settings.FileUploadMaxSizeMb * 1024 * 1024;
        if (file.Length > maxBytes)
            return (false, $"File exceeds maximum size of {_settings.FileUploadMaxSizeMb}MB.", null);

        if (file.Length == 0)
            return (false, "File is empty.", null);

        // 2. Extension validation
        var extension = Path.GetExtension(file.FileName).ToLowerInvariant();
        if (!_settings.AllowedFileExtensions.Contains(extension))
            return (false, "File type not allowed. Only JPG and PNG are accepted.", null);

        // 3. Read file bytes for magic number check
        using var ms = new MemoryStream();
        await file.CopyToAsync(ms);
        var fileBytes = ms.ToArray();

        // 4. Magic number validation (not just extension)
        var detectedMime = DetectMimeType(fileBytes);
        if (detectedMime is null)
        {
            await _audit.LogAsync(userId, "FileUpload", "FileUpload", null, null, null,
                                  ipAddress, false, "Failed magic number validation");
            return (false, "File content does not match a supported image format.", null);
        }

        // 5. Simulated virus scan
        var scanResult = SimulateVirusScan(fileBytes);
        if (scanResult == "Infected")
        {
            await _audit.LogAsync(userId, "FileUpload", "FileUpload", null, null, null,
                                  ipAddress, false, "Virus scan failed");
            return (false, "File failed security scan.", null);
        }

        // 6. Server-generated filename (never use user-provided name)
        var storedFileName = $"{Guid.NewGuid()}{extension}";
        var storagePath    = Path.Combine(_env.ContentRootPath, _settings.FileStoragePath);
        Directory.CreateDirectory(storagePath);
        var fullPath = Path.Combine(storagePath, storedFileName);

        // 7. AES-256 encryption at rest
        var encryptedBytes = EncryptFile(fileBytes);
        await File.WriteAllBytesAsync(fullPath, encryptedBytes);

        // 8. Record upload
        var upload = new FileUpload
        {
            UserId           = userId,
            OriginalFileName = Path.GetFileName(file.FileName),  // sanitized display only
            StoredFileName   = storedFileName,
            MimeType         = detectedMime,
            FileSizeBytes    = file.Length,
            StoragePath      = fullPath,
            IsEncrypted      = true,
            ScanResult       = scanResult,
        };

        _db.FileUploads.Add(upload);
        await _db.SaveChangesAsync();

        await _audit.LogAsync(userId, "FileUpload", "FileUpload", upload.Id.ToString(),
                              null, null, ipAddress, true);

        return (true, "File uploaded successfully.", upload);
    }

    public async Task<(bool Success, byte[]? FileData, string? MimeType)>
        GetFileAsync(int fileId, int userId)
    {
        var upload = await _db.FileUploads.FindAsync(fileId);

        // Ownership check — users can only access their own files
        if (upload is null || upload.UserId != userId)
            return (false, null, null);

        var encryptedBytes = await File.ReadAllBytesAsync(upload.StoragePath);
        var decryptedBytes = DecryptFile(encryptedBytes);

        return (true, decryptedBytes, upload.MimeType);
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    private static string? DetectMimeType(byte[] fileBytes)
    {
        foreach (var (mime, magic) in MagicNumbers)
        {
            if (fileBytes.Length >= magic.Length &&
                fileBytes.Take(magic.Length).SequenceEqual(magic))
                return mime;
        }
        return null;
    }

    private static string SimulateVirusScan(byte[] fileBytes)
    {
        // Simulated scan — checks for EICAR test string
        var content = System.Text.Encoding.ASCII.GetString(
            fileBytes.Take(Math.Min(fileBytes.Length, 100)).ToArray());

        return content.Contains("X5O!P%@AP[4\\PZX54(P^)7CC)7}") ? "Infected" : "Clean";
    }

    private static byte[] EncryptFile(byte[] data)
    {
        // AES-256-CBC encryption at rest
        // In production: use Azure Key Vault for key storage
        using var aes = Aes.Create();
        aes.KeySize = 256;
        aes.GenerateKey();
        aes.GenerateIV();

        using var encryptor = aes.CreateEncryptor();
        var encrypted = encryptor.TransformFinalBlock(data, 0, data.Length);

        // Prepend key + IV to encrypted data (in production, store key separately)
        var result = new byte[aes.Key.Length + aes.IV.Length + encrypted.Length];
        Buffer.BlockCopy(aes.Key, 0, result, 0, aes.Key.Length);
        Buffer.BlockCopy(aes.IV, 0, result, aes.Key.Length, aes.IV.Length);
        Buffer.BlockCopy(encrypted, 0, result, aes.Key.Length + aes.IV.Length, encrypted.Length);

        return result;
    }

    private static byte[] DecryptFile(byte[] data)
    {
        using var aes = Aes.Create();
        aes.KeySize = 256;

        var key       = new byte[32];
        var iv        = new byte[16];
        var encrypted = new byte[data.Length - 48];

        Buffer.BlockCopy(data, 0,  key,       0, 32);
        Buffer.BlockCopy(data, 32, iv,        0, 16);
        Buffer.BlockCopy(data, 48, encrypted, 0, encrypted.Length);

        aes.Key = key;
        aes.IV  = iv;

        using var decryptor = aes.CreateDecryptor();
        return decryptor.TransformFinalBlock(encrypted, 0, encrypted.Length);
    }
}
