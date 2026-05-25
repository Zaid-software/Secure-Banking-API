namespace SecureBankingAPI.Configuration;

public class JwtSettings
{
    public string SecretKey   { get; set; } = string.Empty;
    public string Issuer      { get; set; } = string.Empty;
    public string Audience    { get; set; } = string.Empty;
    public int    ExpiryMinutes { get; set; } = 30;
}

public class AppSettings
{
    public int      MaxLoginAttempts      { get; set; } = 5;
    public int      LockoutMinutes        { get; set; } = 15;
    public int      FileUploadMaxSizeMb   { get; set; } = 5;
    public string[] AllowedFileExtensions { get; set; } = Array.Empty<string>();
    public string   FileStoragePath       { get; set; } = "SecureStorage/Uploads";
}
