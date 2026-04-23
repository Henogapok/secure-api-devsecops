using SecureApi.Services;

namespace SecureApi.Tests;

public class AesEncryptionServiceTests
{
    [Fact]
    public void Encrypt_And_Decrypt_Should_Return_Original_Text()
    {
        var service = new AesEncryptionService();
        var original = "Hello Secure World";

        var encrypted = service.Encrypt(original);
        var decrypted = service.Decrypt(encrypted);

        Assert.Equal(original, decrypted);
    }
}