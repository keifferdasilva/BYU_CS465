using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Logging;

internal sealed class EncryptedEchoServer : EchoServerBase {

    /// <summary>
    /// Logger to use in this class.
    /// </summary>
    private ILogger<EncryptedEchoServer> Logger { get; init; } =
        Settings.LoggerFactory.CreateLogger<EncryptedEchoServer>()!;

    /// <inheritdoc />
    internal EncryptedEchoServer(ushort port) : base(port) { }

    // todo: Step 1: Generate a RSA key (2048 bits) for the server.
    RSA rsaKey = RSA.Create(2048);
           
    /// <inheritdoc />
    public override string GetServerHello() {
        // todo: Step 1: Send the public key to the client in PKCS#1 format.
        // Encode using Base64: Convert.ToBase64String
        var publicKey = rsaKey.ExportRSAPublicKey();
        return Convert.ToBase64String(publicKey);
    }

    /// <inheritdoc />
    public override string TransformIncomingMessage(string input) {
        // todo: Step 1: Deserialize the message.
        var message = JsonSerializer.Deserialize<EncryptedMessage>(input);
        
        // todo: Step 2: Decrypt the message using hybrid encryption.
        Aes aesDecryptor = Aes.Create();
        aesDecryptor.Key = rsaKey.Decrypt(message.AesKeyWrap, RSAEncryptionPadding.OaepSHA256);
        HMACSHA256 hmac = new(rsaKey.Decrypt(message.HMACKeyWrap, RSAEncryptionPadding.OaepSHA256));
        var decryptedMessage = aesDecryptor.DecryptCbc(message.Message, message.AESIV, PaddingMode.PKCS7);
        var decryptedMessageHash = hmac.ComputeHash(decryptedMessage);
        // todo: Step 3: Verify the HMAC.
        // Throw an InvalidSignatureException if the received hmac is bad.
        if(!message.HMAC.SequenceEqual(decryptedMessageHash)){
            throw new InvalidSignatureException();
        }

        // todo: Step 3: Return the decrypted and verified message from the server.
        return Settings.Encoding.GetString(decryptedMessage);
    }

    /// <inheritdoc />
    public override string TransformOutgoingMessage(string input) {
        byte[] data = Settings.Encoding.GetBytes(input);

        // todo: Step 1: Sign the message.
        // Use PSS padding with SHA256.
        var signature = rsaKey.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        // todo: Step 2: Put the data in an SignedMessage object and serialize to JSON.
        // Return that JSON.
        var message = new SignedMessage(data, signature);
        return JsonSerializer.Serialize(message);
    }
}