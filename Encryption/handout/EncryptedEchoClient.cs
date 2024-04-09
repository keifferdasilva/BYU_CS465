using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Logging;

/// <summary>
/// Provides a base class for implementing an Echo client.
/// </summary>
internal sealed class EncryptedEchoClient : EchoClientBase {

    /// <summary>
    /// Logger to use in this class.
    /// </summary>
    private ILogger<EncryptedEchoClient> Logger { get; init; } =
        Settings.LoggerFactory.CreateLogger<EncryptedEchoClient>()!;

    private System.Security.Cryptography.RSA keyHolder;

    /// <inheritdoc />
    public EncryptedEchoClient(ushort port, string address) : base(port, address) {keyHolder = System.Security.Cryptography.RSA.Create(); }

    /// <inheritdoc />
    public override void ProcessServerHello(string message) {
        
        Byte[] array = System.Convert.FromBase64String(message);
        int bytesRead;
        keyHolder.ImportRSAPublicKey(array, out bytesRead);
        
        // Step 1: Get the server's public key. Decode using Base64.
        // Throw a CryptographicException if the received key is invalid.
    }

    /// <inheritdoc />
    public override string TransformOutgoingMessage(string input) {

        // todo: Step 1: Encrypt the input using hybrid encryption.
        // Encrypt using AES with CBC mode and PKCS7 padding.
        // Use a different key each time.
        byte[] data = Settings.Encoding.GetBytes(input);
        Aes aesKey = Aes.Create();
        byte[] encryptedData = aesKey.EncryptCbc(data, aesKey.IV, PaddingMode.PKCS7);
        

        // todo: Step 2: Generate an HMAC of the message.
        // Use the SHA256 variant of HMAC.
        // Use a different key each time.
        HMACSHA256 hmac = new();
        byte[] hash = hmac.ComputeHash(data);

        // todo: Step 3: Encrypt the message encryption and HMAC keys using RSA.
        // Encrypt using the OAEP padding scheme with SHA256.
        byte[] encryptedPrivateKey = keyHolder.Encrypt(aesKey.Key, RSAEncryptionPadding.OaepSHA256);
        byte[] encryptedHMACKey = keyHolder.Encrypt(hmac.Key, RSAEncryptionPadding.OaepSHA256);

        // todo: Step 4: Put the data in an EncryptedMessage object and serialize to JSON.
        // Return that JSON.
        // var message = new EncryptedMessage(...);
        // return JsonSerializer.Serialize(message);
        var message = new EncryptedMessage(encryptedPrivateKey, aesKey.IV, encryptedData, encryptedHMACKey, hash);

        return JsonSerializer.Serialize(message);
    }

    /// <inheritdoc />
    public override string TransformIncomingMessage(string input) {
        // todo: Step 1: Deserialize the message.
        var signedMessage = JsonSerializer.Deserialize<SignedMessage>(input);

        // todo: Step 2: Check the messages signature.
        // Use PSS padding with SHA256.
        // Throw an InvalidSignatureException if the signature is bad.
        if(!keyHolder.VerifyData(signedMessage.Message, signedMessage.Signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss)){
            throw new InvalidSignatureException();
        }

        // todo: Step 3: Return the message from the server.
        return Settings.Encoding.GetString(signedMessage.Message);
    }
}