public static string Encrypt(string data, string publicKey)
{
    try
    {
        byte[] publicKeyBytes = Convert.FromBase64String(publicKey);
        AsymmetricKeyParameter asymmetricKeyParameter = PublicKeyFactory.CreateKey(publicKeyBytes);
        RsaKeyParameters rsaKeyParameters = (RsaKeyParameters)asymmetricKeyParameter;

        byte[] dataToEncrypt = Encoding.UTF8.GetBytes(data);
        var rsaPub = (Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters)asymmetricKeyParameter;
        var encrypter = new OaepEncoding(new RsaEngine(), new Sha256Digest(), new Sha1Digest(), null);
        encrypter.Init(true, rsaPub);
        var cipher = encrypter.ProcessBlock(dataToEncrypt, 0, dataToEncrypt.Length);
        return Convert.ToBase64String(cipher);

    }
    catch (Exception ex)
    {
        return string.Empty;
    }
}

public static string Decrypt(string data, string privateKey)
{
    try
    {
        byte[] privateKeyBytes = Convert.FromBase64String(privateKey);
        AsymmetricKeyParameter asymmetricKeyParameter = PrivateKeyFactory.CreateKey(privateKeyBytes);

        byte[] dataToDecrypt = Convert.FromBase64String(data);
        var rsaPub = (Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters)asymmetricKeyParameter;
        var encrypter = new OaepEncoding(new RsaEngine(), new Sha256Digest(), new Sha1Digest(), null);
        encrypter.Init(false, rsaPub);
        var cipher = encrypter.ProcessBlock(dataToDecrypt, 0, dataToDecrypt.Length);
        return Encoding.UTF8.GetString(cipher);
    }
    catch (Exception ex)
    {
        return string.Empty;
    }
}
