using System;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;

public class GoogleAuthenticator
{
    const int intervalLength = 30;
    const int pinLength = 6;
    static readonly int pinModulo = (int)Math.Pow(10, pinLength);
    static readonly DateTime unixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
    const string allowedSecretKeyLetters = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz01234567";

    /// <summary>
    ///   Number of intervals that have elapsed.
    /// </summary>
    static long currentInterval
    {
        get
        {
            var elapsedSeconds = (long)Math.Floor((DateTime.UtcNow - unixEpoch).TotalSeconds);
            return elapsedSeconds/intervalLength;
        }
    }

    /// <summary>
    ///   Generates a QR code bitmap for provisioning.
    /// </summary>
    public byte[] GenerateProvisioningImage(string identifier, byte[] key, int width, int height)
    {
        var KeyString = Encoder.Base32Encode(key);
        var ProvisionUrl = Encoder.UrlEncode(string.Format("otpauth://totp/{0}?secret={1}&issuer=MyCompany", identifier, KeyString));

        var ChartUrl = string.Format("https://chart.apis.google.com/chart?cht=qr&chs={0}x{1}&chl={2}", width, height, ProvisionUrl);
        using (var Client = new WebClient())
        {
            return Client.DownloadData(ChartUrl);
        }
    }

    public string GenerateSecretKey(int countLetter = 10)
    {
        var stringBuilder = new StringBuilder();
        var random = new Random();
        for (int index = 0; index < countLetter; index++)
        {
            var randomedIndex = random.Next(0, (allowedSecretKeyLetters.Length - 1));
            var letter = allowedSecretKeyLetters.Substring(randomedIndex, 1);
            stringBuilder.Append(letter);
        }

        return stringBuilder.ToString();
    }

    public string GetEncodedSecretKey(string secretKey)
    {
        var secretKeyBytes = Encoding.UTF8.GetBytes(secretKey);
        return Encoder.Base32Encode(secretKeyBytes);
    }

    /// <summary>
    ///   Get current pin of the given key.
    /// </summary>
    public string GetCurrentPin(string secretKey)
    {
        var secretKeyBytes = Encoding.UTF8.GetBytes(secretKey);
        return GetCurrentPin(secretKeyBytes, currentInterval);
    }

    /// <summary>
    ///   Generates a pin by hashing a key and counter.
    /// </summary>
    static string GetCurrentPin(byte[] key, long counter)
    {
        const int sizeOfInt32 = 4;

        var counterBytes = BitConverter.GetBytes(counter);

        if (BitConverter.IsLittleEndian)
        {
            //spec requires bytes in big-endian order
            Array.Reverse(counterBytes);
        }

        var hash = new HMACSHA1(key).ComputeHash(counterBytes);
        var offset = hash[hash.Length - 1] & 0xF;

        var selectedBytes = new byte[sizeOfInt32];
        Buffer.BlockCopy(hash, offset, selectedBytes, 0, sizeOfInt32);

        if (BitConverter.IsLittleEndian)
        {
            //spec interprets bytes in big-endian order
            Array.Reverse(selectedBytes);
        }

        var selectedInteger = BitConverter.ToInt32(selectedBytes, 0);

        //remove the most significant bit for interoperability per spec
        var truncatedHash = selectedInteger & 0x7FFFFFFF;

        //generate number of digits for given pin length
        var pin = truncatedHash % pinModulo;

        return pin.ToString(CultureInfo.InvariantCulture).PadLeft(pinLength, '0');
    }

    #region Nested type: Encoder

    static class Encoder
    {
        const string base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        const string urlEncodeAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~";

        /// <summary>
        ///   Url Encoding (with upper-case hexadecimal per OATH specification)
        /// </summary>
        public static string UrlEncode(string value)
        {

            var builder = new StringBuilder();
            for (var i = 0; i < value.Length; i++)
            {
                var symbol = value[i];

                if (urlEncodeAlphabet.IndexOf(symbol) != -1)
                {
                    builder.Append(symbol);
                }
                else
                {
                    builder.Append('%');
                    builder.Append(((int)symbol).ToString("X2"));
                }
            }

            return builder.ToString();
        }

        /// <summary>
        ///   Base-32 Encoding
        /// </summary>
        public static string Base32Encode(byte[] data)
        {
            const int inByteSize = 8;
            const int outByteSize = 5;
            int i = 0, index = 0;
            var builder = new StringBuilder((data.Length + 7)*inByteSize/outByteSize);

            while (i < data.Length)
            {
                int currentByte = data[i];
                int digit;

                //Is the current digit going to span a byte boundary?
                if (index > (inByteSize - outByteSize))
                {
                    int nextByte;
                    if ((i + 1) < data.Length)
                    {
                        nextByte = data[i + 1];
                    }
                    else
                    {
                        nextByte = 0;
                    }

                    digit = currentByte & (0xFF >> index);
                    index = (index + outByteSize)%inByteSize;
                    digit <<= index;
                    digit |= nextByte >> (inByteSize - index);
                    i++;
                }
                else
                {
                    digit = (currentByte >> (inByteSize - (index + outByteSize))) & 0x1F;
                    index = (index + outByteSize)%inByteSize;

                    if (index == 0)
                    {
                        i++;
                    }
                }
                builder.Append(base32Alphabet[digit]);
            }
            return builder.ToString();
        }
    }
    #endregion
}