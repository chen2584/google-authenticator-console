using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace GoogleAuthenticatorConsole
{
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
        static long GetInterval(DateTime utcDate)
        {
            var elapsedSeconds = (long)Math.Floor((utcDate - unixEpoch).TotalSeconds);
            return elapsedSeconds / intervalLength;
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
            return Base32.Encode(secretKeyBytes);
        }

        public string GetDecodedSecretKey(string encodedSecretKey)
        {
            var secretKeyBytes = Encoding.UTF8.GetBytes(encodedSecretKey);
            var decodedSecretKeyBytes = Base32.Decode(encodedSecretKey);
            return Encoding.UTF8.GetString(decodedSecretKeyBytes);
        }

        /// <summary>
        ///   Get current pin of the given key.
        /// </summary>
        public string GetPin(string secretKey, DateTime utcDate)
        {
            var secretKeyBytes = Encoding.UTF8.GetBytes(secretKey);
            var interval = GetInterval(utcDate);
            return GetPin(secretKeyBytes, interval);
        }

        /// <summary>
        ///   Generates a pin by hashing a key and counter.
        /// </summary>
        private string GetPin(byte[] key, long counter)
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

        public static class Base32
        {

            private static readonly char[] DIGITS;
            private static readonly int MASK;
            private static readonly int SHIFT;
            private static Dictionary<char, int> CHAR_MAP = new Dictionary<char, int>();
            private const string SEPARATOR = "-";

            static Base32() {
                DIGITS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".ToCharArray();
                MASK = DIGITS.Length - 1;
                SHIFT = numberOfTrailingZeros(DIGITS.Length);
                for (int i = 0; i < DIGITS.Length; i++) CHAR_MAP[DIGITS[i]] = i;
            }

            private static int numberOfTrailingZeros(int i) {
                // HD, Figure 5-14
                int y;
                if (i == 0) return 32;
                int n = 31;
                y = i << 16; if (y != 0) { n = n - 16; i = y; }
                y = i << 8; if (y != 0) { n = n - 8; i = y; }
                y = i << 4; if (y != 0) { n = n - 4; i = y; }
                y = i << 2; if (y != 0) { n = n - 2; i = y; }
                return n - (int)((uint)(i << 1) >> 31);
            }

            public static byte[] Decode(string encoded) {
                // Remove whitespace and separators
                encoded = encoded.Trim().Replace(SEPARATOR, "");

                // Remove padding. Note: the padding is used as hint to determine how many
                // bits to decode from the last incomplete chunk (which is commented out
                // below, so this may have been wrong to start with).
                encoded = Regex.Replace(encoded, "[=]*$", "");

                // Canonicalize to all upper case
                encoded = encoded.ToUpper();
                if (encoded.Length == 0) {
                    return new byte[0];
                }
                int encodedLength = encoded.Length;
                int outLength = encodedLength * SHIFT / 8;
                byte[] result = new byte[outLength];
                int buffer = 0;
                int next = 0;
                int bitsLeft = 0;
                foreach (char c in encoded.ToCharArray()) {
                    if (!CHAR_MAP.ContainsKey(c)) {
                        throw new DecodingException("Illegal character: " + c);
                    }
                    buffer <<= SHIFT;
                    buffer |= CHAR_MAP[c] & MASK;
                    bitsLeft += SHIFT;
                    if (bitsLeft >= 8) {
                        result[next++] = (byte)(buffer >> (bitsLeft - 8));
                        bitsLeft -= 8;
                    }
                }
                // We'll ignore leftover bits for now.
                //
                // if (next != outLength || bitsLeft >= SHIFT) {
                //  throw new DecodingException("Bits left: " + bitsLeft);
                // }
                return result;
            }


            public static string Encode(byte[] data, bool padOutput = false) {
                if (data.Length == 0) {
                    return string.Empty;
                }

                // SHIFT is the number of bits per output character, so the length of the
                // output is the length of the input multiplied by 8/SHIFT, rounded up.
                if (data.Length >= (1 << 28)) {
                    // The computation below will fail, so don't do it.
                    throw new ArgumentOutOfRangeException("data");
                }

                int outputLength = (data.Length * 8 + SHIFT - 1) / SHIFT;
                StringBuilder result = new StringBuilder(outputLength);

                int buffer = data[0];
                int next = 1;
                int bitsLeft = 8;
                while (bitsLeft > 0 || next < data.Length) {
                    if (bitsLeft < SHIFT) {
                        if (next < data.Length) {
                            buffer <<= 8;
                            buffer |= (data[next++] & 0xff);
                            bitsLeft += 8;
                        } else {
                            int pad = SHIFT - bitsLeft;
                            buffer <<= pad;
                            bitsLeft += pad;
                        }
                    }
                    int index = MASK & (buffer >> (bitsLeft - SHIFT));
                    bitsLeft -= SHIFT;
                    result.Append(DIGITS[index]);
                }
                if (padOutput) {
                    int padding = 8 - (result.Length % 8);
                    if (padding > 0) result.Append(new string('=', padding == 8 ? 0 : padding));
                }
                return result.ToString();
            }

            private class DecodingException : Exception {
                public DecodingException(string message) : base(message) {
                }
            }
        }
        #endregion
    }
}