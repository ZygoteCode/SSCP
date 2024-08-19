using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Digests;

namespace SSCP.Utils
{
    internal class SscpUtils
    {
        public static byte[] Combine(params byte[][] arrays)
        {
            byte[] ret = new byte[arrays.Sum(x => x.Length)];
            int offset = 0;

            foreach (byte[] data in arrays)
            {
                Buffer.BlockCopy(data, 0, ret, offset, data.Length);
                offset += data.Length;
            }

            return ret;
        }

        public static long GetTimestamp()
        {
            return DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        }

        public static byte[] HashMD5(byte[] data)
        {
            return MD5.Create().ComputeHash(data);
        }

        public static byte[] HashKeccak256(byte[] data)
        {
            KeccakDigest digest = new KeccakDigest(256);
            digest.BlockUpdate(data, 0, data.Length);
            byte[] result = new byte[digest.GetDigestSize()];
            digest.DoFinal(result, 0);
            return result;
        }

        public static bool CompareByteArrays(byte[] first, byte[] second)
        {
            if (first.Length != second.Length)
            {
                return false;
            }

            for (int i = 0; i < first.Length; i++)
            {
                if (first[i] != second[i])
                {
                    return false;
                }
            }

            return true;
        }

        public static byte[] ProcessAES256(byte[] data, byte[] key, byte[] iv, bool isEncrypt)
        {
            IBufferedCipher cipher = CipherUtilities.GetCipher("AES/GCM/NoPadding");
            KeyParameter keyParameter = ParameterUtilities.CreateKeyParameter("AES", key);
            ParametersWithIV parameters = new ParametersWithIV(keyParameter, iv);
            cipher.Init(isEncrypt, parameters);

            byte[] processed = new byte[cipher.GetOutputSize(data.Length)];
            int len = cipher.ProcessBytes(data, 0, data.Length, processed, 0);
            cipher.DoFinal(processed, len);

            return processed;
        }

        public static byte[] GetKeyFromSecretWebSocketKey(string secretWebSocketKey)
        {
            return HashMD5(Encoding.UTF8.GetBytes(secretWebSocketKey));
        }

        public static byte[] GeneratePacketID()
        {
            return HashKeccak256(Combine(SscpGlobal.SscpRandom.GetRandomByteArray(SscpGlobal.PACKET_ID_SIZE), BitConverter.GetBytes(GetTimestamp())));
        }

        public static string GenerateUserID(string ipAddress, int port, byte[] secretWebSocketKey)
        {
            return Convert.ToHexString(HashKeccak256(Combine(Encoding.UTF8.GetBytes(ipAddress), BitConverter.GetBytes(port), secretWebSocketKey, SscpGlobal.SscpRandom.GetRandomBytes(32), BitConverter.GetBytes(GetTimestamp())))).ToLower();
        }
    }
}