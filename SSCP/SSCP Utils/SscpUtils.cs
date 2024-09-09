using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System.Text;

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

        private static byte[] HashWithKeccak(byte[] data, int digestSize)
        {
            KeccakDigest digest = new KeccakDigest(digestSize);
            digest.BlockUpdate(data, 0, data.Length);
            byte[] result = new byte[digest.GetDigestSize()];
            digest.DoFinal(result, 0);
            return result;
        }

        private static byte[] HashWithKeccak128(byte[] data)
        {
            return HashWithKeccak(data, 128);
        }

        public static byte[] HashWithKeccak256(byte[] data)
        {
            return HashWithKeccak(data, 256);
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
            return HashWithKeccak128(Encoding.UTF8.GetBytes(secretWebSocketKey));
        }

        public static byte[] GeneratePacketID()
        {
            return HashWithKeccak256(Combine(SscpGlobal.SscpRandom.GetRandomByteArray(SscpGlobal.PACKET_ID_SIZE), BitConverter.GetBytes(GetTimestamp())));
        }

        public static string GenerateUserID(string ipAddress, int port, byte[] secretWebSocketKey)
        {
            return Convert.ToHexString(HashWithKeccak256(Combine(Encoding.UTF8.GetBytes(ipAddress), BitConverter.GetBytes(port), secretWebSocketKey, SscpGlobal.SscpRandom.GetRandomBytes(32), BitConverter.GetBytes(GetTimestamp())))).ToLower();
        }
    }
}