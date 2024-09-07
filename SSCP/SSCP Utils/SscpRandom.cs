using System.Security.Cryptography;

namespace SSCP.Utils
{
    internal class SscpRandom
    {
        public int Complexity { get; set; }

        public SscpRandom(int complexity = 100)
        {
            Complexity = complexity;
        }

        public byte[] GetRandomByteArray(int size)
        {
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            byte[] random = new byte[size];
            rng.GetBytes(random);
            return random;
        }

        public byte[] GetRandomBytes(int size)
        {
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            byte[] random = new byte[size];
            rng.GetBytes(random);
            return random;
        }

        public byte[] GetRandomByteArray(int min, int max)
        {
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            byte[] random = new byte[GetRandomInt32(min, max)];
            rng.GetBytes(random);
            return random;
        }

        public byte[] GetRandomBytes(int min, int max)
        {
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            byte[] random = new byte[GetRandomInt32(min, max)];
            rng.GetBytes(random);
            return random;
        }

        public int GetRandomInt32()
        {
            List<int[]> arrays = new List<int[]>();

            for (int i = 0; i < Complexity; i++)
            {
                int[] values = new int[Complexity];

                for (int j = 0; j < Complexity; j++)
                {
                    values[j] = GetBasicRandomInt32();
                }

                arrays.Add(values);
            }

            return arrays[GetBasicRandomInt32() % Complexity][GetBasicRandomInt32() % Complexity];
        }

        public int GetRandomInt32(int max)
        {
            return GetRandomInt32() % (max + 1);
        }

        public int GetRandomInt32(int min, int max)
        {
            return GetRandomInt32() % (max - min + 1) + min;
        }

        private int GetBasicRandomInt32()
        {
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            byte[] randomNumber = new byte[4];
            rng.GetBytes(randomNumber);
            int value = BitConverter.ToInt32(randomNumber, 0);

            if (value < 0)
            {
                value *= -1;
            }

            return value;
        }
    }
}