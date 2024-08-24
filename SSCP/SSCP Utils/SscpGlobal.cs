namespace SSCP.Utils
{
    internal class SscpGlobal
    {
        public static SscpRandom SscpRandom = new SscpRandom(2);
        public const long MAX_TIMESTAMP_DELAY = 20000;

        public const double PACKET_NUMBER_INCREMENTAL = 0.0001;
        public const double MAX_PACKET_NUMBER = 1000000000000;

        public const int DOUBLE_SIZE = sizeof(double);
        public const int LONG_SIZE = sizeof(long);
        public const int INTEGER_SIZE = sizeof(int);

        public const int HTTP_400_BAD_REQUEST = 400;
        public const int HTTP_401_UNAUTHORIZED = 401;

        public const int PACKET_ID_SIZE = 6;
        public const int PACKET_ID_MAX_COUNT = 100;

        public const int HASH_SIZE = 32;
        public const int STRING_HASH_SIZE = HASH_SIZE * 2;
        public const int MID_HASH_SIZE = HASH_SIZE / 2;

        public const int DEFAULT_PORT = 9987;
        public const int DEFAULT_BUFFER_SIZE = 1024 * 4;

        public const int RSA_KEY_LENGTH = 1024 * 2;

        public const string DEFAULT_SERVER_IP = "127.0.0.1";
        public const string DEFAULT_URL_SLUG = "/SSCP/";

        public static byte[] EMPTY_IV = new byte[16];
    }
}