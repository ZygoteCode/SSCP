namespace SSCP.Utils
{
    internal class SscpGlobal
    {
        public static SscpRandom SscpRandom = new SscpRandom(2);
        public const long MAX_TIMESTAMP_DELAY = 10000;

        public const double PACKET_NUMBER_INCREMENTAL = 0.0001;
        public const double MAX_PACKET_NUMBER = 1000000000000;

        public const int PACKET_ID_SIZE = 6;
        public const int PACKET_ID_MAX_COUNT = 100;
        public const int RSA_KEY_LENGTH = 2048;
        public const int DEFAULT_PORT = 9987;

        public const string DEFAULT_SERVER_IP = "127.0.0.1";
        public const string DEFAULT_URL_SLUG = "/SSCP/";
    }
}