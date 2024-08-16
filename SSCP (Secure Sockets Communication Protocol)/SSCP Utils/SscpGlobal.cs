namespace SSCP.Utils
{
    internal class SscpGlobal
    {
        public static SscpRandom SscpRandom = new SscpRandom(2);
        public const double PacketNumberIncremental = 0.0001;
        public const double MaxPacketNumber = 1000000000000;
        public const int PacketIdSize = 6;
        public const int PacketIdsMaxCount = 100;
        public const long MaxTimestampDelay = 10000;
        public const int RsaKeyLength = 2048;
    }
}