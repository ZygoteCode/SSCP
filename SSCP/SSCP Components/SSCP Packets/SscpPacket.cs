using System.Text;

namespace SSCP
{
    public class SscpPacket
    {
        public SscpPacketType SscpPacketType { get; set; }
        public byte[] Data { get; set; }

        public SscpPacket(SscpPacketType sscpPacketType, byte[] data)
        {
            SscpPacketType = sscpPacketType;
            Data = data;
        }

        public override string ToString()
        {
            return Encoding.UTF8.GetString(Data);
        }
    }
}