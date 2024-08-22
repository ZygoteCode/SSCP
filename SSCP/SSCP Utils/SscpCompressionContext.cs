using Ionic.Zlib;

namespace SSCP.Utils
{
    internal class SscpCompressionContext
    {
        private ZlibCodec _deflator, _inflator;
        private byte[] _deflateBuffer, _inflateBuffer;

        public SscpCompressionContext()
        {
            _deflator = new ZlibCodec();
            _deflator.InitializeDeflate();

            _inflator = new ZlibCodec();
            _inflator.InitializeInflate();

            _deflateBuffer = new byte[1024];
            _inflateBuffer = new byte[1024];
        }

        public byte[] Compress(byte[] uncompressedBytes)
        {
            _deflator.InputBuffer = uncompressedBytes;
            _deflator.AvailableBytesIn = uncompressedBytes.Length;

            if (_deflateBuffer.Length < uncompressedBytes.Length * 2)
            {
                _deflateBuffer = new byte[uncompressedBytes.Length * 2];
            }

            _deflator.OutputBuffer = _deflateBuffer;
            _deflator.AvailableBytesOut = _deflateBuffer.Length;
            _deflator.NextIn = 0;
            _deflator.NextOut = 0;

            _deflator.Deflate(FlushType.Sync);
            return _deflator.OutputBuffer.Take(_deflator.NextOut).ToArray();
        }

        public byte[] Decompress(byte[] compressedBytes)
        {
            _inflator.InputBuffer = compressedBytes;
            _inflator.AvailableBytesIn = compressedBytes.Length;

            if (_inflateBuffer.Length < compressedBytes.Length * 2)
            {
                _inflateBuffer = new byte[compressedBytes.Length * 2];
            }

            _inflator.OutputBuffer = _inflateBuffer;
            _inflator.AvailableBytesOut = _inflateBuffer.Length;
            _inflator.NextIn = 0;
            _inflator.NextOut = 0;

            _inflator.Inflate(FlushType.Sync);
            return _inflator.OutputBuffer.Take(_inflator.NextOut).ToArray();
        }
    }
}