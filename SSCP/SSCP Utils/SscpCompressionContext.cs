using System;
using System.Buffers;
using Ionic.Zlib;

namespace SSCP.Utils
{
    internal class SscpCompressionContext : IDisposable
    {
        private readonly ZlibCodec _deflator;
        private readonly ZlibCodec _inflator;
        private readonly byte[] _deflateBuffer;
        private readonly byte[] _inflateBuffer;

        public SscpCompressionContext()
        {
            _deflator = new ZlibCodec();
            _deflator.InitializeDeflate();

            _inflator = new ZlibCodec();
            _inflator.InitializeInflate();

            _deflateBuffer = ArrayPool<byte>.Shared.Rent(8192);
            _inflateBuffer = ArrayPool<byte>.Shared.Rent(8192);
        }

        public byte[] Compress(byte[] uncompressedBytes)
        {
            _deflator.InputBuffer = uncompressedBytes;
            _deflator.AvailableBytesIn = uncompressedBytes.Length;
            _deflator.NextIn = 0;

            _deflator.OutputBuffer = _deflateBuffer;
            _deflator.AvailableBytesOut = _deflateBuffer.Length;
            _deflator.NextOut = 0;

            _deflator.Deflate(FlushType.Sync);

            return _deflateBuffer.AsSpan(0, _deflator.NextOut).ToArray();
        }

        public byte[] Decompress(byte[] compressedBytes)
        {
            _inflator.InputBuffer = compressedBytes;
            _inflator.AvailableBytesIn = compressedBytes.Length;
            _inflator.NextIn = 0;

            _inflator.OutputBuffer = _inflateBuffer;
            _inflator.AvailableBytesOut = _inflateBuffer.Length;
            _inflator.NextOut = 0;

            _inflator.Inflate(FlushType.Sync);

            return _inflateBuffer.AsSpan(0, _inflator.NextOut).ToArray();
        }

        public void Dispose()
        {
            ArrayPool<byte>.Shared.Return(_deflateBuffer);
            ArrayPool<byte>.Shared.Return(_inflateBuffer);
            _deflator?.EndDeflate();
            _inflator?.EndInflate();
        }
    }
}
