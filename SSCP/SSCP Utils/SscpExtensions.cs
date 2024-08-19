using SSCP.Utils;

public static class SscpExtensions
{
    public static bool ContainsByteArray(this List<byte[]> list, byte[] toCompare)
    {
        foreach (byte[] array in list)
        {
            if (SscpUtils.CompareByteArrays(array, toCompare))
            {
                return true;
            }
        }

        return false;
    }
}