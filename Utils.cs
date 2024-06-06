using Hexarc.Borsh;

namespace Namada
{
    public sealed class Utils
    {
        public static string HexEncode(byte[] data)
        {
            return Convert.ToHexString(data);
        }

        public static byte[] HexDecode(string data)
        {
            return Convert.FromHexString(data);
        }

        public static string HexEncode(Namada.Transaction.Hash data)
        {
            return HexEncode(data.Value);
        }

        public static TValue DecodeFromBorsh<TValue>(byte[] data)
        {
            return BorshSerializer.Deserialize<TValue>(data);
        }

        public static TValue DecodeFromBorshHexStr<TValue>(string data)
        {
            return DecodeFromBorsh<TValue>(HexDecode(data));
        }

        public static byte[] EncodeWithBorsh<TValue>(TValue data)
        {
            return BorshSerializer.Serialize(data);
        }

        public static string EncodeWithBorshThenHex<TValue>(TValue data)
        {
            return HexEncode(EncodeWithBorsh(data));
        }
    }
}
