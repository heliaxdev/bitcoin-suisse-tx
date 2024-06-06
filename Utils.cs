namespace Namada {
    public sealed class Utils {
        public static string HexEncode(byte[] data) {
            return BitConverter.ToString(data).Replace("-", string.Empty);
        }
    }
}
