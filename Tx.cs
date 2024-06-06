using Hexarc.Borsh;
using Hexarc.Borsh.Serialization;

namespace Namada {
    namespace Transaction {
        [BorshObject]
        public sealed class Tx {
            [BorshPropertyOrder(0)]
            public required Header Header { get; init; }
            
            [BorshPropertyOrder(1)]
            public required Section[] Sections { get; init; }

            public static string Example() {
                var rawData = BorshSerializer.Serialize(1234);
                return Utils.HexEncode(rawData);
            }
        }

        [BorshObject]
        public sealed class Header {
            [BorshPropertyOrder(0)]
            public required Byte Dummy { get; init; }
        }

        [BorshObject]
        public sealed class Section {
            [BorshPropertyOrder(0)]
            public required Byte Dummy { get; init; }
        }
    }
}
