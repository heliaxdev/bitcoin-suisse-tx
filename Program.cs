namespace Namada
{
    class Program
    {
        private const string privateKeyBytes = "E41BE00ECD830BA85F1316D9830DB8BC8AB126E108F75D619D9B68F439070DF4";

        static void Main()
        {
            var key = Transaction.Ed25519PrivateKey.Import(Utils.HexDecode(privateKeyBytes));
            var dummyTx = Transaction.Tx.Dummy();
            var txToSign = new Transaction.Tx
            {
                Header = new Transaction.Header
                {
                    ChainId = dummyTx.Header.ChainId,
                    Timestamp = dummyTx.Header.Timestamp,
                    Batch = dummyTx.Header.Batch,
                    Atomic = dummyTx.Header.Atomic,
                    TxType = new Transaction.TxTypeWrapper
                    {
                        Fee = ((Transaction.TxTypeWrapper)dummyTx.Header.TxType).Fee,
                        GasLimit = ((Transaction.TxTypeWrapper)dummyTx.Header.TxType).GasLimit,
                        PublicKey = key.PublicKey()
                    }
                },
                Sections = dummyTx.Sections
            };

            Console.WriteLine("Dummy tx header hash: {0}", Utils.HexEncode(dummyTx.HeaderHash()));
            Console.WriteLine("Dummy tx raw header hash: {0}", Utils.HexEncode(dummyTx.RawHeaderHash()));
            Console.WriteLine("Dummy tx: {0}", Utils.EncodeWithBorshThenHex(dummyTx));

            Console.WriteLine();

            var signedTx = txToSign.Signed(key);
            Console.WriteLine("Signed dummy tx header hash: {0}", Utils.HexEncode(signedTx.HeaderHash()));
            Console.WriteLine("Signed dummy tx raw header hash: {0}", Utils.HexEncode(signedTx.RawHeaderHash()));
            Console.WriteLine("Signed dummy tx: {0}", Utils.EncodeWithBorshThenHex(signedTx));
        }
    }
}
