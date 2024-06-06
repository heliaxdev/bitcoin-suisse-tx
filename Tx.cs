using Hexarc.Borsh;
using Hexarc.Borsh.Serialization;
using NSec.Cryptography;

namespace Namada.Transaction
{
    [BorshObject]
    public sealed class Tx
    {
        [BorshPropertyOrder(0)]
        public required Header Header { get; init; }

        [BorshPropertyOrder(1)]
        public required Section[] Sections { get; init; }

        public Tx Signed(PrivateKey key)
        {
            return this.SignInner(key).SignWrapper(key);
        }

        internal Tx SignSections(Signer signer, PrivateKey key, Hash[] sections)
        {
            var newSections = new Section[this.Sections.Length + 1];

            Array.Copy(this.Sections, 0, newSections, 0, this.Sections.Length);
            newSections[this.Sections.Length] = AuthorizationSection.Sign(
                signer,
                key,
                sections
            );

            return new Tx { Header = this.Header, Sections = newSections };
        }

        internal Tx SignWrapper(PrivateKey key)
        {
            return this.SignSections(new SignerPubkeys { Value = new PublicKey[] { key.PublicKey() } }, key, this.SectionHashes());
        }

        internal Tx SignInner(PrivateKey key)
        {
            //return this.SignSections(new SignerAddress { Value = key.PublicKey().DeriveImplicitAddress() }, key, new Hash[] { this.RawHeaderHash() });
            return this.SignSections(new SignerPubkeys { Value = new PublicKey[] { key.PublicKey() } }, key, new Hash[] { this.RawHeaderHash() });
        }

        public Hash[] SectionHashes()
        {
            var hashes = new List<Hash>();

            hashes.Add(this.HeaderHash());

            foreach (Section sec in this.Sections)
            {
                hashes.Add(sec.Hash());
            }

            return hashes.ToArray();
        }

        public Hash HeaderHash()
        {
            Section headerSection = new HeaderSection { Value = this.Header };
            return headerSection.Hash();
        }

        public Hash RawHeaderHash()
        {
            Section headerSection = new HeaderSection
            {
                Value = new Header
                {
                    ChainId = this.Header.ChainId,
                    Timestamp = this.Header.Timestamp,
                    Batch = this.Header.Batch,
                    Atomic = this.Header.Atomic,
                    TxType = new TxTypeRaw { },
                }
            };
            return headerSection.Hash();
        }

        public static Tx Dummy()
        {
            var commitments = new HashSet<TxCommitments>();
            commitments.Add(new TxCommitments
            {
                CodeHash = new Hash { Value = new Byte[32] },
                DataHash = new Hash { Value = new Byte[32] },
                MemoHash = new Hash { Value = new Byte[32] },
            });
            var header = new Header
            {
                ChainId = new ChainId { Value = "namada-internal.00000000000000" },
                Timestamp = new Rfc3339Time { Value = "1966-03-03T00:06:56Z" },
                Batch = commitments,
                Atomic = true,
                TxType = new TxTypeWrapper
                {
                    Fee = new Fee
                    {
                        DenominatedAmount = new DenominatedAmount
                        {
                            Amount = Amount.FromU64(100),
                            Denomination = 6,
                        },
                        Token = new EstablishedAddress { Value = new TruncatedHash { Value = new Byte[20] } }
                    },
                    PublicKey = new Ed25519PublicKey { Value = new Byte[32] },
                    GasLimit = new GasLimit { Value = 20 },
                }
            };
            var sectionData = new DataSection
            {
                Salt = new Byte[8],
                Data = new Byte[128],
            } as Section;
            var sectionCode = new CodeSection
            {
                Salt = new Byte[8],
                Code = new HashCommitment
                {
                    Value = new Hash { Value = new Byte[32] }
                },
                Tag = "tx_bond.wasm"
            } as Section;
            var sections = new Section[] { sectionData, sectionCode };
            return new Tx
            {
                Header = header,
                Sections = sections,
            };
        }
    }

    [BorshObject]
    public sealed class GasLimit
    {
        [BorshPropertyOrder(0)]
        public required UInt64 Value { get; init; }
    }

    public abstract class PrivateKey
    {
        public abstract PublicKey PublicKey();

        public abstract Signature Sign(Hash hash);
    }

    public sealed class Ed25519PrivateKey : PrivateKey
    {
        public required Key Key { get; init; }

        public byte[] Export()
        {
            return this.Key.Export(KeyBlobFormat.RawPublicKey);
        }

        public static PrivateKey Import(byte[] privateKeyData)
        {
            return new Ed25519PrivateKey
            {
                Key = Key.Import(
                SignatureAlgorithm.Ed25519,
                privateKeyData,
                KeyBlobFormat.RawPrivateKey
            )
            };
        }

        public static PrivateKey Generate()
        {
            // Define the algorithm to use for key generation
            var algorithm = SignatureAlgorithm.Ed25519;

            var creationParameters = new KeyCreationParameters
            {
                ExportPolicy = KeyExportPolicies.AllowPlaintextExport
            };

            return new Ed25519PrivateKey { Key = new Key(algorithm, creationParameters) };
        }

        public override PublicKey PublicKey()
        {
            return new Ed25519PublicKey { Value = this.Key.PublicKey.Export(KeyBlobFormat.RawPublicKey) };
        }

        public override Signature Sign(Hash hash)
        {
            return new Ed25519Signature { Value = SignatureAlgorithm.Ed25519.Sign(this.Key, hash.Value) };
        }
    }

    [BorshObject]
    [BorshUnion<Ed25519PublicKey>(0)]
    public abstract class PublicKey
    {
        public abstract byte[] GetBytes();

        public abstract bool Verify(Signature sig, Hash hash);

        public Address DeriveImplicitAddress()
        {
            var sha256 = HashAlgorithm.Sha256;
            IncrementalHash.Initialize(sha256, out var hashingState);

            // hash the borsh serialized data
            var serialized = BorshSerializer.Serialize(this);
            IncrementalHash.Update(ref hashingState, serialized);

            var fullHash = IncrementalHash.Finalize(ref hashingState);
            var truncatedHash = new byte[20];
            Buffer.BlockCopy(fullHash, 0, truncatedHash, 0, 20);

            return new ImplicitAddress { Value = new TruncatedHash { Value = truncatedHash } };
        }
    }

    [BorshObject]
    public sealed class Ed25519PublicKey : PublicKey
    {
        [BorshPropertyOrder(0)]
        [BorshFixedArray(32)]
        public required Byte[] Value { get; init; }

        public override byte[] GetBytes()
        {
            return this.Value;
        }

        public override bool Verify(Signature signature, Hash hash)
        {
            var publicKey = NSec.Cryptography.PublicKey.Import(
                SignatureAlgorithm.Ed25519,
                this.Value,
                KeyBlobFormat.RawPublicKey
            );
            if (signature is not Ed25519Signature)
            {
                return false;
            }
            var castedSignature = (Ed25519Signature)signature;
            return SignatureAlgorithm.Ed25519.Verify(
                publicKey,
                hash.Value,
                castedSignature.Value
            );
        }
    }

    [BorshObject]
    [BorshUnion<Ed25519Signature>(0)]
    public abstract class Signature { }

    [BorshObject]
    public sealed class Ed25519Signature : Signature
    {
        [BorshPropertyOrder(0)]
        [BorshFixedArray(64)]
        public required Byte[] Value { get; init; }
    }

    [BorshObject]
    [BorshUnion<EstablishedAddress>(0)]
    [BorshUnion<ImplicitAddress>(1)]
    [BorshUnion<InternalAddress>(2)]
    public abstract class Address { }

    [BorshObject]
    public sealed class EstablishedAddress : Address
    {
        [BorshPropertyOrder(0)]
        public required TruncatedHash Value { get; init; }
    }

    [BorshObject]
    public sealed class ImplicitAddress : Address
    {
        [BorshPropertyOrder(0)]
        public required TruncatedHash Value { get; init; }
    }

    [BorshObject]
    public sealed class InternalAddress : Address
    {
        [BorshPropertyOrder(0)]
        public required InternalAddressKind Kind { get; init; }
    }

    public enum InternalAddressKind
    {
        ProofOfStake,
        __Unused01,
        __Unused02,
        __Unused03,
        __Unused04,
        Governance,
    }

    [BorshObject]
    [BorshUnion<TxTypeRaw>(0)]
    [BorshUnion<TxTypeWrapper>(1)]
    [BorshUnion<TxTypeProtocol>(2)]
    public abstract class TxType { }

    [BorshObject]
    public sealed class TxTypeRaw : TxType { }

    [BorshObject]
    public sealed class TxTypeWrapper : TxType
    {
        [BorshPropertyOrder(0)]
        public required Fee Fee { get; init; }

        [BorshPropertyOrder(1)]
        public required PublicKey PublicKey { get; init; }

        [BorshPropertyOrder(2)]
        public required GasLimit GasLimit { get; init; }
    }

    // NB: unspecified, since we do not make use of
    // protocol txs
    [BorshObject]
    public sealed class TxTypeProtocol : TxType { }

    [BorshObject]
    public sealed class Fee
    {
        [BorshPropertyOrder(0)]
        public required DenominatedAmount DenominatedAmount { get; init; }

        [BorshPropertyOrder(1)]
        public required Address Token { get; init; }
    }

    // NB: little endian 256 bit integer
    [BorshObject]
    public sealed class Amount
    {
        [BorshPropertyOrder(0)]
        [BorshFixedArray(32)]
        public required Byte[] Value { get; init; }

        public static Amount FromU64(UInt64 amount)
        {
            Byte[] inner = new Byte[32];
            Buffer.BlockCopy(BitConverter.GetBytes(amount), 0, inner, 0, 8);
            return new Amount { Value = inner };
        }
    }

    [BorshObject]
    public sealed class DenominatedAmount
    {
        [BorshPropertyOrder(0)]
        public required Amount Amount { get; init; }

        [BorshPropertyOrder(1)]
        public required Byte Denomination { get; init; }
    }

    [BorshObject]
    public sealed class Rfc3339Time
    {
        [BorshPropertyOrder(0)]
        public required string Value { get; init; }
    }

    [BorshObject]
    public sealed class ChainId
    {
        [BorshPropertyOrder(0)]
        public required string Value { get; init; }
    }

    [BorshObject]
    public sealed class Hash
    {
        [BorshPropertyOrder(0)]
        [BorshFixedArray(32)]
        public required Byte[] Value { get; init; }
    }

    [BorshObject]
    public sealed class TruncatedHash
    {
        [BorshPropertyOrder(0)]
        [BorshFixedArray(20)]
        public required Byte[] Value { get; init; }
    }

    [BorshObject]
    public sealed class TxCommitments
    {
        [BorshPropertyOrder(0)]
        public required Hash CodeHash { get; init; }

        [BorshPropertyOrder(1)]
        public required Hash DataHash { get; init; }

        [BorshPropertyOrder(2)]
        public required Hash MemoHash { get; init; }
    }

    [BorshObject]
    public sealed class Header
    {
        [BorshPropertyOrder(0)]
        public required ChainId ChainId { get; init; }

        [BorshPropertyOrder(1)]
        [BorshOptional]
        public Rfc3339Time? Expiration { get; init; }
        //public required Rfc3339Time? Expiration { get; init; }

        [BorshPropertyOrder(2)]
        public required Rfc3339Time Timestamp { get; init; }

        [BorshPropertyOrder(3)]
        public required HashSet<TxCommitments> Batch { get; init; }

        [BorshPropertyOrder(4)]
        public required Boolean Atomic { get; init; }

        [BorshPropertyOrder(5)]
        public required TxType TxType { get; init; }
    }

    public sealed class SectionDiscriminant
    {
        public const byte DataSection = 0;
        public const byte ExtraDataSection = 1;
        public const byte CodeSection = 2;
        public const byte AuthorizationSection = 3;
        public const byte HeaderSection = 6;
    }

    [BorshObject]
    [BorshUnion<DataSection>(SectionDiscriminant.DataSection)]
    [BorshUnion<ExtraDataSection>(SectionDiscriminant.ExtraDataSection)]
    [BorshUnion<CodeSection>(SectionDiscriminant.CodeSection)]
    [BorshUnion<AuthorizationSection>(SectionDiscriminant.AuthorizationSection)]
    [BorshUnion<HeaderSection>(SectionDiscriminant.HeaderSection)]
    // NB: other variants not required
    public abstract class Section
    {
        internal abstract byte Discriminant { get; }

        virtual public Hash Hash()
        {
            var sha256 = HashAlgorithm.Sha256;
            IncrementalHash.Initialize(sha256, out var hashingState);

            // hash the borsh serialized data
            var serialized = BorshSerializer.Serialize(this);
            IncrementalHash.Update(ref hashingState, serialized);

            return new Hash { Value = IncrementalHash.Finalize(ref hashingState) };
        }

        public static Section DummyHeader()
        {
            return new HeaderSection
            {
                Value = Tx.Dummy().Header
            };
        }
    }

    [BorshObject]
    public sealed class DataSection : Section
    {
        internal override byte Discriminant { get { return SectionDiscriminant.DataSection; } }

        [BorshPropertyOrder(0)]
        [BorshFixedArray(8)]
        public required Byte[] Salt { get; init; }

        [BorshPropertyOrder(1)]
        public required Byte[] Data { get; init; }

        public static Section Dummy()
        {
            return new DataSection
            {
                Salt = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 },
                Data = System.Text.Encoding.UTF8.GetBytes("bing bongus"),
            };
        }
    }

    [BorshObject]
    public sealed class ExtraDataSection : Section
    {
        internal override byte Discriminant { get { return SectionDiscriminant.ExtraDataSection; } }

        [BorshPropertyOrder(0)]
        [BorshFixedArray(8)]
        public required Byte[] Salt { get; init; }

        [BorshPropertyOrder(1)]
        public required Commitment Code { get; init; }

        [BorshPropertyOrder(2)]
        [BorshOptional]
        public string? Tag { get; init; }
    }

    [BorshObject]
    public sealed class CodeSection : Section
    {
        internal override byte Discriminant { get { return SectionDiscriminant.CodeSection; } }

        [BorshPropertyOrder(0)]
        [BorshFixedArray(8)]
        public required Byte[] Salt { get; init; }

        [BorshPropertyOrder(1)]
        public required Commitment Code { get; init; }

        [BorshPropertyOrder(2)]
        [BorshOptional]
        public string? Tag { get; init; }

        public static Section Dummy()
        {
            return new CodeSection
            {
                Salt = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 },
                Code = new HashCommitment { Value = new Hash { Value = new byte[] { 40, 134, 125, 152, 174, 143, 209, 43, 225, 159, 197, 186, 19, 84, 60, 98, 220, 26, 56, 202, 51, 75, 102, 195, 221, 222, 172, 249, 34, 115, 217, 40 } } },
                Tag = "tx_bond.wasm"
            };
        }

        override public Hash Hash()
        {
            var sha256 = HashAlgorithm.Sha256;
            IncrementalHash.Initialize(sha256, out var hashingState);

            // hash the discriminant
            var discriminant = this.Discriminant;
            IncrementalHash.Update(ref hashingState, new ReadOnlySpan<byte>(ref discriminant));

            // hash salt
            IncrementalHash.Update(ref hashingState, this.Salt);
            // hash code
            if (this.Code is HashCommitment)
            {
                var code = (HashCommitment)this.Code;
                IncrementalHash.Update(ref hashingState, code.Value.Value);
            }
            else if (this.Code is IdCommitment)
            {
                var code = (IdCommitment)this.Code;
                IncrementalHash.Update(ref hashingState, sha256.Hash(code.Value));
            }
            // hash tag
            IncrementalHash.Update(ref hashingState, BorshSerializer.Serialize(Option<String>.Create(this.Tag)));

            return new Hash { Value = IncrementalHash.Finalize(ref hashingState) };
        }
    }

    [BorshObject]
    [BorshUnion<HashCommitment>(0)]
    [BorshUnion<IdCommitment>(1)]
    public abstract class Commitment { }

    [BorshObject]
    public sealed class HashCommitment : Commitment
    {
        [BorshPropertyOrder(0)]
        public required Hash Value { get; init; }
    }

    [BorshObject]
    public sealed class IdCommitment : Commitment
    {
        [BorshPropertyOrder(0)]
        public required Byte[] Value { get; init; }
    }

    [BorshObject]
    public sealed class AuthorizationSection : Section
    {
        internal override byte Discriminant { get { return SectionDiscriminant.AuthorizationSection; } }

        [BorshPropertyOrder(0)]
        public required Hash[] Targets { get; init; }

        [BorshPropertyOrder(1)]
        public required Signer Signer { get; init; }

        [BorshPropertyOrder(2)]
        public required Dictionary<Byte, Signature> Signatures { get; init; }

        // NB: hashes this as a non section wrapped obj
        internal Hash HashInner()
        {
            var sha256 = HashAlgorithm.Sha256;
            IncrementalHash.Initialize(sha256, out var hashingState);

            // hash the borsh serialized data
            var serialized = BorshSerializer.Serialize(this);
            IncrementalHash.Update(ref hashingState, serialized);

            return new Hash { Value = IncrementalHash.Finalize(ref hashingState) };
        }

        internal static Section Sign(Signer signer, PrivateKey key, Hash[] sectionsToSign)
        {
            AuthorizationSection targetToSign = new AuthorizationSection
            {
                Targets = sectionsToSign,
                Signer = new SignerPubkeys { Value = new PublicKey[0] },
                Signatures = new Dictionary<Byte, Signature>(),
            };

            var signature = key.Sign(targetToSign.HashInner());
            targetToSign.Signatures.Add(0, signature);

            return new AuthorizationSection
            {
                Targets = sectionsToSign,
                Signer = signer,
                Signatures = targetToSign.Signatures,
            };
        }
    }

    [BorshObject]
    public sealed class HeaderSection : Section
    {
        internal override byte Discriminant { get { return SectionDiscriminant.HeaderSection; } }

        [BorshPropertyOrder(0)]
        public required Header Value { get; init; }
    }

    [BorshObject]
    [BorshUnion<SignerAddress>(0)]
    [BorshUnion<SignerPubkeys>(1)]
    public abstract class Signer { }

    [BorshObject]
    public sealed class SignerAddress : Signer
    {
        [BorshPropertyOrder(0)]
        public required Address Value { get; init; }
    }

    [BorshObject]
    public sealed class SignerPubkeys : Signer
    {
        [BorshPropertyOrder(0)]
        public required PublicKey[] Value { get; init; }
    }
}
