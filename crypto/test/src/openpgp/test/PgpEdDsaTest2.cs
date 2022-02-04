using System;
using System.Collections;
using System.IO;
using System.Text;

using NUnit.Framework;
using Org.BouncyCastle.Asn1.Gnu;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    [TestFixture]
    public class PgpEdDsaTest2
        : SimpleTest
    {
        private static readonly string edDSASampleKey =
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "Comment: Alice's OpenPGP certificate\n" +
            "Comment: https://www.ietf.org/id/draft-bre-openpgp-samples-01.html\n" +
            "\n" +
            "mDMEXEcE6RYJKwYBBAHaRw8BAQdArjWwk3FAqyiFbFBKT4TzXcVBqPTB3gmzlC/U\n" +
            "b7O1u120JkFsaWNlIExvdmVsYWNlIDxhbGljZUBvcGVucGdwLmV4YW1wbGU+iJAE\n" +
            "ExYIADgCGwMFCwkIBwIGFQoJCAsCBBYCAwECHgECF4AWIQTrhbtfozp14V6UTmPy\n" +
            "MVUMT0fjjgUCXaWfOgAKCRDyMVUMT0fjjukrAPoDnHBSogOmsHOsd9qGsiZpgRnO\n" +
            "dypvbm+QtXZqth9rvwD9HcDC0tC+PHAsO7OTh1S1TC9RiJsvawAfCPaQZoed8gK4\n" +
            "OARcRwTpEgorBgEEAZdVAQUBAQdAQv8GIa2rSTzgqbXCpDDYMiKRVitCsy203x3s\n" +
            "E9+eviIDAQgHiHgEGBYIACAWIQTrhbtfozp14V6UTmPyMVUMT0fjjgUCXEcE6QIb\n" +
            "DAAKCRDyMVUMT0fjjlnQAQDFHUs6TIcxrNTtEZFjUFm1M0PJ1Dng/cDW4xN80fsn\n" +
            "0QEA22Kr7VkCjeAEC08VSTeV+QFsmz55/lntWkwYWhmvOgE=\n" +
            "=iIGO\n" +
            "-----END PGP PUBLIC KEY BLOCK-----\n";

        private static readonly string edDSASecretKey =
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
                "Comment: Alice's OpenPGP Transferable Secret Key\n" +
                "Comment: https://www.ietf.org/id/draft-bre-openpgp-samples-01.html\n" +
                "\n" +
                "lFgEXEcE6RYJKwYBBAHaRw8BAQdArjWwk3FAqyiFbFBKT4TzXcVBqPTB3gmzlC/U\n" +
                "b7O1u10AAP9XBeW6lzGOLx7zHH9AsUDUTb2pggYGMzd0P3ulJ2AfvQ4RtCZBbGlj\n" +
                "ZSBMb3ZlbGFjZSA8YWxpY2VAb3BlbnBncC5leGFtcGxlPoiQBBMWCAA4AhsDBQsJ\n" +
                "CAcCBhUKCQgLAgQWAgMBAh4BAheAFiEE64W7X6M6deFelE5j8jFVDE9H444FAl2l\n" +
                "nzoACgkQ8jFVDE9H447pKwD6A5xwUqIDprBzrHfahrImaYEZzncqb25vkLV2arYf\n" +
                "a78A/R3AwtLQvjxwLDuzk4dUtUwvUYibL2sAHwj2kGaHnfICnF0EXEcE6RIKKwYB\n" +
                "BAGXVQEFAQEHQEL/BiGtq0k84Km1wqQw2DIikVYrQrMttN8d7BPfnr4iAwEIBwAA\n" +
                "/3/xFPG6U17rhTuq+07gmEvaFYKfxRB6sgAYiW6TMTpQEK6IeAQYFggAIBYhBOuF\n" +
                "u1+jOnXhXpROY/IxVQxPR+OOBQJcRwTpAhsMAAoJEPIxVQxPR+OOWdABAMUdSzpM\n" +
                "hzGs1O0RkWNQWbUzQ8nUOeD9wNbjE3zR+yfRAQDbYqvtWQKN4AQLTxVJN5X5AWyb\n" +
                "Pnn+We1aTBhaGa86AQ==\n" +
                "=n8OM\n" +
                "-----END PGP PRIVATE KEY BLOCK-----\n";

        private static readonly string revBlock =
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
                "Comment: Alice's revocation certificate\n" +
                "Comment: https://www.ietf.org/id/draft-bre-openpgp-samples-01.html\n" +
                "\n" +
                "iHgEIBYIACAWIQTrhbtfozp14V6UTmPyMVUMT0fjjgUCXaWkOwIdAAAKCRDyMVUM\n" +
                "T0fjjoBlAQDA9ukZFKRFGCooVcVoDVmxTaHLUXlIg9TPh2f7zzI9KgD/SLNXUOaH\n" +
                "O6TozOS7C9lwIHwwdHdAxgf5BzuhLT9iuAM=\n" +
                "=Tm8h\n" +
                "-----END PGP PUBLIC KEY BLOCK-----\n";

        
        private void EncryptDecryptBcTest(PgpPublicKey pubKey, PgpPrivateKey secKey)
        {
            byte[] text = { (byte)'h', (byte)'e', (byte)'l', (byte)'l', (byte)'o', (byte)' ', (byte)'w', (byte)'o', (byte)'r', (byte)'l', (byte)'d', (byte)'!', (byte)'\n' };

            PgpLiteralDataGenerator lData = new PgpLiteralDataGenerator();
            MemoryStream ldOut = new MemoryStream();
            Stream pOut = lData.Open(ldOut, PgpLiteralDataGenerator.Utf8, PgpLiteralData.Console, text.Length, DateTime.Now);

            pOut.Write(text, 0, text.Length);

            pOut.Close();

            byte[] data = ldOut.ToArray();

            MemoryStream cbOut = new MemoryStream();

            PgpEncryptedDataGenerator cPk = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Cast5);

            cPk.AddMethod(pubKey);

            Stream cOut = cPk.Open(/* new UncloseableOutputStream(*/ cbOut /* ) */, data.Length);

            cOut.Write(data, 0, data.Length);

            cOut.Close();

            PgpObjectFactory pgpF = new PgpObjectFactory(cbOut.ToArray());

            PgpEncryptedDataList encList = (PgpEncryptedDataList)pgpF.NextObject();

            PgpPublicKeyEncryptedData encP = (PgpPublicKeyEncryptedData)encList.Get(0);

            Stream clear = encP.GetDataStream(secKey);

            pgpF = new PgpObjectFactory(clear);

            PgpLiteralData ld = (PgpLiteralData)pgpF.NextObject();

            clear = ld.GetInputStream();
            MemoryStream bOut = new MemoryStream();

            int ch;
            while ((ch = clear.ReadByte()) >= 0)
            {
                bOut.WriteByte((byte)ch);
            }

            byte[] tout = bOut.ToArray();

            if (!AreEqual(tout, text))
            {
                Fail("wrong plain text in generated packet");
            }
        }

        private void KeyringBcTest()
        {
            String identity = "eric@bouncycastle.org";
            char[] passPhrase = "Hello, world!".ToCharArray();

            
            Ed25519KeyPairGenerator edKp = new Ed25519KeyPairGenerator();
            edKp.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));


            PgpKeyPair dsaKeyPair = new PgpKeyPair(PublicKeyAlgorithmTag.EdDsa, edKp.GenerateKeyPair(), DateTime.Now);

            X25519KeyPairGenerator dhKp = new X25519KeyPairGenerator();
            dhKp.Init(new X25519KeyGenerationParameters(new SecureRandom()));

            PgpKeyPair dhKeyPair = new PgpKeyPair(PublicKeyAlgorithmTag.ECDH, dhKp.GenerateKeyPair(), DateTime.Now);

            EncryptDecryptBcTest(dhKeyPair.PublicKey, dhKeyPair.PrivateKey);

            PgpKeyRingGenerator keyRingGen = new PgpKeyRingGenerator(
                PgpSignature.PositiveCertification, dsaKeyPair,
                identity, SymmetricKeyAlgorithmTag.Aes256, HashAlgorithmTag.Sha1, true, passPhrase, true, null, null, new SecureRandom()
              );

            keyRingGen.AddSubKey(dhKeyPair);

            MemoryStream secretOut = new MemoryStream();

            PgpSecretKeyRing secRing = keyRingGen.GenerateSecretKeyRing();

            PgpPublicKeyRing pubRing = keyRingGen.GeneratePublicKeyRing();

            secRing.Encode(secretOut);

            secretOut.Close();
            secRing = new PgpSecretKeyRing(secretOut.ToArray());

            var pit = secRing.GetSecretKeys().GetEnumerator();
            pit.MoveNext();
            pit.MoveNext();
            PgpPublicKey sKey = ((PgpSecretKey)pit.Current).PublicKey;

            PgpPublicKey vKey = secRing.GetPublicKey();
             
            int count = 0;
            foreach (PgpSignature sig in sKey.GetSignatures())
            {
                if (sig.KeyId == vKey.KeyId && sig.SignatureType == PgpSignature.SubkeyBinding)
                {
                    count++;
                    sig.InitVerify(vKey);
                    if (!sig.VerifyCertification(vKey, sKey))
                    {
                        Fail("failed to verify sub-key signature.");
                    }
                }
            }
            IsTrue(count == 1);
            
            secRing = new PgpSecretKeyRing(secretOut.ToArray());

            PgpPublicKey pubKey = sKey;
            PgpPrivateKey privKey = secRing.GetSecretKey(pubKey.KeyId).ExtractPrivateKey(passPhrase);

            if (privKey == null)
            {
                Fail("Could not find private key");
            }
           
            EncryptDecryptBcTest(pubKey, privKey);
        }
         
        public override void PerformTest()
        {
            ArmoredInputStream aIn = new ArmoredInputStream(new MemoryStream(Encoding.ASCII.GetBytes(edDSASampleKey)));

            PgpPublicKeyRing pubKeyRing = new PgpPublicKeyRing(aIn);

            IsTrue(AreEqual(Hex.Decode("EB85 BB5F A33A 75E1 5E94 4E63 F231 550C 4F47 E38E"), pubKeyRing.GetPublicKey().GetFingerprint()));

            aIn = new ArmoredInputStream(new MemoryStream(Encoding.ASCII.GetBytes(edDSASecretKey)));

            PgpSecretKeyRing secRing = new PgpSecretKeyRing(aIn);

            IsTrue(secRing.GetSecretKey().IsSigningKey);

            PgpSignatureGenerator pgpGen = new PgpSignatureGenerator(PublicKeyAlgorithmTag.EdDsa, HashAlgorithmTag.Sha256);

            pgpGen.InitSign(PgpSignature.SubkeyBinding, secRing.GetSecretKey().ExtractPrivateKey(null));

            PgpSignature sig = pgpGen.GenerateCertification(pubKeyRing.GetPublicKey(), pubKeyRing.GetPublicKey(5145070902336167606L));

            sig.InitVerify(pubKeyRing.GetPublicKey());

            IsTrue(sig.VerifyCertification(pubKeyRing.GetPublicKey(), pubKeyRing.GetPublicKey(5145070902336167606L)));

            EncryptDecryptBcTest(pubKeyRing.GetPublicKey(5145070902336167606L),
                secRing.GetSecretKey(5145070902336167606L).ExtractPrivateKey(null));

            aIn = new ArmoredInputStream(new MemoryStream(Encoding.ASCII.GetBytes(revBlock)));

            PgpSignatureList sigs = (PgpSignatureList)new PgpObjectFactory(aIn).NextObject();

            sig = sigs.Get(0);

            sig.InitVerify(pubKeyRing.GetPublicKey());

            IsTrue(sig.VerifyCertification(pubKeyRing.GetPublicKey()));

            KeyringBcTest();
            SksKeyTest();
            AliceBcKeyTest();
        }

        private void AliceBcKeyTest()
        {
            byte[] text = { (byte)'h', (byte)'e', (byte)'l', (byte)'l', (byte)'o', (byte)' ', (byte)'w', (byte)'o', (byte)'r', (byte)'l', (byte)'d', (byte)'!', (byte)'\n' };
            ArmoredInputStream aIn = new ArmoredInputStream(new MemoryStream(Encoding.ASCII.GetBytes(edDSASampleKey)));

            PgpPublicKeyRing rng = new PgpPublicKeyRing(aIn);

            aIn = new ArmoredInputStream(new MemoryStream(Encoding.ASCII.GetBytes(edDSASecretKey)));

            PgpSecretKeyRing secRing = new PgpSecretKeyRing(aIn);

            PgpPublicKey pubKey = rng.GetPublicKey(5145070902336167606L);
            PgpPrivateKey privKey = secRing.GetSecretKey(5145070902336167606L).ExtractPrivateKey(null);

            PgpLiteralDataGenerator lData = new PgpLiteralDataGenerator();
            MemoryStream ldOut = new MemoryStream();
            Stream pOut = lData.Open(ldOut, PgpLiteralDataGenerator.Utf8, PgpLiteralData.Console, text.Length, DateTime.Now);

            pOut.Write(text, 0, text.Length);

            pOut.Close();

            byte[] data = ldOut.ToArray();

            MemoryStream cbOut = new MemoryStream();

            PgpEncryptedDataGenerator cPk = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes128, true);

            cPk.AddMethod(pubKey);

            Stream cOut = cPk.Open(/* new UncloseableOutputStream( */ cbOut /* ) */, data.Length);

            cOut.Write(data, 0, data.Length);

            cOut.Close();

            PgpObjectFactory pgpF = new PgpObjectFactory(cbOut.ToArray());

            PgpEncryptedDataList encList = (PgpEncryptedDataList)pgpF.NextObject();

            PgpPublicKeyEncryptedData encP = (PgpPublicKeyEncryptedData)encList.Get(0);

            Stream clear = encP.GetDataStream(privKey);

            pgpF = new PgpObjectFactory(clear);

            PgpLiteralData ld = (PgpLiteralData)pgpF.NextObject();

            clear = ld.GetInputStream();
            MemoryStream bOut = new MemoryStream();

            int ch;
            while ((ch = clear.ReadByte()) >= 0)
            {
                bOut.WriteByte((byte)ch);
            }

            byte[] tout = bOut.ToArray();

            if (!AreEqual(tout, text))
            {
                Fail("wrong plain text in generated packet");
            }
        }

        private void SksKeyTest()
        {
            byte[] data = Strings.ToByteArray("testing, 1, 2, 3, testing...");

            ArmoredInputStream aIn = new ArmoredInputStream(new MemoryStream(Encoding.ASCII.GetBytes(@"-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: SKS 1.1.6

mDMEXl1WjhYJKwYBBAHaRw8BAQdAoPlx4e6UlAd0tDq8SPjwNHqUciv+FybLYrPocBJ6Ze20
HlJvYiBEZW5uaXMgPHJvYmRAdGVsZWNvbTI2LmNoPoiQBBMWCAA4FiEEtDGzEElVJ9+SNbQu
ZgxU5RXBR+oFAl5dVo4CGwMFCwkIBwIGFQoJCAsCBBYCAwECHgECF4AACgkQZgxU5RXBR+oS
ywD/RowXCrbr8dj9uVpuVKe2FFN+SdlWk/xae0LlniAeJ6QBAK+SnvX2bVStf1XIUxupqheZ
zj+W8kojFNXPK9UBECwIuDgEXl1WjhIKKwYBBAGXVQEFAQEHQBC8TTeQKgW1ml2S/uMrYETD
w56ilf/FTTTdViCJjiVGAwEIB4h4BBgWCAAgFiEEtDGzEElVJ9+SNbQuZgxU5RXBR+oFAl5d
Vo4CGwwACgkQZgxU5RXBR+pY+QD/ap3BMh/ottU4nzEg7Vo2lF/IxsBTLKkKXaXxN4a19O0B
ALUL3OLNjjcGZzKaNkkg0MGjwg/S+1xod7+75Jk3CmMD
=GN3J
-----END PGP PUBLIC KEY BLOCK----- 
")));

            // make sure we can parse it without falling over.
            PgpPublicKeyRing rng = new PgpPublicKeyRing(aIn);

            PgpEncryptedDataGenerator encDataGen = new
                PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes128, true);

            encDataGen.AddMethod(rng.GetPublicKey(6752245936421807937L));

            MemoryStream cbOut = new MemoryStream();

            Stream cOut = encDataGen.Open(/* new UncloseableOutputStream( */ cbOut /* ) */, data.Length);

            cOut.Write(data, 0, data.Length);

            cOut.Close();
        }

        public override string Name
        {
            get { return "PgpEdDsaTest2"; }
        }

        public static void Main(
            string[] args)
        {
            RunTest(new PgpECDsaTest());
        }

        [Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();

            Assert.AreEqual(Name + ": Okay", resultText);
        }
    }
}
