using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Collections;
namespace SimpleEncryption
{

    class DESCryptor
    {
        private readonly short[] PC_1_Table = new short[]
        {
               57, 49, 41, 33, 25, 17, 9,
               1,  58, 50, 42, 34, 26, 18,
               10, 2,  59, 51, 43, 35, 27,
               19, 11, 3,  60, 52, 44, 36,
               63, 55, 47, 39, 31, 23, 15,
               7,  62, 54, 46, 38, 30, 22,
               14, 6,  61, 53, 45, 37, 29,
               21, 13, 5,  28, 20, 12, 4
        };
        private readonly short[] ShiftTable = new short[]
        {
            1,
            1,
            2,
            2,
            2,
            2,
            2,
            2,
            1,
            2,
            2,
            2,
            2,
            2,
            2,
            1
        };
        private readonly short[] PC_2_Table = new short[]
        {
                 14, 17, 11, 24, 1, 5,
                 3,  28, 15, 6, 21, 10,
                 23, 19, 12, 4, 26, 8,
                 16, 7,  27, 20,13, 2,
                 41, 52, 31, 37,47, 55,
                 30, 40, 51, 45,33, 48,
                 44, 49, 39, 56,34, 53,
                 46, 42, 50, 36,29, 32
        };
        private readonly short[] ipPos = new short[] {

                                       58,50,42,34,26,18,10,2,
                                       60,52,44,36,28,20,12,4,
                                       62,54,46,38,30,22,14,6,
                                       64,56,48,40,32,24,16,8,
                                       57,49,41,33,25,17,9,1,
                                       59,51,43,35,27,19,11,3,
                                       61,53,45,37,29,21,13,5,
                                       63,55,47,39,31,23,15,7

        };
        private readonly short[] EBitSelection = new short[]
        {
            32, 1 , 2 , 3 , 4 , 5,
            4,  5,  6,  7,  8,  9,
            8, 9,   10,    11,    12,   13,
            12 ,   13   ,14,    15    ,16 ,  17,
            16  ,  17   ,18 ,   19   , 20  , 21,
            20   , 21  , 22  ,  23  ,  24   ,25,
            24    ,25 ,  26   , 27 ,   28  , 29,
            28    ,29,   30    ,31,    32  ,  1
        };
        private readonly short[,] S1SubstitutionBox = new short[,]
        {
            { 10,  0 ,  9, 14  , 6,  3 , 15,  5  , 1 ,13  ,12 , 7  ,11,  4  , 2,  8 },
            { 13,  7 ,  0,  9 ,  3,  4 ,  6 ,10 ,  2,  8 ,  5, 14  ,12, 11 , 15,  1 },
            { 13,  6,   4,  9,   8, 15,   3 , 0,  11 , 1,   2 ,12 ,  5, 10,  14,  7 },
            { 1, 10,  13 , 0,   6 , 9,   8  ,7,   4 ,15,  14  ,3,  11,  5,   2 ,12 }
        };
        private readonly short[,] S2SubstititionBox = new short[,]
        {
            { 15,  1,   8, 14,   6 ,11,   3 , 4,   9 , 7,   2 ,13,  12 , 0,   5 ,10 },
            { 3, 13,   4,  7,  15 , 2 ,  8, 14 , 12 , 0 ,  1 ,10,   6 , 9 , 11,  5 },
            { 0, 14,   7, 11,  10 , 4 , 13 , 1 ,  5 , 8 , 12 , 6,   9 , 3 ,  2, 15 },
            { 13,  8,  10,  1,   3, 15 ,  4,  2 , 11,  6 ,  7, 12 ,  0 , 5,  14 , 9 }
        };
        private readonly short[,] S3SubstitutionBox = new short[,]
        {
            { 10  ,0,   9 ,14,   6  ,3,  15 , 5,   1 ,13,  12,  7,  11 , 4,   2  ,8 },
            { 13 , 7 ,  0 , 9,   3 , 4,   6 ,10,   2 , 8,   5, 14,  12, 11,  15 , 1 },
            { 13,  6 ,  4,  9,   8, 15,   3,  0,  11,  1,   2, 12,   5, 10,  14,  7 },
            { 1, 10 , 13,  0 ,  6,  9 ,  8,  7 ,  4, 15 , 14,  3 , 11,  5 ,  2, 12 }
        };
        private readonly short[,] S4SubstitutionBox = new short[,]
        {
            { 7, 13 , 14,  3 ,  0,  6 ,  9, 10 ,  1,  2 ,  8,  5 , 11, 12 ,  4, 15 },
            { 13,  8,  11,  5,   6, 15,   0,  3,   4,  7,   2, 12,   1 ,10,  14,  9 },
            { 10 , 6,   9,  0,  12, 11,   7, 13,  15,  1,   3, 14,   5,  2,   8,  4 },
            { 3 ,15,   0 , 6,  10 , 1,  13,  8,   9 , 4,   5 ,11,  12 , 7,   2, 14 }
        };
        private readonly short[,] S5SubstitutionBox = new short[,]
        {
             { 2, 12,   4,  1,   7, 10,  11,  6,   8,  5,   3, 15,  13,  0,  14,  9 },
             { 14, 11,   2, 12,   4,  7,  13 , 1  , 5 , 0 , 15, 10 ,  3,  9,   8,  6 },
             { 4,  2 ,  1, 11,  10 ,13 ,  7 , 8 , 15 , 9 , 12 , 5 ,  6,  3 ,  0 ,14 },
             { 11,  8,  12,  7,   1, 14 ,  2, 13,   6, 15,   0,  9,  10,  4,   5,  3 }
        };
        private readonly short[,] S6SubstitutionBox = new short[,]
        {
            { 12,  1 , 10, 15,   9,  2  , 6,  8  , 0, 13  , 3,  4 , 14,  7  , 5 ,11 },
            { 10, 15 ,  4,  2 ,  7, 12 ,  9 , 5 ,  6,  1 , 13, 14 ,  0, 11 ,  3 , 8 },
            { 9, 14 , 15,  5 ,  2,  8 , 12 , 3 ,  7 , 0 ,  4 ,10  , 1 ,13 , 11  ,6 },
            { 4,  3,   2, 12,   9,  5,  15 ,10,  11 ,14,   1 , 7 ,  6  ,0 ,  8 ,13 }
        };
        private readonly short[,] S7SubstitutionBox = new short[,]
        {
            { 4, 11 ,  2, 14  ,15,  0  , 8, 13   ,3 ,12  , 9 , 7   ,5 ,10   ,6,  1 },
            { 13,  0,  11,  7 ,  4,  9,   1, 10 , 14,  3 ,  5, 12 ,  2 ,15 ,  8,  6 },
            { 1,  4 , 11, 13,  12 , 3,   7 ,14 , 10 ,15 ,  6 , 8 ,  0  ,5 ,  9 , 2 },
           { 6, 11,  13,  8,   1 , 4,  10 , 7,   9 , 5,   0 ,15,  14  ,2,   3 ,12 }
        };
        private readonly short[,] S8SubstitutionBox = new short[,]
        {
            { 13,  2 ,  8,  4,   6, 15,  11,  1,  10,  9  , 3, 14  , 5 , 0  ,12,  7 },
            { 1 ,15 , 13 , 8,  10 , 3,   7 , 4,  12 , 5  , 6, 11  , 0 ,14  , 9 , 2 },
            { 7 ,11,   4 , 1,   9, 12,  14 , 2,   0 , 6 , 10, 13 , 15  ,3 ,  5 , 8 },
            { 2 , 1,  14 , 7,   4, 10,   8, 13,  15 ,12,   9,  0,   3  ,5,   6 ,11 }
        };
        private readonly short[] PermutationBox = new short[]
        {
            16,   7  ,20,  21,
            29 , 12 , 28,  17,
            1  ,15 , 23 , 26,
            5 , 18 , 31 , 10,
            2  , 8 , 24 , 14,
            32  ,27,   3,   9,
            19 , 13,  30,   6,
            22 , 11,   4,  25
        };
        private readonly short[] inverseIpPos = new short[]
        {
            40,     8 ,  48,    16,    56,   24,    64,   32,
            39 ,    7 ,  47 ,   15,    55,   23,    63,   31,
            38 ,    6 ,  46 ,   14,    54,   22,    62,   30,
            37 ,    5 ,  45 ,   13,    53,   21,    61,   29,
            36 ,    4 ,  44 ,   12,    52,   20,    60,   28,
            35 ,    3 ,  43 ,   11,    51,   19,    59,   27,
            34 ,    2 ,  42 ,   10,    50,   18,    58,   26,
            33 ,    1,   41 ,    9,    49,   17,    57,   25
        };

        public static byte[] ToByteArray(BitArray bits)
        {
            byte[] ret = new byte[(bits.Length - 1) / 8 + 1];
            bits.CopyTo(ret, 0);
            return ret;

        }
        public DESCryptor(string _PlainText, string _Key)
        {
            PlainText = Encoding.Unicode.GetBytes(_PlainText);
            byte[] ByteKey = new byte[8];
            ByteKey = Encoding.Unicode.GetBytes(_Key);
            BitKey = new BitArray(ByteKey);
            GenerateDesKey(_Key);
        }
        public DESCryptor(byte[] _PlainText, string _Key)
        {
            PlainText = _PlainText;
            byte[] ByteKey = new byte[8];
            ByteKey = Encoding.Unicode.GetBytes(_Key);
            BitKey = new BitArray(ByteKey);
            GenerateDesKey(_Key);
        }
        private byte[] PlainText;
        private BitArray BitKey;
        private byte[] ciphertextByte;
        private BitArray cipherText;
        private byte[] inverseCipherTextByte;
        private BitArray inverseCipherText;

        public byte[] CipherText
        {
            get { return ciphertextByte; }
        }
        public byte[] InverseCipherText {  get { return inverseCipherTextByte; } }
        
        private void GenerateDesKey(string key)
        {
            //Ne radi se parity bit
            using (SHA1Managed sha1 = new SHA1Managed())
            {
                byte[] keyByte = new byte[8];
                var hash = sha1.ComputeHash(Encoding.ASCII.GetBytes(key));
                for (int i = 0; i < 8; i++)
                {
                    keyByte[i] = hash[i];
                }
                BitKey = new BitArray(keyByte);
            }
        }
        private BitArray IP(byte[] array)
        {
            BitArray permutedArray = new BitArray(64); // Inicijalizuj permutacioni array
            BitArray initialArray = new BitArray(array);
            for (int i = 1; i <= 64; i++)
            {
                int index = ipPos[i - 1] - 1; //Koji bit treba zameniti
                permutedArray[i - 1] = initialArray[index];
            }
            return permutedArray;
        }
        private BitArray PC1(BitArray KeyBits) {
            BitArray KPlusBits = new BitArray(56);
            
            for(int i = 0; i < 56; i++)
            {
                KPlusBits[i] = KeyBits[PC_1_Table[i] - 1];
            }
            return KPlusBits;
        }
        private BitArray PC2(BitArray KPlus)
        {
            BitArray SubkeyBits = new BitArray(48);
            for (int i = 0; i < 48; i++)
            {
                SubkeyBits[i] = KPlus[PC_2_Table[i] - 1];
            }
            return SubkeyBits;
        }
        private BitArray[] GenerateKeys()
        {
            BitArray KPlus = PC1(BitKey);
            BitArray C0 = new BitArray(28);
            BitArray D0 = new BitArray(28);
            BitArray[] PC2Complete = new BitArray[16];
            for (int i = 0; i < 16; i++)
                PC2Complete[i] = new BitArray(48);
            BitArray[] CArray = new BitArray[16];
            BitArray[] DArray = new BitArray[16];
            BitArray[] CDArray = new BitArray[16];
            for(int i = 0; i < 16; i++)
            {
                CArray[i] = new BitArray(28);
                DArray[i] = new BitArray(28);
                CDArray[i] = new BitArray(56);
            }
            for(int i = 0, j = 28; i < 28; i++, j++)
            {
                C0[i] = KPlus[i];
                D0[i] = KPlus[j];
            }
            for(int i = 1; i < 28; i++)
            {
                CArray[0][i] = C0[i - 1];
                DArray[0][i] = D0[i - 1];
            }
            CArray[0][0] = C0[15];
            DArray[0][0] = D0[15];
            for (int i = 1; i < 16; i++)
            {
                CArray[i] = shiftBits(CArray[i - 1], ShiftTable[i]);
                DArray[i] = shiftBits(DArray[i - 1], ShiftTable[i]);
            }
            for(int i = 1; i < 16; i++)
            {
                for(int j = 0, z = 28; j < 28; j++, z++)
                {
                    CDArray[i][j] = CArray[i][j];
                    CDArray[i][z] = DArray[i][j];
                }
                PC2Complete[i] = PC2(CDArray[i]);
            }
            return PC2Complete;
        }
        private BitArray shiftBits(BitArray bitArray, short v)
        {
            for(short i = 0; i < v; i++)
            {
                bool temp = bitArray[27];
                for(int j = 27; j > 0; j--)
                {
                    bitArray[j] = bitArray[j - 1];
                }
                bitArray[0] = temp;
            }
            return bitArray;
        }
        private BitArray supstitutionFunction(BitArray right, BitArray Key)
        {
            BitArray Rprime = EBitSelectionFunction(right);
            Rprime.Xor(Key);
            BitArray[] RPrimeSixBitArrays = new BitArray[8];
            for(int i = 0; i < 8; i++)
            {
                RPrimeSixBitArrays[i] = new BitArray(6);
            }
            for(short s1 = 0, s2 = 6, s3 = 12, s4 = 18, s5 = 24, s6 = 30, s7 = 36, s8 = 42; s1 < 6; s1++, s2++, s3++, s4++, s5++, s6++, s7++, s8++)
            {
                RPrimeSixBitArrays[0][s1] = Rprime[s1];
                RPrimeSixBitArrays[1][s1] = Rprime[s2];
                RPrimeSixBitArrays[2][s1] = Rprime[s3];
                RPrimeSixBitArrays[3][s1] = Rprime[s4];
                RPrimeSixBitArrays[4][s1] = Rprime[s5];
                RPrimeSixBitArrays[5][s1] = Rprime[s6];
                RPrimeSixBitArrays[6][s1] = Rprime[s7];
                RPrimeSixBitArrays[7][s1] = Rprime[s8];
            }
            BitArray Px = new BitArray(32);
            for (int i = 0; i < 8; i++)
            {
                BitArray temp = new BitArray(4);
                temp = SBoxSubstitution(RPrimeSixBitArrays[i], i + 1);
                for(int j = i*4, z = 0; z < 4; j++, z++)
                {
                    Px[j] = temp[z];
                }
            }

            Px = PermutationBoxFunction(Px);
            return Px;
        }
        private BitArray PermutationBoxFunction(BitArray px)
        {
            BitArray bb = new BitArray(32);
            for(int i = 0; i < 32; i++)
            {
                bb[i] = px[PermutationBox[i] - 1];
            }
            return bb;
        }
        private BitArray SBoxSubstitution(BitArray bitArray, int v)
        {
            short[][,] array = new short[8][,]{ S1SubstitutionBox, S2SubstititionBox, S3SubstitutionBox, S4SubstitutionBox, S5SubstitutionBox, S6SubstitutionBox, S7SubstitutionBox, S8SubstitutionBox };
            int row = Convert.ToInt32(bitArray[0]) + Convert.ToInt32(bitArray[5])*2;
            int column = Convert.ToInt32(bitArray[4])*8 + Convert.ToInt32(bitArray[3])*4 + Convert.ToInt32(bitArray[2])*2 + Convert.ToInt32(bitArray[1]);
            short result = array[v - 1][row, column];
            byte[] resultBytes = BitConverter.GetBytes(result);
            BitArray temp = new BitArray(resultBytes);
            BitArray Result = new BitArray(4);
            for (int i = 0; i < 4; i++) Result[i] = temp[i];
            return Result;
        }
        private BitArray EBitSelectionFunction(BitArray right)
        {
            BitArray EBitArray = new BitArray(48);

            for(int i = 0; i < 48; i++)
            {
                EBitArray[i] = right[EBitSelection[i] - 1];
            }
            return EBitArray;
        }
        private BitArray InverseIP(BitArray array)
        {
            BitArray permutedArray = new BitArray(64); // Inicijalizuj permutacioni 
            for (int i = 1; i <= 64; i++)
            {
                int index = inverseIpPos[i - 1] - 1; //Koji bit treba zameniti
                permutedArray[i - 1] = array[index];
            }
            return permutedArray;
        }
        public void DESEncrypt()
        {
            int originalByteLength = PlainText.Length;
            int offset = originalByteLength % 8;
            byte[] AddedBytes = new byte[originalByteLength + 9 - offset];
            for (int i = 1; i <= originalByteLength; i++)
            {
                AddedBytes[i] = PlainText[i - 1];
            }
            AddedBytes[0] = Convert.ToByte(8 - offset);
            for (int k = 1; k < AddedBytes.Length; k+=8)
            {
                byte[] x = new byte[8];
                for(int o = k, j = 0; j < 8; j++, o++)
                {
                    x[j] = AddedBytes[o];
                }
                BitArray initPermut = IP(x);
                BitArray IPBits = initPermut;
                BitArray Left = new BitArray(32);
                BitArray Right = new BitArray(32);
                BitArray[] SubKeys = GenerateKeys();
                for (int i = 0, j = 32; i < 32; i++, j++)
                {
                    Left[i] = IPBits[i];
                    Right[i] = IPBits[j];
                }
                for (int i = 0; i < 15; i++)
                {
                    BitArray temp = Left;
                    Left = Right;

                    Right = temp.Xor(supstitutionFunction(Right, SubKeys[i]));

                }

                BitArray temp1 = Left;
                Left = Right;
                Right = temp1.Xor(supstitutionFunction(Right, SubKeys[15]));
                cipherText = new BitArray(64);
                for (int i = 0, j = 32; i < 32; i++, j++)
                {
                    cipherText[i] = Right[i];
                    cipherText[j] = Left[i];
                }
                cipherText = InverseIP(cipherText);
                ciphertextByte = ToByteArray(cipherText);
                for(int o = k, j = 0; j < 8; j++, o++)
                {
                    AddedBytes[o] = ciphertextByte[j];
                }
            }
            PlainText = AddedBytes;
            ciphertextByte = AddedBytes;
        }
        public void DESDecrypt()
        {
            int numberOfAddedBytes = Convert.ToInt32(PlainText[0]);
            if (numberOfAddedBytes > 8) throw new Exception("File is not encrypted!");
            byte[] tempe = new byte[PlainText.Length - 1];
            for (int k = 1; k < PlainText.Length; k+=8)
            {
                byte[] x = new byte[8];
                for(int o = k, j = 0; j < 8; j++, o++)
                {
                    x[j] = PlainText[o];
                }
                BitArray initPermut = IP(x);
                BitArray IPBits = initPermut;
                BitArray Left = new BitArray(32);
                BitArray Right = new BitArray(32);
                BitArray[] SubKeys = GenerateKeys();
                for (int i = 0, j = 32; i < 32; i++, j++)
                {
                    Left[i] = IPBits[i];
                    Right[i] = IPBits[j];
                }
                for (int i = 0; i < 15; i++)
                {
                    BitArray temp = Left;
                    Left = Right;
                    Right = temp.Xor(supstitutionFunction(Right, SubKeys[15 - i]));

                }

                BitArray temp1 = Left;
                Left = Right;
                Right = temp1.Xor(supstitutionFunction(Right, SubKeys[0]));
                inverseCipherText = new BitArray(64);
                for (int i = 0, j = 32; i < 32; i++, j++)
                {
                    inverseCipherText[i] = Right[i];
                    inverseCipherText[j] = Left[i];
                }
                inverseCipherText = InverseIP(inverseCipherText);
                inverseCipherTextByte = ToByteArray(inverseCipherText);
                for (int o = k, j = 0; j < 8; j++, o++)
                {
                    tempe[o-1] = inverseCipherTextByte[j];
                }
            }
            byte[] original = new byte[PlainText.Length - 1 - numberOfAddedBytes];
            for(int i = 0; i < PlainText.Length - 1 - numberOfAddedBytes; i++)
            {
                original[i] = tempe[i];
            }
            inverseCipherTextByte = original;
        }
    }
}
