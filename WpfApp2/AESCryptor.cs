using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Collections;
using System.Security.Cryptography;


namespace SimpleEncryption
{
    class AESCryptor
    {
        static readonly byte[,] RijndaelSBox = new byte[16, 16]
        {
            {0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76},
            {0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0},
            {0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15},
            {0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75},
            {0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84},
            {0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf},
            {0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8},
            {0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2},
            {0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73},
            {0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb},
            {0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79},
            {0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08},
            {0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a},
            {0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e},
            {0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf},
            {0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16}
        };
        static readonly byte[,] RijndaelInverseSBox = new byte[16, 16]
       {
            {0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb},
            {0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb},
            {0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e},
            {0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25},
            {0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92},
            {0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84},
            {0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06},
            {0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b},
            {0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73},
            {0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e},
            {0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b},
            {0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4},
            {0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f},
            {0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef},
            {0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61},
            {0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d}
       };
        static readonly byte[] RCON = {
            0x01,
            0x02,
            0x04,
            0x08,
            0x10,
            0x20,
            0x40,
            0x80,
            0x1b,
            0x36
    };
        static readonly byte[,] MixColumnMultiplicator = new byte[4, 4]
        {
            {0x02,0x03,0x01,0x01},
            {0x01,0x02,0x03,0x01},
            {0x01,0x01,0x02,0x03 },
            {0x03,0x01,0x01,0x02 },
        };
        static readonly byte[,] InvMixColumnMultiplicator = new byte[4, 4]
        {
            { 0x0e, 0x0b, 0x0d,0x09 },
            { 0x09, 0x0e, 0x0b, 0x0d},
            { 0x0d, 0x09, 0x0e, 0x0b},
            { 0x0b,0x0d, 0x09, 0x0e }
        };
        public AESCryptor(byte[] _Plaintext, byte[] _CipherKeyBytes)
        {
            CipherKeyBytes = FixKeySize(_CipherKeyBytes);
            Plaintext = _Plaintext;
        }
        public AESCryptor(string _Plaintext, byte[] _CipherKeyBytes)
        {
            Plaintext = Encoding.Unicode.GetBytes(_Plaintext);
            CipherKeyBytes = FixKeySize(_CipherKeyBytes);
        }
        public AESCryptor(string _Plaintext, string _CipherKeyBytes)
        {
            Plaintext = Encoding.Unicode.GetBytes(_Plaintext);
            CipherKeyBytes = FixKeySize(Encoding.Unicode.GetBytes(_CipherKeyBytes));
        }
        public AESCryptor(byte[] _Plaintext, string _CipherKeyBytes)
        {
            CipherKeyBytes = FixKeySize(Encoding.Unicode.GetBytes(_CipherKeyBytes));
            Plaintext = _Plaintext;
        }

        byte[] CipherKeyBytes; // Ulaz u algoritam
        public byte[] Plaintext = null; // Ulaz u algoritam
        byte[] Encryptedmessage = null;

        int AddedBytes;

        
        byte[,] CipheredWord;
        byte[,] PlaintextMatrix;
        public byte[] PlainText
        {
            get
            {
                if (Plaintext == null) throw new Exception("Nije inicijalizovano");
                return Plaintext;
            }
        }
        public byte[] EncryptedMessage
        {
            get {
                if (Encryptedmessage == null) throw new Exception("Nije desifrovano nista");
                return Encryptedmessage;
            }
        }


        public static byte[] ToByteArray(BitArray bits)
        {
            byte[] ret = new byte[(bits.Length - 1) / 8 + 1];
            bits.CopyTo(ret, 0);
            return ret;

        }
        private byte[,] SubBytes(byte[,] State)
        {
            byte[,] SBoxState = new byte[4, 4];
            for (short i = 0; i < 4; i++)
            {
                for (short j = 0; j < 4; j++)
                {
                    byte[] p = new byte[1] { State[i, j] };
                    BitArray originalByte = new BitArray(p);
                    BitArray rowBits = new BitArray(4);
                    BitArray colBits = new BitArray(4);
                    for (int x = 0, y = 4; x < 4; x++, y++)
                    {
                        rowBits[x] = originalByte[y];
                        colBits[x] = originalByte[x];
                    }
                    byte[] row = ToByteArray(rowBits);
                    byte[] col = ToByteArray(colBits);
                    SBoxState[i, j] = RijndaelSBox[row[0], col[0]];

                }
            }
            return SBoxState;
        }
        private byte[] FixKeySize(byte[] OriginalCipherKey)
        {
            byte[] cipherKey = new byte[16];
            SHA1Managed managed = new SHA1Managed();
            var hashed = managed.ComputeHash(OriginalCipherKey);
            for(int i = 0; i < 16; i++)
            {
                cipherKey[i] = hashed[i];
            }

            return cipherKey;

        }
        private byte[,] ShiftRows(byte[,] State)
        {
            for(int i = 3; i >= 0; i--)
            {
                for(int j = 0; j < i; j++)
                {
                    byte temp = State[i, 0];
                    for (int x = 0; x < 3; x++)
                        State[i, x] = State[i, x + 1];
                    State[i, 3] = temp;
                }
            }
            return State;
        }
        private byte[,] MixColumns(byte [,] State)
        {
            byte[] temp = new byte[4], temporaryVector = new byte[4];
            byte tempByte = new byte();
            byte[,] newState = new byte[4, 4];
            for (int j = 0; j < 4; j++)
            {
                
                for (int i = 0; i < 4; i++)
                {
                    temp[i] = State[i, j];
                }
                for (int mi = 0; mi < 4; mi++)
                {
                    byte djuro = 0x00;
                    for(int mj = 0; mj < 4; mj++)
                    {
                        if (MixColumnMultiplicator[mi, mj] == 1)
                        {
                            tempByte = temp[mj];
                        } else if(MixColumnMultiplicator[mi, mj] == 2) {
                            tempByte = temp[mj];
                            BitArray x = new BitArray(new byte[] { temp[mj] });
                            BitArray o = new BitArray(new byte[] { 0x90 });
                            if(x[7] == true)
                            {
                                tempByte <<= 1;
                                x = new BitArray(new byte[] { tempByte });
                                o = new BitArray(new byte[] { 0x1B });
                                x.Xor(o);
                                tempByte = ToByteArray(x)[0];
                            } else { tempByte <<= 1; }
                            
                        }
                        else if (MixColumnMultiplicator[mi, mj] == 3)
                        {
                            tempByte = temp[mj];
                            byte[] beforeXor = new byte[] { tempByte };
                            BitArray x = new BitArray(new byte[] { temp[mj] });
                            BitArray o = new BitArray(new byte[] { 0x90 });
                            if (x[7] == true)
                            {
                                tempByte <<= 1;
                                x = new BitArray(new byte[] { tempByte });
                                o = new BitArray(new byte[] { 0x1B });
                                x.Xor(o);
                                tempByte = ToByteArray(x)[0];
                            }
                            else { tempByte <<= 1; }
                            byte[] afterXor = new byte[] { tempByte };
                            BitArray before = new BitArray(beforeXor);
                            BitArray after = new BitArray(afterXor);
                            after.Xor(before);
                            tempByte = ToByteArray(after)[0];
                        }
                        djuro ^= tempByte;
                    }
                    temporaryVector[mi] = djuro;
                }
                for(int tempCancer = 0; tempCancer < 4; tempCancer++)
                {
                    newState[tempCancer, j] = temporaryVector[tempCancer];
                }
                
            }
            return newState;
        }
        private byte[,] AddRoundKey(byte [,] State, byte[,] words)
        {
            string tempo = "";
            byte[] yy = new byte[16];
            int u = 0;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    yy[u++] = State[i, j];
                }
            }
            tempo = BitConverter.ToString(yy);
            for (int i = 0; i < 4; i++)
            {
               
                for(int j = 0; j < 4; j++)
                {
                    byte[] States = new byte[1];
                    States[0] = State[i, j];
                    byte[] Words = new byte[1];
                    Words[0] = words[i, j];
                    BitArray StateByte = new BitArray(States);
                    BitArray WordByte = new BitArray(Words);
                    StateByte.Xor(WordByte);
                    State[i, j] = ToByteArray(StateByte)[0];
                }
            }
           
            return State;
        }
        private byte[,] KeyExpansion(byte[] cipherKey) //Ok
        {
            string[] arr = new string[40];
            int oo = 0;
            string urmom = "";
            byte[,] w = new byte[44, 4];
            byte[] temp = new byte[4];
            short i = 0;
            while(i < 4)
            {
                w[i, 0] = cipherKey[0+i*4];
                w[i, 1] = cipherKey[1+i*4];
                w[i, 2] = cipherKey[2+i*4];
                w[i, 3] = cipherKey[3+i*4];
                i++;
            }
            i = 4;
            while(i < 44)
            {
                for (int j = 0; j < 4; j++)
                    temp[j] = w[i - 1, j];

                urmom += BitConverter.ToString(temp);
                if (i % 4 == 0)
                {
                    temp = SubWord(RotWord(temp));
                    BitArray tempBit = new BitArray(temp);
                    byte[] tempo = new byte[4];
                    tempo[0] = RCON[(i / 4) - 1];
                    for (int x = 1; x < 4; x++) tempo[x] = 0x00;
                    BitArray Rcon = new BitArray(tempo);
                    tempBit.Xor(Rcon);
                    temp = ToByteArray(tempBit);
                }
                byte[] yok = new byte[4];
                for (int j = 0; j < 4; j++)
                {
                    yok[j] = w[i - 4, j];
                   
                }
                BitArray temp1 = new BitArray(yok);
                BitArray temp2 = new BitArray(temp);
                byte[] fake = ToByteArray(temp1.Xor(temp2));
                for (int j = 0; j < 4; j++) {
                    
                    w[i, j] = fake[j];
                }
                urmom = BitConverter.ToString(fake);
                arr[oo++] = urmom;
                i++;
                urmom = "";
            }
            return w;
        }
        private byte[] SubWord(byte[] mothafuckahehe)
        {
            for (int i = 0; i < 4; i++)
            {
                BitArray rowBits = new BitArray(4);
                BitArray colBits = new BitArray(4);
                byte[] g = new byte[] { mothafuckahehe[i] };
                BitArray originalByte = new BitArray(g);
                for (int x = 0, y = 4; x < 4; x++, y++)
                {
                    rowBits[x] = originalByte[y];
                    colBits[x] = originalByte[x];
                }
                byte[] row = ToByteArray(rowBits);
                byte[] col = ToByteArray(colBits);
                mothafuckahehe[i] = RijndaelSBox[row[0], col[0]];
            }
            return mothafuckahehe;
        }
        private byte[] RotWord(byte[] temp)
        {
            byte first = temp[0];
            for(int i = 0; i < 3; i++)
            {
                temp[i] = temp[i + 1];
            }
            temp[3] = first;
            return temp;
        }
        private byte[,] Encrypt(byte[,] InputPlaintext, byte[] CipherKey)
        {
            byte[,] State = new byte[4,4];
            State = InputPlaintext;
            byte[,] w = KeyExpansion(CipherKey);
            byte[,] word = new byte[4,4];
            for (int i = 0; i < 4; i++)
                for(int j = 0; j < 4; j++)
                    word[j,i] = w[i,j];
            State = AddRoundKey(State, word);
            
            for (short round = 1; round < 10; round++)
            {
                State = SubBytes(State);
                State = ShiftRows(State);
                State = MixColumns(State);
                for (int i = 0; i < 4; i++)
                    for (int j = 0; j < 4; j++)
                        word[j, i] = w[(round*4)+i, j];
                State = AddRoundKey(State, word);
                
            }
            State = SubBytes(State);
            State = ShiftRows(State);
            for (int i = 0; i < 4; i++)
                for(int j = 0; j < 4;j++)
                    word[j,i] = w[40 + i, j];
            State = AddRoundKey(State, word);
            CipheredWord = State;
            return State;
        }
        public byte[] Encrypt()
        {
            byte[] newPlaintext;
            
            if(Plaintext.Length % 16 != 0)
            {
                AddedBytes = 16 - Plaintext.Length % 16;
                newPlaintext = new byte[Plaintext.Length + AddedBytes];
                for(int i = 0; i < newPlaintext.Length; i++) { newPlaintext[i] = 0xFF; }
                for(int i = 0; i < Plaintext.Length; i++)
                {
                    newPlaintext[i] = Plaintext[i];
                }
            } else
            {
                newPlaintext = Plaintext;
            }
            Encryptedmessage = new byte[newPlaintext.Length + 2];
            Encryptedmessage[0] = Convert.ToByte(AddedBytes);
            Encryptedmessage[1] = Convert.ToByte(AddedBytes);
            for (int pt = 0; pt < newPlaintext.Length; pt += 16)
            {
                byte[] temp = new byte[16];
                for(int tp = pt, j = 0; tp < pt + 16; tp++, j++)
                {
                    temp[j] = newPlaintext[tp];
                }
                byte[,] InputState = new byte[4, 4];
                int x = 0;
                for (int i = 0; i < 4; i++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        InputState[i, j] = temp[x++];
                    }
                }
                byte[,] poop = Encrypt(InputState, CipherKeyBytes);
                byte[] mako = new byte[16];
                int u = 0;
                for(int i = 0; i < 4; i++)
                {
                    for(int j = 0; j < 4; j++)
                    {
                        mako[u++] = poop[i, j];
                    }
                }
                for (int tp = pt, j = 0; tp < pt + 16; tp++, j++)
                {
                    Encryptedmessage[pt+j+2] = mako[j];
                }
            }
            return Encryptedmessage;
        }

        // DECRYPTION
        private byte[,] InvShiftRows(byte[,] State)
        {
            for (int i = 3; i >= 0; i--)
            {
                for (int j = 0; j < 4 - i; j++)
                {
                    byte temp = State[i, 0];
                    for (int x = 0; x < 3; x++)
                        State[i, x] = State[i, x + 1];
                    State[i, 3] = temp;
                }
            }
            return State;
        }
        private byte[,] InvSubBytes(byte[,] State)
        {
            byte[,] SBoxState = new byte[4, 4];
            for (short i = 0; i < 4; i++)
            {
                for (short j = 0; j < 4; j++)
                {
                    byte[] p = new byte[1] { State[i, j] };
                    BitArray originalByte = new BitArray(p);
                    BitArray rowBits = new BitArray(4);
                    BitArray colBits = new BitArray(4);
                    for (int x = 0, y = 4; x < 4; x++, y++)
                    {
                        rowBits[x] = originalByte[y];
                        colBits[x] = originalByte[x];
                    }
                    byte[] row = ToByteArray(rowBits);
                    byte[] col = ToByteArray(colBits);
                    SBoxState[i, j] = RijndaelInverseSBox[row[0], col[0]];

                }
            }
            return SBoxState;
        }
        private byte[,] InvMixColumns(byte[,] State)
        {
            byte[] temp = new byte[4], temporaryVector = new byte[4];
            byte tempByte = new byte();
            BitArray x;
            BitArray o;
            byte[,] newState = new byte[4, 4];
            for (int j = 0; j < 4; j++)
            {

                for (int i = 0; i < 4; i++)
                {
                    temp[i] = State[i, j];
                }
                for (int mi = 0; mi < 4; mi++)
                {
                    
                    byte djuro = 0x00;
                    for (int mj = 0; mj < 4; mj++)
                    {
                        if (InvMixColumnMultiplicator[mi, mj] == 9)
                        {
                            tempByte = temp[mj];
                            BitArray oldOne = new BitArray(new byte[] { tempByte });
                            for (int m = 0; m < 3; m++)
                            {
                                x = new BitArray(new byte[] { tempByte });
                                o = new BitArray(new byte[] { 0x90 });
                                if (x[7] == true)
                                {
                                    tempByte <<= 1;
                                    x = new BitArray(new byte[] { tempByte });
                                    o = new BitArray(new byte[] { 0x1B });
                                    x.Xor(o);
                                    tempByte = ToByteArray(x)[0];
                                }
                                else { tempByte <<= 1; }
                            }
                            BitArray newOne = new BitArray(new byte[] { tempByte });
                            newOne.Xor(oldOne);
                            tempByte = ToByteArray(newOne)[0];
                        }
                        else if (InvMixColumnMultiplicator[mi, mj] == 11)
                        {
                            tempByte = temp[mj];
                            BitArray oldOne = new BitArray(new byte[] { tempByte });
                            for (int m = 0; m < 2; m++)
                            {
                                x = new BitArray(new byte[] { tempByte });
                                o = new BitArray(new byte[] { 0x90 });
                                if (x[7] == true)
                                {
                                    tempByte <<= 1;
                                    x = new BitArray(new byte[] { tempByte });
                                    o = new BitArray(new byte[] { 0x1B });
                                    x.Xor(o);
                                    tempByte = ToByteArray(x)[0];
                                }
                                else { tempByte <<= 1; }
                            }
                            BitArray newOne = new BitArray(new byte[] { tempByte });
                            newOne.Xor(oldOne);
                            tempByte = ToByteArray(newOne)[0];
                            x = new BitArray(new byte[] { tempByte });
                            o = new BitArray(new byte[] { 0x90 });
                            if (x[7] == true)
                            {
                                tempByte <<= 1;
                                x = new BitArray(new byte[] { tempByte });
                                o = new BitArray(new byte[] { 0x1B });
                                x.Xor(o);
                                tempByte = ToByteArray(x)[0];
                            }
                            else { tempByte <<= 1; }
                            newOne = new BitArray(new byte[] { tempByte });
                            newOne.Xor(oldOne);
                            tempByte = ToByteArray(newOne)[0];
                        }
                        else if (InvMixColumnMultiplicator[mi, mj] == 13)
                        {
                            tempByte = temp[mj];
                            BitArray oldOne = new BitArray(new byte[] { tempByte });
                            x = new BitArray(new byte[] { tempByte });
                            o = new BitArray(new byte[] { 0x90 });
                            if (x[7] == true)
                            {
                                tempByte <<= 1;
                                x = new BitArray(new byte[] { tempByte });
                                o = new BitArray(new byte[] { 0x1B });
                                x.Xor(o);
                                tempByte = ToByteArray(x)[0];
                            }
                            else { tempByte <<= 1; }
                            BitArray newOne = new BitArray(new byte[] { tempByte });
                            newOne.Xor(oldOne);
                            tempByte = ToByteArray(newOne)[0];
                            for (int i = 0; i < 2; i++)
                            {
                                x = new BitArray(new byte[] { tempByte });
                                o = new BitArray(new byte[] { 0x90 });
                                if (x[7] == true)
                                {
                                    tempByte <<= 1;
                                    x = new BitArray(new byte[] { tempByte });
                                    o = new BitArray(new byte[] { 0x1B });
                                    x.Xor(o);
                                    tempByte = ToByteArray(x)[0];
                                }
                                else { tempByte <<= 1; }
                            }
                            newOne = new BitArray(new byte[] { tempByte });
                            newOne.Xor(oldOne);
                            tempByte = ToByteArray(newOne)[0];
                        }
                        else if (InvMixColumnMultiplicator[mi, mj] == 14)
                        {
                            tempByte = temp[mj];
                            BitArray oldOne = new BitArray(new byte[] { tempByte });
                            x = new BitArray(new byte[] { tempByte });
                            o = new BitArray(new byte[] { 0x90 });
                            if (x[7] == true)
                            {
                                tempByte <<= 1;
                                x = new BitArray(new byte[] { tempByte });
                                o = new BitArray(new byte[] { 0x1B });
                                x.Xor(o);
                                tempByte = ToByteArray(x)[0];
                            }
                            else { tempByte <<= 1; }
                            BitArray newOne = new BitArray(new byte[] { tempByte });
                            newOne.Xor(oldOne);
                            tempByte = ToByteArray(newOne)[0];
                            x = new BitArray(new byte[] { tempByte });
                            o = new BitArray(new byte[] { 0x90 });
                            if (x[7] == true)
                            {
                                tempByte <<= 1;
                                x = new BitArray(new byte[] { tempByte });
                                o = new BitArray(new byte[] { 0x1B });
                                x.Xor(o);
                                tempByte = ToByteArray(x)[0];
                            }
                            else { tempByte <<= 1; }
                            newOne = new BitArray(new byte[] { tempByte });
                            newOne.Xor(oldOne);
                            tempByte = ToByteArray(newOne)[0];
                            x = new BitArray(new byte[] { tempByte });
                            o = new BitArray(new byte[] { 0x90 });
                            if (x[7] == true)
                            {
                                tempByte <<= 1;
                                x = new BitArray(new byte[] { tempByte });
                                o = new BitArray(new byte[] { 0x1B });
                                x.Xor(o);
                                tempByte = ToByteArray(x)[0];
                            }
                            else { tempByte <<= 1; }
                        }
                        djuro ^= tempByte;
                    }
                    temporaryVector[mi] = djuro;
                }
                for (int tempCancer = 0; tempCancer < 4; tempCancer++)
                {
                    newState[tempCancer, j] = temporaryVector[tempCancer];
                }

            }
            return newState;
        }
        private byte[,] Decrypt(byte[,] InputCipher, byte[] CipherKey) {

            byte[,] State = new byte[4, 4];
            State = InputCipher;
            byte[,] w = KeyExpansion(CipherKey);
            byte[,] word = new byte[4, 4];
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    word[j, i] = w[40 + i, j];
            State = AddRoundKey(State, word);

            for (short round = 9; round > 0; round--)
            {
                State = InvShiftRows(State);
                State = InvSubBytes(State);
                for (int i = 0; i < 4; i++)
                    for (int j = 0; j < 4; j++)
                        word[j, i] = w[(round*4) + i, j];
                State = AddRoundKey(State, word);
                State = InvMixColumns(State);
            }

            State = InvShiftRows(State);
            State = InvSubBytes(State);
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    word[j, i] = w[i, j];
            State = AddRoundKey(State, word);

            PlaintextMatrix = State;
            return State;
        }
        public byte[] Decrypt()
        {
            
            if (Encryptedmessage == null)
            {
                AddedBytes = Plaintext[1];
                if (AddedBytes > 16) throw new Exception("Plaintext nije sifrovan");
                Encryptedmessage = Plaintext;
            } else { AddedBytes = Encryptedmessage[1]; }
            Plaintext = new byte[Encryptedmessage.Length - 2];
            for(int i = 2; i < Encryptedmessage.Length; i += 16)
            {
                byte[,] tempEn = new byte[4,4];
                int u = i;
                for(int ii = 0; ii < 4; ii++)
                {
                    for(int jj = 0; jj < 4; jj++)
                    {
                        tempEn[ii, jj] = Encryptedmessage[u++];
                    }
                }
                tempEn = Decrypt(tempEn, CipherKeyBytes);

                u = i - 2;
                for (int ii = 0; ii < 4; ii++)
                {
                    for (int jj = 0; jj < 4; jj++)
                    {
                        Plaintext[u++] = tempEn[ii, jj];
                    }
                }
            }
            byte[] tempNew = new byte[Plaintext.Length - AddedBytes];
            for(int i = 0; i < tempNew.Length; i++)
            {
                tempNew[i] = Plaintext[i];
            }
            Plaintext = new byte[tempNew.Length];
            Plaintext = tempNew;
            return Plaintext;
        }
    }
}
