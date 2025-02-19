using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using System.Security.Cryptography.Xml;
using System.Numerics;
using System.Threading;
using System.ComponentModel.DataAnnotations;
using System.Formats.Asn1;

namespace ACrypt
{
    // An aritmetic coder (compressor) that encrypts by 
    // taking a hash of given length of the provided key and/or pin and IV and
    // encodes it with 100% foreknowledge as a prefix of the message (basically using zero space).
    
    // The remainder of the message is encoded with a symbol table using a simple prefix adaptive model that is surprisingly effective
    // It does the same on decode to remove the prefix and decode the remaining message successfully.

    // Decrypt *must* use the same Key, Pin, IV, Step as Encrypt. All are optional.

    // The current Step is empirically chosen to provide minimal compression with the
    // advantage of the length of the encrypted message not being more than the unencrypted message.
    // For text or other files with a degree of repetition use a larger step (try powers of two) for
    // a much higher compression ration.

    public class ACoder2
    {
        // SIZE OF ARITHMETIC CODE VALUES.
        const int CodeValueBits = 32; // Number of bits in a code value
        const int CodeValueBitsScale = 14;
        const long ScaleValue = ((long)1 << CodeValueBitsScale);
        const long TopValue = ((long)1 << CodeValueBits) - 1;  // Largest code value

        // HALF AND QUARTER POINTS IN THE CODE VALUE RANGE. 
        const long Qtr = TopValue / 4 + 1;
        const long FirstQtr = Qtr;         // Point after first quarter 
        const long Half = 2 * Qtr;         // Point after first half
        const long ThirdQtr = 3 * Qtr;     // Point after third quarter

        // INTERFACE TO THE MODEL.
        // THE SET OF SYMBOLS THAT MAY BE ENCODED.
        const int NumberOfChars = 256; // Number of character symbols
        const int EofSymbol = NumberOfChars + 1; // Index of EOF symbol (1-indexed)
        const int NumberOfSymbols = NumberOfChars + 2; // Total number of symbols

        // CUMULATIVE FREQUENCY TABLE
        const long MaxFrequency = ((uint)1 << (CodeValueBits - 2)) - 1; // Maximum allowed frequency count 2^14 - 1
        YABIT CumeFreq;

        readonly byte[] encryptKey;
        long codingStep;
        readonly long[] initFreq;
        readonly int randomVLen;
        readonly uint randomSeed;
        readonly Dictionary<int,int> codingSymbols;

        class RandomLehmer
        {
            private uint _state;
            private readonly uint _seed;
            public RandomLehmer(uint seed)
            {
                _seed = seed;
                _state = seed;
            }

            public void Reset()
            {
                _state = _seed;
            }

            public uint Next()
            {
                _state = (uint)((ulong)_state * 279470273u % 0xfffffffb);
                return _state;
            }
        }

        readonly RandomLehmer prng;

        class FnvHash
        {
            private ulong _offset = 2166136261;
            private ulong _prime = 1099511628211;
            private ulong _mask = 0xFFFFFFFF;
            private ulong _hash;

            public FnvHash()
            {
                _hash = _offset;
            }

            public void Reset() { _hash = _offset; }

            public ulong Finalize() {  ulong result = _hash; _hash = _offset; return result; }

            public ulong Hash (ulong val) {
                unchecked
                {
                    _hash ^= val;
                    _hash *= _prime;
                    _hash &= _mask;
                }
                return _hash;
            }

            public ulong ComputeHash(byte[] bites)
            {
                Reset();
                for(int i=0; i<bites.Length; i++)
                {
                    Hash(bites[i]);
                }
                return Finalize();
            }
        }

        //private readonly int[] piDigits;

        class YABIT
        {
            // #define LSBIT(i) ((i) & -(i)) // Return the least-significant set bit in i
            // The following identities allow additional optimization,
            // but are omitted from this example code for clarity:
            // i - LSBIT(i)   == i & (i - 1)
            // i + LSBIT(i+1) == i | (i + 1)

            readonly int SIZE;
            readonly long[] A;
            int LSB_SIZE;

            static int LSBIT(int i) { return ((i) & (-i)); }

            public long PrefixSum(int i)
            {
                long sum = 0;
                if (!(0 <= i && i <= SIZE)) { throw new Exception($"YABIT: Range error; {i}"); }
                for (; i > 0; i &= (i - 1) /*i -= LSBIT(i)*/)
                    sum += A[i - 1];
                return sum;
            }

            public void Add(int i, long delta)
            {
                if (!(0 <= i && i <= SIZE)) { throw new Exception($"YABIT: Range error; {i}"); }
                for (; i < SIZE; i |= (i + 1) /*i += LSBIT(i + 1)*/)
                    A[i] += delta;
            }

            public long RangeSum(int i, int j)
            {
                long sum = 0;
                if (!(0 <= i && i <= SIZE)) { throw new Exception($"YABIT: Range error; {i}"); }
                for (; j > i; j &= (j - 1) /*j -= LSBIT(j)*/)
                    sum += A[j - 1];
                for (; i > j; i &= (i - 1) /*i -= LSBIT(i)*/)
                    sum -= A[i - 1];
                return sum;
            }

            private void Ini()
            {
                int lsb = SIZE;
                while (lsb != LSBIT(lsb))
                    lsb -= LSBIT(lsb);
                LSB_SIZE = lsb;

                for (int i = 0; i < SIZE; i++)
                {
                    int j = i + LSBIT(i + 1);
                    if (j < SIZE)
                        A[j] += A[i];
                }
            }

            public void Scale(int c)
            {
                long[] a = Fini();
                for (int i = 0; i < SIZE; i++)
                {
                    a[i] = (a[i] / c) | (0x01); // For AC coding, cannot be zero
                }
                Array.Copy(a, A, SIZE);
                Ini();
            }

            public YABIT(long[] arr)
            {
                SIZE = arr.Length;
                A = new long[SIZE];
                for (int i = 0; i < SIZE; i++) { A[i] = arr[i]; }
                Ini();
            }

            public long[] Fini()
            {
                long[] result = new long[SIZE];
                for (int i = SIZE; i-- > 0;)
                {
                    int j = i + LSBIT(i + 1);
                    if (j < SIZE)
                        A[j] -= A[i];
                }
                Array.Copy(A, result, SIZE);
                return result;
            }

            public long Get(int i)
            {
                return RangeSum(i, i + 1);
            }

            public void Set(int i, long value)
            {
                Add(i, value - Get(i));
            }

            int SetBitNumber(int n)
            {
                // To find the position of the most significant set bit
                int k = (int)(Math.Log(n) / Math.Log(2));
                // To return the the value of the number with set bit at k-th position
                return 1 << k;
            }

            public int RankQuery(long value)
            {
                int i = 0, j = SIZE;

                // The following could be precomputed, or use find first set
                //while (j != LSBIT(j))
                //    j -= LSBIT(j);
                j = LSB_SIZE;

                // j is now the highest power of 2 <= SIZE
                for (; j > 0; j >>= 1)
                {
                    if (i + j <= SIZE && A[i + j - 1] <= value)
                    {
                        value -= A[i + j - 1];
                        i += j;
                    }
                }
                return i;
            }

        }

        class BitInput
        {
            byte buffer;
            byte bitsToGo;
            int garbageBits;
            readonly byte[] inputBytes;
            int ndx;
            bool atEof;

            public BitInput(ACoder2 ctx, byte[] input)
            {
                bitsToGo = 0;
                garbageBits = 0;
                inputBytes = input;
                ndx = 0;
                atEof = false;
            }

            public bool AtEOF()
            {
                return atEof;
            }

            public int InputBit()
            {
                int bit;
                if (bitsToGo == 0)
                {
                    if (atEof || ndx >= inputBytes.Length)
                    {
                        atEof = true;
                        garbageBits += 1;
                        if (garbageBits > CodeValueBits - 2)
                        {
                            throw new Exception($"ACoder2: Bad input; {garbageBits} > {CodeValueBits-2}");
                        }
                    }
                    else
                    {
                        buffer = inputBytes[ndx];
                        ndx += 1;
                    }
                    bitsToGo = 8;
                }
                bit = buffer & 1;
                buffer >>= 1;
                bitsToGo -= 1;
                return bit;
            }
        }

        class BitOutput
        {
            //readonly List<byte> output;
            readonly MemoryStream outstrm;

            byte buffer;
            byte bitsToGo;
            long count;

            public long Count { get { return count; } }

            public BitOutput(int capacity)
            {
                //output = new(capacity);
                outstrm = new();
                buffer = 0;
                bitsToGo = 8;
                count = 0;
            }

            public void OutputBit(int bit)
            {
                buffer >>= 1;
                if (bit == 1)
                {
                    buffer |= 0x80;
                }
                bitsToGo -= 1;
                if (bitsToGo == 0)
                {
                    //output.Add(buffer);
                    outstrm.WriteByte(buffer);
                    count += 1;
                    bitsToGo = 8;
                }
            }

            public byte[] Done()
            {
                buffer >>= bitsToGo;
                //output.Add(buffer);
                //return output.ToArray();
                outstrm.WriteByte(buffer);
                count += 1;
                return outstrm.ToArray();
            }
        }

        class Model
        {
            readonly long[] initFreq;
            readonly ACoder2 coder;

            long[] magicFreq;

            int prevSymbol;
            YABIT[] yABITs;
            long[] ttlYABITs;

            public Model(ACoder2 ctx)
            {
                coder = ctx;
                initFreq = new long[NumberOfSymbols];
                Array.Fill(initFreq, 1);
                Array.Copy(ctx.initFreq, initFreq, NumberOfSymbols);

                magicFreq = new long[NumberOfSymbols];
                Array.Fill(magicFreq, 1);

                InitYABITS();
            }

            private void InitYABITS()
            {
                yABITs = new YABIT[NumberOfSymbols];
                ttlYABITs = new long[NumberOfSymbols];
                for (int i=0; i<NumberOfSymbols; i += 1)
                {
                    yABITs[i] = yABITs[i] = new YABIT(initFreq);
                    long prefixSum = yABITs[i].PrefixSum(NumberOfSymbols);
                    if (prefixSum > MaxFrequency)
                    {
                        throw new Exception($"ACoder2: Frequency (yabit) out of range error {prefixSum} > {MaxFrequency}");
                    }
                    ttlYABITs[i] = prefixSum;
                }
                prevSymbol = -1;

                coder.CumeFreq = new(initFreq);
            }

            public void SetSymbolMagic(int symbol, int prevSymbol = -1)
            {
                if (prevSymbol < 0)
                {
                    Array.Fill(magicFreq, 1);
                    magicFreq[symbol] = MaxFrequency - NumberOfSymbols;
                    coder.CumeFreq = new(magicFreq);
                }
                else
                {
                    coder.CumeFreq.Set(prevSymbol, 1);
                    coder.CumeFreq.Set(symbol, MaxFrequency - NumberOfSymbols);
                }
                long prefixSum = coder.CumeFreq.PrefixSum(NumberOfSymbols);
                if (prefixSum > MaxFrequency)
                {
                    throw new Exception($"ACoder2: Frequency (magic) out of range error {prefixSum} > {MaxFrequency}");
                }
            }

            public void ResetModelSymbols()
            {
                InitYABITS();
            }

            public void Update(int symbol)
            {
                void scaleYABIT(int yabit)
                {
                    YABIT yABIT = yABITs[yabit];
                    long ttlFreq = ttlYABITs[yabit];
                    if (ttlFreq > MaxFrequency)
                    {
                        //long prevTtlFreq = ttlFreq;
                        yABIT.Scale((int)ScaleValue);
                        ttlFreq = yABIT.PrefixSum(NumberOfSymbols);
                        ttlYABITs[yabit] = ttlFreq;
                        //Console.Error.WriteLine($"MaxFrequency of [{yabit}] exceeded...scaling; {prevTtlFreq} -> {ttlFreq}");
                    }

                    long freqStep = coder.codingStep;
                    yABIT.Add(symbol, freqStep);
                    ttlYABITs[yabit] += freqStep;
                }

                if (prevSymbol >= 0)
                {
                    scaleYABIT(prevSymbol);
                }
                else
                {
                    scaleYABIT(symbol);
                }

                if (coder.codingSymbols.TryGetValue(symbol, out int value))
                {
                    value++;
                    coder.codingSymbols[symbol] = value;
                }
                else
                {
                    coder.codingSymbols.Add(symbol, 1);
                }

                prevSymbol = symbol;
                coder.CumeFreq = yABITs[symbol];

            }

        }

        public ACoder2(byte[] key, uint pin = 0, int rv = 0, uint step = 0)
        {
            FnvHash hasher = new FnvHash();

            if (rv > 0)
            {
                randomVLen = rv;
                randomSeed = pin;
                if (randomVLen > 0 && randomSeed > 0)
                {
                    hasher.Reset();
                    byte[] bytes = BitConverter.GetBytes(randomSeed);
                    if (BitConverter.IsLittleEndian)
                        Array.Reverse(bytes);
                    ulong hashSeed = hasher.ComputeHash(bytes);
                    uint prngSeed = (uint)hashSeed;
                    prng = new RandomLehmer(prngSeed);
                }
            }


            if (key != null && key.Length > 0)
            {
                hasher.Reset();
                ulong encryptKeyHash = hasher.ComputeHash(key);
                encryptKey = BitConverter.GetBytes(encryptKeyHash);
                if (BitConverter.IsLittleEndian)
                    Array.Reverse(encryptKey);
                uint prngSeed = BitConverter.ToUInt32(encryptKey, 0);
                if (randomVLen > 0 && prng == null)
                {
                    prng = new RandomLehmer(prngSeed);
                }

            }

            initFreq = new long[NumberOfSymbols];
            for (int i = 0; i < NumberOfSymbols; i += 1)
            {
                if (i < NumberOfChars)
                {
                    initFreq[i] = NumberOfChars >> 1;
                }
                else
                {
                    initFreq[i] = 1;
                }
            }
            codingStep = step > 0 ? step : NumberOfChars;
            codingSymbols = [];
        }

        public byte[] Encode(string input)
        {
            return Encode(System.Text.Encoding.UTF8.GetBytes(input));
        }

        public byte[] Encode(byte[] input)
        {
            codingSymbols.Clear();

            Model model = new(this);
            long low, high;
            long bitsToFollow;
            BitOutput bitOutput;

            void StartEncoding()
            {
                low = 0;
                high = TopValue;
                bitsToFollow = 0;
            }

            void EncodeSymbol(int symbol)
            {
                long range;
                long ttlSym = CumeFreq.PrefixSum(NumberOfSymbols);
                long ttlSymHi = CumeFreq.PrefixSum(symbol + 1);
                long ttlSymLo = CumeFreq.PrefixSum(symbol);

                range = (high - low) + 1;
                high = low + (range * ttlSymHi) / ttlSym - 1;
                low = low + (range * ttlSymLo) / ttlSym;
                for (; ; )
                {
                    if (high < Half)
                    {
                        bitPlusFollow(0);
                    }
                    else if (low >= Half)
                    {
                        bitPlusFollow(1);
                        low -= Half;
                        high -= Half;
                    }
                    else if (low >= FirstQtr && high < ThirdQtr)
                    {
                        bitsToFollow += 1;
                        low -= FirstQtr;
                        high -= FirstQtr;
                    }
                    else
                    {
                        break;
                    }
                    low <<= 1; //2 * low;
                    high = (high << 1) + 1; // 2 * high + 1;
                }
            }

            void DoneEncoding()
            {
                bitsToFollow += 1;
                if (low < FirstQtr)
                {
                    bitPlusFollow(0);
                }
                else
                {
                    bitPlusFollow(1);
                }
            }

            void bitPlusFollow(int bit)
            {
                bitOutput.OutputBit(bit);
                while (bitsToFollow > 0)
                {
                    bitOutput.OutputBit(bit == 1 ? 0 : 1);
                    bitsToFollow -= 1;
                }
            }


            bitOutput = new(input.Length);
            StartEncoding();

            if (randomVLen > 0 && prng != null)
            {
                //Console.Error.WriteLine("Encoding IV...");
                prng.Reset();
                var rv = new byte[randomVLen];
                for (int i = 0; i < rv.Length; i += 1)
                {
                    rv[i] = (byte)(prng.Next() % 255);
                }
                int prevKeySymbol = -1;
                for (int i = 0; i < rv.Length; i += 1)
                {
                    var keySymbol = rv[i];
                    model.SetSymbolMagic(keySymbol, prevKeySymbol);
                    EncodeSymbol(keySymbol);
                    prevKeySymbol = keySymbol;
                }
                model.ResetModelSymbols();
            }

            if (encryptKey != null)
            {
                //Console.Error.WriteLine("Encoding Key...");
                var keyHash = encryptKey;
                int prevKeySymbol = -1;
                for (int i=0; i< keyHash.Length; i+=1)
                {
                    var keySymbol = keyHash[i];
                    model.SetSymbolMagic(keySymbol, prevKeySymbol);
                    EncodeSymbol(keySymbol);
                    prevKeySymbol = keySymbol;
                }
                model.ResetModelSymbols();
            }

            //Console.Error.WriteLine("Encoding Data...");
            for (int i = 0; i < input.Length; i += 1)
            {
                int symbol;
                symbol = input[i];
                EncodeSymbol(symbol);
                model.Update(symbol);
            }
            EncodeSymbol(EofSymbol);
            DoneEncoding();

            KeyValuePair<int, int>[] cs = codingSymbols.ToArray();
            Array.Sort(cs, (a, b) => { return b.Value - a.Value; });
            foreach (var item in cs)
            {
                Console.Error.Write($"[{item.Key},{item.Value}] ");
            }
            Console.Error.WriteLine($"[{codingSymbols.Count}]");

            return bitOutput.Done();
        }

        public byte[] Decode(byte[] input)
        {
            codingSymbols.Clear();

            Model model = new(this);
            long value;
            long low, high;
            BitInput bitInput;
            MemoryStream output = new MemoryStream(8192);

            void StartDecoding()
            {
                value = 0;
                for (int i = 0; i < CodeValueBits; i += 1)
                {
                    value = (value << 1) + bitInput.InputBit();
                }
                low = 0;
                high = TopValue;
            }

            int DecodeSymbol()
            {

                long ttlSym = CumeFreq.PrefixSum(NumberOfSymbols);
                long range = (high - low) + 1;
                long cum = (((value - low) + 1) * ttlSym - 1) / range;
                long ttlSymHi, ttlSymLo;
                int symbol;

                symbol = CumeFreq.RankQuery(cum);
                ttlSymHi = CumeFreq.PrefixSum(symbol + 1);
                ttlSymLo = CumeFreq.PrefixSum(symbol);

                high = low + (range * ttlSymHi) / ttlSym - 1;
                low = low + (range * ttlSymLo) / ttlSym;
                for (; ; )
                {
                    if (high < Half)
                    {
                        /* nothing */
                    }
                    else if (low >= Half)
                    {
                        value -= Half;
                        low -= Half;
                        high -= Half;
                    }
                    else if (low >= FirstQtr && high < ThirdQtr)
                    {
                        value -= FirstQtr;
                        low -= FirstQtr;
                        high -= FirstQtr;
                    }
                    else
                    {
                        break;
                    }
                    low <<= 1;
                    high = (high << 1) + 1;
                    value = (value << 1) + bitInput.InputBit();
                }
                return symbol;
            }

            bitInput = new(this, input);
            StartDecoding();

            try
            {
                if (randomVLen > 0 && prng != null)
                {
                    //Console.Error.WriteLine("Decoding IV...");
                    prng.Reset();
                    var rv = new byte[randomVLen];
                    for (int i = 0; i < rv.Length; i += 1)
                    {
                        rv[i] = (byte)(prng.Next() % 255);
                    }
                    int prevKeySymbol = -1;
                    for (int i = 0; i < rv.Length; i += 1)
                    {
                        int keySymbol = rv[i];
                        model.SetSymbolMagic(keySymbol, prevKeySymbol);
                        int symbol = DecodeSymbol();
                        if (symbol == EofSymbol)
                        {
                            return [];
                        }
                        if (symbol != keySymbol)
                        {
                            return [];
                        }
                        prevKeySymbol = keySymbol;
                    }
                    model.ResetModelSymbols();
                }

                if (encryptKey != null)
                {
                    //Console.Error.WriteLine("Decoding Key...");
                    var keyHash = encryptKey;
                    int prevKeySymbol = -1;
                    for (int i = 0; i < keyHash.Length; i += 1)
                    {
                        int keySymbol = keyHash[i];
                        model.SetSymbolMagic(keySymbol, prevKeySymbol);
                        int symbol = DecodeSymbol();
                        if (symbol == EofSymbol)
                        {
                            return [];
                        }
                        if (symbol != keySymbol)
                        {
                            return [];
                        }
                        prevKeySymbol = keySymbol;
                    }
                    model.ResetModelSymbols();
                }

                //Console.Error.WriteLine("Decoding Data...");
                for (; ; )
                {
                    int symbol = DecodeSymbol();
                    if (symbol == EofSymbol)
                    {
                        break;
                    }
                    output.WriteByte((byte) symbol);
                    model.Update(symbol);
                }
                //Console.Error.WriteLine("Decoding Done");

            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex.Message);
            }

            return output.ToArray();
        }

        public byte[] LZWEncode(byte[] input)
        {
            codingSymbols.Clear();

            Model model = new(this);
            long low, high;
            long bitsToFollow;
            BitOutput bitOutput;

            void StartEncoding()
            {
                low = 0;
                high = TopValue;
                bitsToFollow = 0;
            }

            void EncodeSymbol(int symbol)
            {
                long range;
                long ttlSym = CumeFreq.PrefixSum(NumberOfSymbols);
                long ttlSymHi = CumeFreq.PrefixSum(symbol + 1);
                long ttlSymLo = CumeFreq.PrefixSum(symbol);

                range = (high - low) + 1;
                high = low + (range * ttlSymHi) / ttlSym - 1;
                low = low + (range * ttlSymLo) / ttlSym;
                for (; ; )
                {
                    if (high < Half)
                    {
                        bitPlusFollow(0);
                    }
                    else if (low >= Half)
                    {
                        bitPlusFollow(1);
                        low -= Half;
                        high -= Half;
                    }
                    else if (low >= FirstQtr && high < ThirdQtr)
                    {
                        bitsToFollow += 1;
                        low -= FirstQtr;
                        high -= FirstQtr;
                    }
                    else
                    {
                        break;
                    }
                    low <<= 1; //2 * low;
                    high = (high << 1) + 1; // 2 * high + 1;
                }
            }

            void DoneEncoding()
            {
                bitsToFollow += 1;
                if (low < FirstQtr)
                {
                    bitPlusFollow(0);
                }
                else
                {
                    bitPlusFollow(1);
                }
            }

            void bitPlusFollow(int bit)
            {
                bitOutput.OutputBit(bit);
                while (bitsToFollow > 0)
                {
                    bitOutput.OutputBit(bit == 1 ? 0 : 1);
                    bitsToFollow -= 1;
                }
            }


            LZWCoder lzwCoder = new();
            List<int> lzwInput = lzwCoder.Encode(input);

            bitOutput = new(input.Length);
            StartEncoding();

            if (randomVLen > 0 && prng != null)
            {
                //Console.Error.WriteLine("Encoding IV...");
                prng.Reset();
                var rv = new byte[randomVLen];
                for (int i = 0; i < rv.Length; i += 1)
                {
                    rv[i] = (byte)(prng.Next() % 255);
                }
                int prevKeySymbol = -1;
                for (int i = 0; i < rv.Length; i += 1)
                {
                    var keySymbol = rv[i];
                    model.SetSymbolMagic(keySymbol, prevKeySymbol);
                    EncodeSymbol(keySymbol);
                    prevKeySymbol = keySymbol;
                }
                model.ResetModelSymbols();
            }

            if (encryptKey != null)
            {
                //Console.Error.WriteLine("Encoding Key...");
                var keyHash = encryptKey;
                int prevKeySymbol = -1;
                for (int i = 0; i < keyHash.Length; i += 1)
                {
                    var keySymbol = keyHash[i];
                    model.SetSymbolMagic(keySymbol, prevKeySymbol);
                    EncodeSymbol(keySymbol);
                    prevKeySymbol = keySymbol;
                }
                model.ResetModelSymbols();
            }

            //Console.Error.WriteLine("Encoding Data...");
            //for (int i = 0; i < lzwInput.Count; i += 1)
            //{
            //    int val = lzwInput[i];
            //    val = val & 0xFFFF;
            //    byte byteLo = (byte)(val & 0xFF);
            //    byte byteHi = (byte)(val >> 8);
            //    EncodeSymbol(byteLo);
            //    model.Update(byteLo);
            //    EncodeSymbol(byteHi);
            //    model.Update(byteHi);
            //}
            for (int i = 0; i < lzwInput.Count; i += 1)
            {
                int val = lzwInput[i];
                val = val & 0xFFFF;
                byte byteHi = (byte)(val >> 8);
                EncodeSymbol(byteHi);
                model.Update(byteHi);
            }
            for (int i = 0; i < lzwInput.Count; i += 1)
            {
                int val = lzwInput[i];
                val = val & 0xFFFF;
                byte byteLo = (byte)(val & 0xFF);
                EncodeSymbol(byteLo);
                model.Update(byteLo);
            }

            EncodeSymbol(EofSymbol);
            DoneEncoding();

            KeyValuePair<int, int>[] cs = codingSymbols.ToArray();
            Array.Sort(cs, (a, b) => { return b.Value - a.Value; });
            foreach (var item in cs)
            {
                Console.Error.Write($"[{item.Key},{item.Value}] ");
            }
            Console.Error.WriteLine($"[{codingSymbols.Count}]");

            return bitOutput.Done();
        }

        public byte[] LZWDecode(byte[] input)
        {
            codingSymbols.Clear();

            Model model = new(this);
            long value;
            long low, high;
            BitInput bitInput;
            MemoryStream output = new MemoryStream(8192);

            void StartDecoding()
            {
                value = 0;
                for (int i = 0; i < CodeValueBits; i += 1)
                {
                    value = (value << 1) + bitInput.InputBit();
                }
                low = 0;
                high = TopValue;
            }

            int DecodeSymbol()
            {

                long ttlSym = CumeFreq.PrefixSum(NumberOfSymbols);
                long range = (high - low) + 1;
                long cum = (((value - low) + 1) * ttlSym - 1) / range;
                long ttlSymHi, ttlSymLo;
                int symbol;

                symbol = CumeFreq.RankQuery(cum);
                ttlSymHi = CumeFreq.PrefixSum(symbol + 1);
                ttlSymLo = CumeFreq.PrefixSum(symbol);

                high = low + (range * ttlSymHi) / ttlSym - 1;
                low = low + (range * ttlSymLo) / ttlSym;
                for (; ; )
                {
                    if (high < Half)
                    {
                        /* nothing */
                    }
                    else if (low >= Half)
                    {
                        value -= Half;
                        low -= Half;
                        high -= Half;
                    }
                    else if (low >= FirstQtr && high < ThirdQtr)
                    {
                        value -= FirstQtr;
                        low -= FirstQtr;
                        high -= FirstQtr;
                    }
                    else
                    {
                        break;
                    }
                    low <<= 1;
                    high = (high << 1) + 1;
                    value = (value << 1) + bitInput.InputBit();
                }
                return symbol;
            }

            bitInput = new(this, input);
            StartDecoding();

            try
            {
                if (randomVLen > 0 && prng != null)
                {
                    //Console.Error.WriteLine("Decoding IV...");
                    prng.Reset();
                    var rv = new byte[randomVLen];
                    for (int i = 0; i < rv.Length; i += 1)
                    {
                        rv[i] = (byte)(prng.Next() % 255);
                    }
                    int prevKeySymbol = -1;
                    for (int i = 0; i < rv.Length; i += 1)
                    {
                        int keySymbol = rv[i];
                        model.SetSymbolMagic(keySymbol, prevKeySymbol);
                        int symbol = DecodeSymbol();
                        if (symbol == EofSymbol)
                        {
                            return [];
                        }
                        if (symbol != keySymbol)
                        {
                            return [];
                        }
                        prevKeySymbol = keySymbol;
                    }
                    model.ResetModelSymbols();
                }

                if (encryptKey != null)
                {
                    //Console.Error.WriteLine("Decoding Key...");
                    var keyHash = encryptKey;
                    int prevKeySymbol = -1;
                    for (int i = 0; i < keyHash.Length; i += 1)
                    {
                        int keySymbol = keyHash[i];
                        model.SetSymbolMagic(keySymbol, prevKeySymbol);
                        int symbol = DecodeSymbol();
                        if (symbol == EofSymbol)
                        {
                            return [];
                        }
                        if (symbol != keySymbol)
                        {
                            return [];
                        }
                        prevKeySymbol = keySymbol;
                    }
                    model.ResetModelSymbols();
                }

                //Console.Error.WriteLine("Decoding Data...");
                for (; ; )
                {
                    int symbol = DecodeSymbol();
                    if (symbol == EofSymbol)
                    {
                        break;
                    }
                    output.WriteByte((byte)symbol);
                    model.Update(symbol);
                }
                //Console.Error.WriteLine("Decoding Done");

                var acOutput = output.ToArray();
                List<int> lzwInput = [];
                //int ndx = 0;
                //while (ndx < acOutput.Length)
                //{
                //    byte byteLo = acOutput[ndx++];
                //    byte byteHi = acOutput[ndx++];
                //    int val = 0;
                //    val = (byteHi << 8) | byteLo;
                //    lzwInput.Add(val);
                //}
                int ndx = 0;
                int ndxHalf = acOutput.Length >> 1;
                while (ndx < ndxHalf)
                {
                    byte byteHi = acOutput[ndx];
                    int val = (byteHi << 8);
                    lzwInput.Add(val);
                    ndx++;
                }
                while (ndx < acOutput.Length)
                {
                    byte byteLo = acOutput[ndx];
                    int val = lzwInput[ndx - ndxHalf];
                    val |= byteLo;
                    lzwInput[ndx - ndxHalf] = val;
                    ndx++;
                }


                LZWCoder lzwCoder = new();
                var lzwOutput = lzwCoder.Decode(lzwInput).ToArray();
                
                return lzwOutput;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex);
                return [];
            }

        }

    }

}
    
