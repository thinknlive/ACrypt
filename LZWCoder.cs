namespace ACrypt
{

    public class LZWCoder
    {
        const int MAXIMUM_DICT_CODES = 2 << 14;
        readonly int EOB = 0;

        readonly Dictionary<string, int> encodeDict;
        readonly Dictionary<int, byte[]> decodeDict;

        public LZWCoder()
        {
            encodeDict = [];
            decodeDict = [];
        }

        private string b2s(byte[] bytes)
        {
            return Convert.ToHexString(bytes);
        }
        private byte[] s2b(string s)
        {
            return Convert.FromHexString(s);
        }

        public List<int> Encode(byte[] uncompressed)
        {
            ResetEncodeDict();
            List<int> result = [];
            void WriteKey(List<byte> key)
            {
                if (key.Count == 0) { return; }
                int code;
                if (key.Count == 1)
                {
                    code = key[0] + 1; // Optimization; skip dictionary lookup for single chars
                }
                else
                {
                    code = encodeDict[b2s([.. key])];
                }
                result.Add(code);
            }

            void WriteCode(int code)
            {
                result.Add(code);
            }

            byte c;
            int nextCode = -1;

            List<byte> wc = [];
            int cNdx = 0, len = uncompressed.Length;
            while (cNdx < len)
            {
                if (encodeDict.Count >= MAXIMUM_DICT_CODES)
                {
                    WriteKey(wc);
                    WriteCode(EOB);
                    ResetEncodeDict();
                }

                c = uncompressed[cNdx++];
                {
                    List<byte> word = [.. wc]; word.Add(c);
                    if (encodeDict.TryGetValue(b2s([.. word]), out int wcCode))
                    {
                        //w = wc;
                        nextCode = wcCode;
                        wc = word;
                        continue;
                    }
                }

                // Write w
                if (nextCode >= 0)
                {
                    WriteCode(nextCode);
                    nextCode = -1;
                }
                else
                {
                    WriteKey(wc);
                }

                // Add w+c
                wc.Add(c);
                if (encodeDict.Count < MAXIMUM_DICT_CODES)
                {
                    encodeDict[b2s([.. wc])] = encodeDict.Count;
                }

                //w = c;
                wc = [c];
            }

            if (wc.Count > 0)
            {
                WriteKey(wc);
            }

            return result;
        }

        public List<byte> Decode(List<int> input)
        {
            ResetDecodeDict();
            List<byte> result = [];

            void WriteBytes(List<byte> bites)
            {
                for (int i = 0; i < bites.Count; i++) { result.Add(bites[i]); }
            }

            // First
            int cNdx = 0, len = input.Count;
            int value = input[cNdx++];
            List<byte> w = [.. decodeDict[value]];
            WriteBytes(w);

            while (cNdx < len)
            {
                int k = input[cNdx++];
                if (k == EOB)
                {
                    ResetDecodeDict();
                    if (cNdx < len)
                    {
                        value = input[cNdx++];
                        w = [.. decodeDict[value]];
                        continue;
                    }
                }

                List<byte> entry;
                if (decodeDict.ContainsKey(k))
                {
                    entry = [.. decodeDict[k]];
                }
                else if (k == decodeDict.Count)
                {
                    //entry = w + w[0];
                    entry = [.. w];
                    entry.Add(w[0]);
                }
                else
                {
                    throw new Exception($"LZWCoder: Bad compressed [{k}]");
                }

                WriteBytes(entry);

                // new sequence; add it to the dictionary
                if (decodeDict.Count < MAXIMUM_DICT_CODES)
                {
                    // Add w + entry[0];
                    List<byte> wc = [.. w];
                    wc.Add(entry[0]);
                    decodeDict.Add(decodeDict.Count, [.. wc]);
                }

                w = entry;
            }

            return result;
        }

        private void ResetEncodeDict()
        {
            encodeDict.Clear();
            byte[] c;
            encodeDict[""] = 0;
            for (int i = 0; i < 256; i++)
            {
                c = [(byte)i];
                encodeDict[b2s(c)] = i + 1;
            }
        }

        private void ResetDecodeDict()
        {
            decodeDict.Clear();
            byte[] c;
            decodeDict[0] = Array.Empty<byte>();
            for (int i = 0; i < 256; i++)
            {
                c = [(byte)i];
                decodeDict[i + 1] = c;
            }
        }


    }


}
