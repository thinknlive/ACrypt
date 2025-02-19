using System;
using System.ComponentModel.Design;
using System.Diagnostics;
using System.Text;
using CommandLine;


namespace ACrypt
{
    class Program
    {
        [Verb("encrypt")]
        public class EncryptOptions
        {
            [Option("file-in", Required = false)]
            public string FileIn { get; set; }

            [Option("data-in", Required = false)]
            public string Data { get; set; }

            [Option("key", Required = false)]
            public string AppKey { get; set; }

            [Option("pin", Required = false)]
            public uint AppIVPin { get; set; }

            [Option("iv", Required = false)]
            public uint AppIVLength { get; set; }


            [Option("file-out", Required = false)]
            public string FileOut { get; set; }

            [Option("hex", Required = false)]
            public bool Hex { get; set; }

            [Option("base64", Required = false)]
            public bool Base64 { get; set; }

            [Option("step", Required = false)]
            public uint CodingStep { get; set; }

        }

        [Verb("decrypt")]
        public class DecryptOptions
        {
            [Option("file-in", Required = false)]
            public string FileIn { get; set; }

            [Option("data-in", Required = false)]
            public string Data { get; set; }

            [Option("key", Required = false)]
            public string AppKey { get; set; }

            [Option("pin", Required = false)]
            public uint AppIVPin { get; set; }

            [Option("iv", Required = false)]
            public uint AppIVLength { get; set; }

            [Option("file-out", Required = false)]
            public string FileOut { get; set; }

            [Option("hex", Required = false)]
            public bool Hex { get; set; }

            [Option("base64", Required = false)]
            public bool Base64 { get; set; }

            [Option("astext", Required = false)]
            public bool IsText { get; set; }

            [Option("step", Required = false)]
            public uint CodingStep { get; set; }


        }

        static void Main(string[] args)
        {
            Console.Error.WriteLine("Cryptor");
            ConfigAppSettingsSecret(args);
        }

        private static void ConfigAppSettingsSecret(string[] args)
        {
            CommandLine.Parser.Default.ParseArguments<EncryptOptions, DecryptOptions>(args)
            .MapResult(
                (EncryptOptions options) => RunEncrypt(options),
                (DecryptOptions options) => RunDecrypt(options),
                errs => 1
            );

        }

        private static int RunEncrypt(EncryptOptions options)
        {
            string dataIn = options.Data;
            string fileIn = options.FileIn;
            string fileOut = options.FileOut;
            ACoder protector = new ACoder(
                options.AppKey != null ? Encoding.UTF8.GetBytes(options.AppKey) : [], 
                options.AppIVPin, 
                (int) options.AppIVLength,
                options.CodingStep);

            if (!string.IsNullOrEmpty(fileIn))
            {
                Console.Error.WriteLine($"START: Encrypt FileOut [{options.FileOut}], FileIn [{fileIn}]");

                try
                {
                    byte[] data = File.ReadAllBytes(fileIn);

                    {
                        // Testing out the LZW Coder
                        LZWCoder lzw = new();
                        Stopwatch lzwTimer = Stopwatch.StartNew();
                        List<int> encoded = lzw.Encode(data);
                        long msecsEnc = lzwTimer.ElapsedMilliseconds;

                        lzwTimer.Restart();
                        List<byte> decoded = lzw.Decode(encoded);
                        long msecsDec = lzwTimer.ElapsedMilliseconds;

                        var preHash = SHA256.Create().ComputeHash(data);
                        var postHash = SHA256.Create().ComputeHash([.. decoded]);
                        double lzwPct = Math.Round(((double)encoded.Count / data.Length) * 100.0, 3);

                        Console.Error.WriteLine(
                            $"LZW: ENCode [{data.Length}], [{msecsEnc}] msecs; " +
                            $" Encoded Length [{encoded.Count}]; " +
                            $"DECode [{decoded.Count}], [{msecsDec}] msecs; Pct [{lzwPct}]\n" +
                            $"[{Convert.ToHexString(preHash)}] ?= [{Convert.ToHexString(postHash)}]");
                        
                        lzwTimer.Restart();
                        byte[] acLzwEncoded = protector.LZWEncode(data);
                        msecsEnc = lzwTimer.ElapsedMilliseconds;

                        lzwTimer.Restart();
                        byte[] acLzwDecoded = protector.LZWDecode(acLzwEncoded);
                        msecsDec = lzwTimer.ElapsedMilliseconds;

                        preHash = SHA256.Create().ComputeHash(data);
                        postHash = SHA256.Create().ComputeHash(acLzwDecoded);
                        lzwPct = Math.Round(((double)acLzwEncoded.Length / data.Length) * 100.0, 3);
                        Console.Error.WriteLine(
                            $"ACLZW: ENCode [{data.Length}], [{msecsEnc}] msecs; " +
                            $" Encoded Length [{acLzwEncoded.Length}]; " +
                            $"DECode [{acLzwDecoded.Length}], [{msecsDec}] msecs; Pct [{lzwPct}]\n" +
                            $"[{Convert.ToHexString(preHash)}] ?= [{Convert.ToHexString(postHash)}]");
                    }
                    
                    Stopwatch sw = Stopwatch.StartNew();
                    byte[] secretBin = protector.Encode(data);
                    long elapsed = sw.ElapsedMilliseconds;

                    string secret = "";
                    if (options.Base64)
                    {
                        secret = Convert.ToBase64String(secretBin);
                    }
                    if (options.Hex)
                    {
                        secret = Convert.ToHexString(secretBin);
                    }

                    int lenOut = !string.IsNullOrEmpty(secret) ? secret.Length : secretBin.Length;
                    int lenIn = data.Length > 0 ? data.Length : 1;
                    double pct = Math.Round(((double)lenOut / data.Length) * 100.0, 3);
                    Console.Error.WriteLine($"-----: Elapsed [{elapsed}] msecs; Size In [{data.Length}], Out [{lenOut}]; Pct [{pct}]");

                    if (!string.IsNullOrEmpty(fileOut))
                    {
                        if (!string.IsNullOrEmpty(secret))
                        {
                            File.WriteAllText(fileOut, secret, Encoding.UTF8);
                        }
                        else
                        {
                            File.WriteAllBytes(fileOut, secretBin);
                        }
                    }
                    else
                    {
                        if (!string.IsNullOrEmpty(secret))
                        {
                            Console.WriteLine(secret);
                        }
                        else
                        {
                            Console.Write(secretBin);
                        }
                    }
                }
                catch (Exception e)
                {
                    Console.Error.WriteLine($"_____: ERROR encoding [{e.Message}]");
                }

                Console.Error.WriteLine($"FINIS: Encrypt FileOut [{options.FileOut}], FileIn [{fileIn}]");
            }
            else if (!string.IsNullOrEmpty(dataIn) && dataIn.Length > 0)
            {
                Console.Error.WriteLine($"START: Encrypt FileOut [{options.FileOut}], Data");

                try
                {
                    string data = dataIn;
                    byte[] secretBin = protector.Encode(data);
                    string secret = "";
                    if (options.Base64)
                    {
                        secret = Convert.ToBase64String(secretBin);
                    }
                    if (options.Hex)
                    {
                        secret = Convert.ToHexString(secretBin);
                    }

                    int lenOut = !string.IsNullOrEmpty(secret) ? secret.Length : secretBin.Length;
                    int lenIn = data.Length > 0 ? data.Length : 1;
                    double pct = Math.Round(((double)lenOut / data.Length) * 100.0, 3);
                    Console.Error.WriteLine($"-----: Size In [{data.Length}], Out [{lenOut}]; Pct [{pct}]");

                    if (!string.IsNullOrEmpty(fileOut))
                    {
                        if (!string.IsNullOrEmpty(secret))
                        {
                            File.WriteAllText(fileOut, secret, Encoding.UTF8);
                        }
                        else
                        {
                            File.WriteAllBytes(fileOut, secretBin);
                        }
                    }
                    else
                    {
                        if (!string.IsNullOrEmpty(secret))
                        {
                            Console.WriteLine(secret);
                        }
                        else
                        {
                            Console.Write(secretBin);
                        }
                    }
                }
                catch (Exception e)
                {
                    Console.Error.WriteLine($"_____: ERROR encoding [{e.Message}]");
                }

                Console.Error.WriteLine($"FINIS: Encrypt FileOut [{options.FileOut}], Data");
            }

            return 0;
        }

        private static int RunDecrypt(DecryptOptions options)
        {
            string dataIn = options.Data;
            string fileIn = options.FileIn;
            string fileOut = options.FileOut; // ?? options.FileIn;
            ACoder protector = new ACoder(
                !string.IsNullOrEmpty(options.AppKey) ? Encoding.UTF8.GetBytes(options.AppKey) : [], 
                options.AppIVPin, 
                (int)options.AppIVLength,
                options.CodingStep);

            if (!string.IsNullOrEmpty(fileIn))
            {
                Console.Error.WriteLine($"START: Decrypt FileOut [{options.FileOut}], FileIn [{fileIn}]");

                try
                {
                    byte[] data;
                    if (options.Base64)
                    {
                        data = Convert.FromBase64String(File.ReadAllText(fileIn, Encoding.UTF8));
                    }
                    if (options.Hex)
                    {
                        string hexStr = File.ReadAllText(fileIn, Encoding.UTF8);
                        data = Convert.FromHexString(hexStr);
                        //data = Enumerable.Range(0, hexStr.Length / 2).Select(x => Convert.ToByte(hexStr.Substring(x * 2, 2), 16)).ToArray();
                    }
                    else
                    {
                        data = File.ReadAllBytes(fileIn);
                    }

                    Stopwatch sw = Stopwatch.StartNew();
                    byte[] secretBin = protector.Decode(data);
                    long elapsed = sw.ElapsedMilliseconds;

                    string secret = "";
                    if (options.IsText) { secret = System.Text.Encoding.UTF8.GetString(secretBin); };

                    int lenOut = !string.IsNullOrEmpty(secret) ? secret.Length : secretBin.Length;
                    int lenIn = data.Length > 0 ? data.Length : 1;
                    double pct = Math.Round(((double)lenOut / data.Length) * 100.0, 3);
                    Console.Error.WriteLine($"-----: Elapsed [{elapsed}] msecs; Size In [{data.Length}], Out [{lenOut}]; Pct [{pct}]");

                    if (!string.IsNullOrEmpty(fileOut))
                    {
                        if (!string.IsNullOrEmpty(secret))
                        {
                            File.WriteAllText(fileOut, secret, Encoding.UTF8);
                        }
                        else
                        {
                            File.WriteAllBytes(fileOut, secretBin);
                        }
                    }
                    else
                    {
                        if (!string.IsNullOrEmpty(secret))
                        {
                            Console.WriteLine(secret);
                        }
                        else
                        {
                            Console.Write(secretBin);
                        }
                    }

                }
                catch (Exception e)
                {
                    Console.Error.WriteLine($"_____: ERROR decoding [{e.Message}]");
                }

                Console.Error.WriteLine($"FINIS: Decrypt FileIn [{options.FileOut}], FileIn [{fileIn}]");
            }
            else if (!string.IsNullOrEmpty(dataIn) && dataIn.Length > 0)
            {
                Console.Error.WriteLine($"START: Decrypt FileOut [{options.FileOut}], Data");

                try
                {
                    byte[] data;
                    if (options.Base64)
                    {
                        data = Convert.FromBase64String(dataIn);
                    }
                    else if (options.Hex)
                    {
                        data = Convert.FromHexString(dataIn);
                        //data = Enumerable.Range(0, dataIn.Length / 2).Select(x => Convert.ToByte(dataIn.Substring(x * 2, 2), 16)).ToArray();
                    }
                    else
                    {
                        data = [];
                    }

                    byte[] secretBin = protector.Decode(data);
                    string secret = "";
                    if (options.IsText) { secret = System.Text.Encoding.UTF8.GetString(secretBin); };

                    int lenOut = !string.IsNullOrEmpty(secret) ? secret.Length : secretBin.Length;
                    int lenIn = data.Length > 0 ? data.Length : 1;
                    double pct = Math.Round(((double)lenOut / data.Length) * 100.0, 3);
                    Console.Error.WriteLine($"-----: Size In [{data.Length}], Out [{lenOut}]; Pct [{pct}]");

                    if (!string.IsNullOrEmpty(fileOut))
                    {
                        if (!string.IsNullOrEmpty(secret))
                        {
                            File.WriteAllText(fileOut, secret, Encoding.UTF8);
                        }
                        else
                        {
                            File.WriteAllBytes(fileOut, secretBin);
                        }
                    }
                    else
                    {
                        if (!string.IsNullOrEmpty(secret))
                        {
                            Console.WriteLine(secret);
                        }
                        else
                        {
                            Console.Write(secretBin);
                        }
                    }
                }
                catch (Exception e)
                {
                    Console.Error.WriteLine($"_____: ERROR decoding [{e.Message}]");
                }

                Console.Error.WriteLine($"FINIS: Decrypt FileIn [{options.FileOut}], Data");
            }
            return 0;
        }

        //private static string CurrentDirectory
        //{
        //    get { return Directory.GetParent(typeof(Program).Assembly.Location).FullName; }
        //}

        //private static string ConfigFileFullPath
        //{
        //    get { return Path.Combine(CurrentDirectory, SECRET_CONFIG_FILE_NAME); }
        //}
    }
}
