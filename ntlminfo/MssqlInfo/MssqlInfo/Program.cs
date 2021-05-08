﻿using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace MssqlInfo
{
    class Program
    {
        static void Main(string[] args)
        {
            byte[] MSSQL_Client_Receive = new byte[2048];
            string host = args[0];
            int port = int.Parse(args[1]);

            try
            {
                var MSSQL_Client = new TcpClient();
                IAsyncResult result = MSSQL_Client.BeginConnect(host, port, null, null);
                bool success = result.AsyncWaitHandle.WaitOne(5000, true);
                if (!MSSQL_Client.Connected)
                {
                    Console.WriteLine($@"target {host} WmiInfo can't connect!");
                    return;
                }
                NetworkStream MSSQL_Client_Stream = MSSQL_Client.GetStream();
                MSSQL_Client.ReceiveTimeout = 30000;
                byte[] prelogin = {
                    0x12,0x01,0x00,0x58,0x00,0x00,0x01,0x00,0x00,0x00,0x1f,0x00,0x06,0x01,0x00,0x25,
                    0x00,0x01,0x02,0x00,0x26,0x00,0x01,0x03,0x00,0x27,0x00,0x04,0x04,0x00,0x2b,0x00,
                    0x01,0x05,0x00,0x2c,0x00,0x24,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x00,
                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
                };

                byte[] SSPI_Message =
                {
                    0x10,0x01,0x01,0xb3,0x00,0x00,0x01,0x00,0xab,0x01,0x00,0x00,0x04,0x00,0x00,0x74,
                    0x40,0x1f,0x00,0x00,0x00,0x00,0x00,0x06,0x2a,0x2a,0x2a,0x2a,0x00,0x00,0x00,0x00,
                    0xe0,0x83,0x00,0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x5e,0x00,0x09,0x00,
                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x21,0x00,0xb2,0x00,0x0e,0x00,
                    0xce,0x00,0x04,0x00,0xd2,0x00,0x21,0x00,0x14,0x01,0x00,0x00,0x14,0x01,0x07,0x00,
                    0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x22,0x01,0x7e,0x00,0xa0,0x01,0x00,0x00,0xa0,0x01,
                    0x00,0x00,0x00,0x00,0x00,0x00,0x41,0x00,0x4e,0x00,0x4f,0x00,0x4e,0x00,0x59,0x00,
                    0x4d,0x00,0x4f,0x00,0x55,0x00,0x53,0x00,0x43,0x00,0x6f,0x00,0x72,0x00,0x65,0x00,
                    0x20,0x00,0x2e,0x00,0x4e,0x00,0x65,0x00,0x74,0x00,0x20,0x00,0x53,0x00,0x71,0x00,
                    0x6c,0x00,0x43,0x00,0x6c,0x00,0x69,0x00,0x65,0x00,0x6e,0x00,0x74,0x00,0x20,0x00,
                    0x44,0x00,0x61,0x00,0x74,0x00,0x61,0x00,0x20,0x00,0x50,0x00,0x72,0x00,0x6f,0x00,
                    0x76,0x00,0x69,0x00,0x64,0x00,0x65,0x00,0x72,0x00,0x31,0x00,0x30,0x00,0x2e,0x00,
                    0x32,0x00,0x30,0x00,0x30,0x00,0x2e,0x00,0x32,0x00,0x31,0x00,0x35,0x00,0x2e,0x00,
                    0x31,0x00,0x30,0x00,0x38,0x00,0xa0,0x01,0x00,0x00,0x43,0x00,0x6f,0x00,0x72,0x00,
                    0x65,0x00,0x20,0x00,0x2e,0x00,0x4e,0x00,0x65,0x00,0x74,0x00,0x20,0x00,0x53,0x00,
                    0x71,0x00,0x6c,0x00,0x43,0x00,0x6c,0x00,0x69,0x00,0x65,0x00,0x6e,0x00,0x74,0x00,
                    0x20,0x00,0x44,0x00,0x61,0x00,0x74,0x00,0x61,0x00,0x20,0x00,0x50,0x00,0x72,0x00,
                    0x6f,0x00,0x76,0x00,0x69,0x00,0x64,0x00,0x65,0x00,0x72,0x00,0x54,0x00,0x64,0x00,
                    0x73,0x00,0x54,0x00,0x65,0x00,0x73,0x00,0x74,0x00,0x60,0x7c,0x06,0x06,0x2b,0x06,
                    0x01,0x05,0x05,0x02,0xa0,0x72,0x30,0x70,0xa0,0x30,0x30,0x2e,0x06,0x0a,0x2b,0x06,
                    0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a,0x06,0x09,0x2a,0x86,0x48,0x82,0xf7,0x12,
                    0x01,0x02,0x02,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x12,0x01,0x02,0x02,0x06,0x0a,
                    0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x1e,0xa2,0x3c,0x04,0x3a,0x4e,0x54,
                    0x4c,0x4d,0x53,0x53,0x50,0x00,0x01,0x00,0x00,0x00,0xb7,0xb2,0x08,0xe2,0x09,0x00,
                    0x09,0x00,0x31,0x00,0x00,0x00,0x09,0x00,0x09,0x00,0x28,0x00,0x00,0x00,0x0a,0x00,
                    0x61,0x4a,0x00,0x00,0x00,0x0f,0x41,0x4e,0x4f,0x4e,0x59,0x4d,0x4f,0x55,0x53,0x57,
                    0x4f,0x52,0x4b,0x47,0x52,0x4f,0x55,0x50,0x01,0x00,0x00,0x00,0x00,0x05,0x00,0x00,
                    0x00,0x00,0xff
                };

                SendStream(MSSQL_Client_Stream, prelogin);
                MSSQL_Client_Receive = SendStream(MSSQL_Client_Stream, SSPI_Message);
                NTLMInfo NTLMInfo = new NTLMInfo();
                NTLMInfo = GetNTLMInfo(MSSQL_Client_Receive, NTLMInfo);
                Console.WriteLine($@"target {host} MSSQL Info: Windows Version {NTLMInfo.OsVersion} Build {NTLMInfo.OsBuildNumber}, Domain Name {NTLMInfo.NbtDoaminName}, Computer Name {NTLMInfo.NbtComputer}, Dns Suffix {NTLMInfo.DnsDomainName}, Dns Computer Name {NTLMInfo.DnsDomainName}, TimeStamp {NTLMInfo.TimeStamp}");
                MSSQL_Client.Close();
                MSSQL_Client_Stream.Close();

            }
            catch (Exception ex)
            {
                Console.WriteLine($@"target {host} MSSQL Info Error:{ex.Message}");
            }
        }

        public static byte[] SendStream(NetworkStream stream, byte[] BytesToSend)
        {
            byte[] BytesReceived = new byte[2048];
            stream.Write(BytesToSend, 0, BytesToSend.Length);
            stream.Flush();
            stream.Read(BytesReceived, 0, BytesReceived.Length);
            return BytesReceived;
        }

        public class NTLMInfo
        {
            public string NativeOs { get; set; }
            public string NativeLanManager { get; set; }
            public string NbtDoaminName { get; set; }
            public string NbtComputer { get; set; }
            public string DomainName { get; set; }
            public short OsBuildNumber { get; set; }

            public string OsVersion { get; set; }
            public string DnsComputerName { get; set; }
            public string DnsDomainName { get; set; }
            public string DNSTreeName { get; set; }
            public DateTime TimeStamp { get; set; }
            public bool SMBsigning { get; set; }
        }

        public static NTLMInfo GetNTLMInfo(byte[] buf, NTLMInfo ntlminfo)
        {
            string NTLMSSP_Negotiate = BitConverter.ToString(buf).Replace("-", "");
            int off;
            off = NTLMSSP_Negotiate.IndexOf("4E544C4D53535000") / 2;
            int NTLMSSP_Negotiate_Len = (NTLMSSP_Negotiate.Length - NTLMSSP_Negotiate.IndexOf("4E544C4D53535000")) / 2;
            byte[] ntlm = new byte[NTLMSSP_Negotiate_Len];
            Array.Copy(buf, off, ntlm, 0, NTLMSSP_Negotiate_Len);

            NTLMSSP_Negotiate_Len = BitConverter.ToInt16(ntlm, 0xc);
            off = BitConverter.ToInt16(ntlm, 0x10);
            ntlminfo.OsBuildNumber = BitConverter.ToInt16(ntlm, off - 6);
            ntlminfo.OsVersion = $@"{ntlm[off - 8]}.{ntlm[off - 7]}";

            off += NTLMSSP_Negotiate_Len;
            int type = BitConverter.ToInt16(ntlm, off);

            while (type != 0)
            {
                off += 2;
                NTLMSSP_Negotiate_Len = BitConverter.ToInt16(ntlm, off);
                off += 2;
                switch (type)
                {
                    case 1:
                        {
                            ntlminfo.NbtComputer = Encoding.Unicode.GetString(ntlm, off, NTLMSSP_Negotiate_Len);
                            //Console.WriteLine("NetBIOS computer name: " + Encoding.Unicode.GetString(ntlm, off, len));
                            break;
                        }
                    case 2:
                        {
                            ntlminfo.NbtDoaminName = Encoding.Unicode.GetString(ntlm, off, NTLMSSP_Negotiate_Len);
                            //Console.WriteLine("NetBIOS domain name: " + Encoding.Unicode.GetString(ntlm, off, len));
                            break;
                        }
                    case 3:
                        {
                            ntlminfo.DnsComputerName = Encoding.Unicode.GetString(ntlm, off, NTLMSSP_Negotiate_Len);
                            //Console.WriteLine("DNS computer name: " + Encoding.Unicode.GetString(ntlm, off, len));
                            break;
                        }
                    case 4:
                        {
                            ntlminfo.DnsDomainName = Encoding.Unicode.GetString(ntlm, off, NTLMSSP_Negotiate_Len);
                            //Console.WriteLine("DNS domain name: " + Encoding.Unicode.GetString(ntlm, off, len));
                            break;
                        }
                    case 5:
                        {
                            ntlminfo.DNSTreeName = Encoding.Unicode.GetString(ntlm, off, NTLMSSP_Negotiate_Len);
                            //Console.WriteLine("DNS tree name: " + Encoding.Unicode.GetString(ntlm, off, len));
                            break;
                        }
                    case 7:
                        {
                            ntlminfo.TimeStamp = DateTime.FromFileTime(BitConverter.ToInt64(ntlm, off));
                            //Console.WriteLine("time stamp: {0:o}", DateTime.FromFileTime(BitConverter.ToInt64(ntlm, off)));
                            break;
                        }
                    default:
                        {
                            //Console.Write("Unknown type {0}, data: ", type);
                            for (int i = 0; i < NTLMSSP_Negotiate_Len; i++)
                            {
                                Console.Write(ntlm[i + off].ToString("X2"));
                            }
                            Console.WriteLine();
                            break;
                        }
                }
                off += NTLMSSP_Negotiate_Len;
                type = BitConverter.ToInt16(ntlm, off);
            }

            return ntlminfo;
        }
    }

}
