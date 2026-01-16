// /********************************************************
// *                                                       *
// *   Copyright (C) Microsoft. All rights reserved.       *
// *                                                       *
// ********************************************************/

using SyslogDecode.Model;
using SyslogDecode.Parsing.VariantParsers;
using System.Collections.Generic;
using System.Linq;

namespace SyslogDecode.Parsing.Extractors
{
    public class IpAddressesExtractor : IValuesExtractor
    {
        private const char Dot = '.';
        private const char Colon = ':';

        public IList<NameValuePair> ExtractValues(ParserContext ctx)
        {
            ParsedSyslogMessage entry = ctx.ParsedMessage;
            List<NameValuePair> ipList = [];

            List<string> ipv4list = [.. FindIpv4Addresses(entry.Message)];
            if (ipv4list != null && ipv4list.Count > 0)
            {
                List<NameValuePair> prmList = [.. ipv4list.Select(ip => new NameValuePair() { Name = "IPv4", Value = ip })];
                ipList.AddRange(prmList);
            }

            List<string> ipv6list = [.. FindIpv6Addresses(entry.Message)];
            if (ipv6list != null && ipv6list.Count > 0)
            {
                List<NameValuePair> prmList = [.. ipv6list.Select(ip => new NameValuePair() { Name = "IPv6", Value = ip })];
                ipList.AddRange(prmList);
            }

            return ipList;
        }

        private static IEnumerable<string> FindIpv4Addresses(string? message)
        {
            if (message == null)
            {
                yield break; // no message means nothing to do
            }
            else
            {

                int start = 1;
                while (start < message.Length - 5)
                {
                    // try to find the first dot in IP like 127.0.0.1
                    int dotPos = message.IndexOf(Dot, start);
                    // found, and at least single char before, and a few chars after
                    if (dotPos <= 0 || dotPos >= message.Length - 5)
                    {
                        yield break; //we are done
                    }

                    start = message.SkipUntil(dotPos + 1, ch => !ch.IsIpV4Char()); //for the next iteration, skip beyond the whole address
                                                                                   // there should be digit before and after
                    if (!char.IsDigit(message[dotPos - 1]) || !char.IsDigit(message[dotPos + 1]))
                    {
                        continue; // proceed to next occurrence
                    }
                    // try getting IP; first go back and find first digit
                    int ipStart = dotPos;
                    while (ipStart > 0 && char.IsDigit(message[ipStart - 1]))
                    {
                        ipStart--;
                    }

                    int ipEnd = ipStart;
                    while (ipEnd < message.Length - 1 && message[ipEnd + 1].IsIpV4Char())
                    {
                        ipEnd++;
                    }

                    string ipStr = message.Substring(ipStart, ipEnd - ipStart + 1);
                    start = ipEnd + 1; //for next iteration
                                       // check it has 4 segments
                    if (IsIpv4Address(ipStr))
                    {
                        yield return ipStr;
                    }
                } //while 
            }
        }

        private static IEnumerable<string> FindIpv6Addresses(string? message)
        {
            if (message == null)
            {
                yield break; // no message means nothing to do
            }
            else
            {
                int start = 1;
                while (start < message.Length - 10)
                {
                    // try to find the first colon in IP
                    int colPos = message.IndexOf(Colon, start);
                    // found, and at least single char before, and a few chars after
                    if (colPos <= 0 || colPos >= message.Length - 5)
                    {
                        yield break; //we are done
                    }

                    start = message.SkipUntil(colPos + 1, ch => !ch.IsIpV6Char()); //for the next iteration
                                                                                   // there should be hex digit before and hex digit or colon after
                    if (!message[colPos - 1].IsHexDigit() || !message[colPos + 1].IsIpV6Char())
                    {
                        continue; // proceed to next occurrence
                    }
                    // try getting IP; first go back and find first digit
                    int ipStart = colPos;
                    while (ipStart > 0 && message[ipStart - 1].IsHexDigit())
                    {
                        ipStart--;
                    }

                    int ipEnd = ipStart;
                    while (ipEnd < message.Length - 1 && message[ipEnd + 1].IsIpV6Char())
                    {
                        ipEnd++;
                    }

                    string ipStr = message.Substring(ipStart, ipEnd - ipStart + 1);
                    start = ipEnd + 1; //for next iteration
                    if (IsIpv6Address(ipStr))
                    {
                        yield return ipStr;
                    }
                } //while
            }
        }

        /// <summary>Provides quick test for IPv4 address. </summary>
        /// <param name="value">String value to check.</param>
        /// <returns></returns>
        public static bool IsIpv4Address(string value)
        {
            // quick checks to get out quickly
            if (string.IsNullOrWhiteSpace(value) || value.Length < 7)
            {
                return false;
            }
            // first and last chars must be digits, and must contain dot
            if (!char.IsDigit(value[0]) || !char.IsDigit(value[^1]) || !value.Contains(Dot))
            {
                return false;
            }

            string[] segms = value.Split(Dot);
            if (segms.Length != 4)
            {
                return false;
            }
            // check that every segment is integer
            // last segment may include :port, so remove it
            int colPos = segms[3].IndexOf(':');
            if (colPos > 0)
            {
                segms[3] = segms[3][..colPos];
            }

            foreach (string segm in segms)
            {
                if (segm.Length > 3 || !int.TryParse(segm, out int _))
                {
                    return false;
                }
            }

            return true;
        }

        /// <summary>Provides quick test for IPv6 address. </summary>
        /// <param name="value">String value to check.</param>
        /// <returns></returns>
        public static bool IsIpv6Address(string value)
        {
            // quick checks to get out quickly
            if (string.IsNullOrWhiteSpace(value) || value.Length < 7 || !value.Contains(Colon))
            {
                return false;
            }
            // check it has 8 segments or contains :: - do not confuse it with time 15:20:46
            string[] segms = value.Split(':');
            if (segms.Length <= 4)
            {
                return false;
            }

            if ((segms.Length < 8 && !value.Contains("::")) || segms.Length > 9) //segm #9 might be port
            {
                return false;
            }

            foreach (string segm in segms)
            {
                if (string.IsNullOrEmpty(segm))
                {
                    continue; //case for :: - skipped 0 segments
                }

                if (segm.Length > 4)
                {
                    return false;
                }
                // check hex digits only
                if (segm.ToCharArray().Any(c => !c.IsHexDigit()))
                {
                    return false;
                }
            }
            return true;
        }

        public static IList<NameValuePair> ExtractIpAddresses(IEnumerable<NameValuePair> fromValuesOf)
        {
            // note - we are removing duplicates
            IEnumerable<NameValuePair> ipv4s = fromValuesOf
                                .Where(p => IsIpv4Address(p.Value))
                                .Select(p => p.Value)
                                .Distinct()
                                .Select(ip => new NameValuePair() { Name = "IPv4", Value = ip });
            IEnumerable<NameValuePair> ipv6s = [.. fromValuesOf
                          .Where(p => IsIpv6Address(p.Value))
                          .Select(p => p.Value)
                          .Distinct()
                          .Select(ip => new NameValuePair() { Name = "IPv6", Value = ip })];
            List<NameValuePair> all = [.. ipv4s];
            all.AddRange(ipv6s);
            return all;

        }
    }
}
