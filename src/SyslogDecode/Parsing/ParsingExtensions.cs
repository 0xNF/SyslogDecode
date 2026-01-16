// /********************************************************
// *                                                       *
// *   Copyright (C) Microsoft. All rights reserved.       *
// *                                                       *
// ********************************************************/

using SyslogDecode.Model;
using SyslogDecode.Parsing.VariantParsers;
using System;
using System.Collections.Generic;
using System.Linq;

namespace SyslogDecode.Parsing
{
    public static class ParsingExtensions
    {
        public static bool IsIpV4Char(this char ch)
        {
            return ch == SyslogChars.Dot || char.IsDigit(ch);
        }

        public static bool IsHexDigit(this char ch)
        {
            return char.IsDigit(ch) || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F');
        }

        public static bool IsIpV6Char(this char ch)
        {
            return ch == SyslogChars.Colon || IsHexDigit(ch);
        }

        public static int SkipUntil(this string message, int start, Func<char, bool> func)
        {
            int p = start;
            while (p < message.Length && !func(message[p]))
            {
                p++;
            }

            return p;
        }

        public static int Skip(this string message, int start, params char[] chars)
        {
            int p = start;
            while (p < message.Length && chars.Contains(message[p]))
            {
                p++;
            }

            return p;
        }
        public static int SkipUntil(this string message, int start, params char[] chars)
        {
            int p = start;
            while (p < message.Length && !chars.Contains(message[p]))
            {
                p++;
            }

            return p;
        }

        public static void AddRange(this IList<NameValuePair> dataList, IList<NameValuePair> nv)
        {
            foreach (NameValuePair prm in nv)
            {
                dataList.Add(prm);
            }
        }

        public static void Add(this IList<NameValuePair> dataList, string name, string value)
        {
            dataList.Add(new NameValuePair() { Name = name, Value = value });
        }
    }
}
