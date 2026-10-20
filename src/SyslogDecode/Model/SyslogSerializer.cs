// /********************************************************
// *                                                       *
// *   Copyright (C) Microsoft. All rights reserved.       *
// *                                                       *
// ********************************************************/

using SyslogDecode.Parsing.VariantParsers;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace SyslogDecode.Model
{
    /// <summary>
    /// Serializes SyslogEntry instances into a string for transmission over a network.
    /// </summary>
    public static class SyslogSerializer
    {
        private const char Space = ' ';
        private const char NilChar = '-';
        private const char Lbr = '[';
        private const char Rbr = ']';
        private const char Escape = '\\';
        private const char DQuote = '"';

        private static readonly char[] _charsToEscape = [DQuote, Escape, Rbr]; //according to RFC-5424 these must be escaped

        public const string TimestampFormat = "yyyy'-'MM'-'ddTHH:mm:ss.fffZ";

        public static string Serialize(ParsedSyslogMessage entry)
        {
            StringBuilder writer = new();
            writer.WriteHeader(entry);
            writer.WriteStructuredData(entry.StructuredData5424);
            if (!string.IsNullOrEmpty(entry.Message))
            {
                _ = writer.Append(SyslogChars.Space);
                _ = writer.Append(entry.Message);
            }
            return writer.ToString();
        }

        private static void WriteHeader(this StringBuilder writer, ParsedSyslogMessage entry)
        {
            _ = writer.Append('<');
            int pri = GetPriority(entry);
            _ = writer.Append(pri);
            _ = writer.Append('>');
            _ = writer.Append('1');
            _ = writer.Append(Space);
            SyslogHeader header = entry.Header;
            string tsStr = header.Timestamp == null ? string.Empty : header.Timestamp.Value.ToUniversalTime().ToString(TimestampFormat, CultureInfo.InvariantCulture);
            writer.AppendWordOrNil(tsStr);
            writer.AppendWordOrNil(header.HostName);
            writer.AppendWordOrNil(header.AppName);
            writer.AppendWordOrNil(header.ProcId);
            writer.AppendWordOrNil(header.MsgId);
        }

        private static void AppendWordOrNil(this StringBuilder writer, string? word)
        {
            _ = string.IsNullOrWhiteSpace(word) ? writer.Append(NilChar) : writer.Append(word);
            _ = writer.Append(Space);
        }

        private static int GetPriority(this ParsedSyslogMessage entry)
        {
            return (((int)entry.Facility) * 8) + (int)entry.Severity;
        }

        private static void WriteStructuredData(this StringBuilder writer, IDictionary<string, IList<NameValuePair>> structuredData)
        {
            if (structuredData == null || structuredData.Count == 0)
            {
                _ = writer.Append(NilChar);
                _ = writer.Append(Space);
                return;
            }

            foreach (KeyValuePair<string, IList<NameValuePair>> de in structuredData)
            {
                string elemName = de.Key;
                IList<NameValuePair> paramList = de.Value;
                _ = writer.Append(Lbr);
                _ = writer.Append(elemName);
                foreach (NameValuePair prm in paramList)
                {
                    _ = writer.Append(Space);
                    _ = writer.Append(prm.Name);
                    _ = writer.Append('=');
                    string prmValue = EscapeParamValue(prm.Value);
                    _ = writer.Append(DQuote);
                    _ = writer.Append(prmValue);
                    _ = writer.Append(DQuote);
                }
                _ = writer.Append(Rbr);
            }
        }

        private static string EscapeParamValue(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return string.Empty;
            }

            if (value.IndexOfAny(_charsToEscape) < 0)
            {
                return value;
            }
            // replace with escaped
            string escaped = value.Replace(@"\", @"\\").Replace(@"""", @"\""").Replace(@"]", @"\]");
            return escaped;
        }
    }
}
