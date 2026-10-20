// /********************************************************
// *                                                       *
// *   Copyright (C) Microsoft. All rights reserved.       *
// *                                                       *
// ********************************************************/

using SyslogDecode.Model;
using System;
using System.Collections.Generic;
using System.Globalization;

namespace SyslogDecode.Parsing.VariantParsers
{
    /// <summary>Parses list of key-value pairs; like Sophos firewal format: 
    /// https://docs.sophos.com/nsg/sophos-firewall/v16058/Help/en-us/webhelp/onlinehelp/index.html#page/onlinehelp/WAFLogs.html
    /// </summary>
    internal class KeyValueListParser : ISyslogVariantParser
    {
        public bool TryParse(ParserContext ctx)
        {
            if (ctx.Current == SyslogChars.Space)
            {
                ctx.SkipSpaces();
            }

            // typically entries start with 'device=' or 'date='
            bool match = ctx.Match("device=") || ctx.Match("date=");
            if (!match)
            {
                match = TryMatchAnyKey(ctx);
            }
            if (!match)
            {
                return false;
            }

            // It is the format for this parser
            _ = ctx.Reset(); // Match(...) moved the position, so return to the start
            ctx.ParsedMessage.PayloadType = PayloadType.KeyValuePairs;
            List<NameValuePair> kvList = ReadKeyValuePairs(ctx);
            ctx.ParsedMessage.ExtractedTuples.AddRange(kvList);
            // try some known values and put them in the header
            SyslogHeader hdr = ctx.ParsedMessage.Header;
            hdr.HostName = kvList.GetValue("device_id");
            string? date = kvList.GetValue("date");
            string? time = kvList.GetValue("time");
            if (date != null)
            {
                // the sender's clock time, taken as the receiver's local time, as an RFC-3164 time without a zone is
                string dateTimeStr = $"{date}T{time}";
                if (DateTime.TryParse(dateTimeStr, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal | DateTimeStyles.AdjustToUniversal, out DateTime dt))
                {
                    hdr.Timestamp = dt;
                }
            }

            return true;
        } //method

        private static List<NameValuePair> ReadKeyValuePairs(ParserContext ctx)
        {
            List<NameValuePair> prmList = [];
            /*
2 troubles here: 
*/
            while (!ctx.Eof())
            {
                ctx.SkipSpaces();
                string name = ctx.ReadWord();
                if (!ctx.ReadSymbol('=', throwIfMismatch: false))
                {
                    // Some entries are malformed: double quoted strings  
                    // the result is that we do not find '=' after closing the quote. So we just add the rest to a separate param and exit
                    string text = ctx.Text[ctx.Position..];
                    prmList.Add(new NameValuePair() { Name = "Message", Value = text });
                    return prmList;
                }
                ctx.SkipSpaces();
                string value;
                if (ctx.Current == SyslogChars.DQuote)
                {
                    // For double-quoted values, some values are malformed - they contain nested d-quoted strings that are not escaped.
                    value = ctx.ReadQuotedString();
                }
                else
                {
                    // Special case: non quoted empty values, ex: ' a= b=234 '; value of 'a' is Empty. We check the char after we read the value, 
                    //      and if it is '=', we back off, set value to empty. 
                    int saveP = ctx.Position;
                    value = ctx.ReadWord();
                    if (ctx.Current == '=')
                    {
                        ctx.Position = saveP;
                        value = string.Empty;
                    }
                }
                NameValuePair lastPrm = new() { Name = name, Value = value };
                prmList.Add(lastPrm);
            }
            return prmList;
        }

        // let try to match any key, like <120> abc = def
        private static bool TryMatchAnyKey(ParserContext ctx)
        {
            if (!char.IsLetter(ctx.Current))
            {
                return false;
            }

            int savePos = ctx.Position;
            _ = ctx.ReadWord();
            ctx.SkipSpaces();
            bool result = ctx.Match("=");
            ctx.Position = savePos;
            return result;

        }


    }
}
