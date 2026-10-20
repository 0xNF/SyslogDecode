// /********************************************************
// *                                                       *
// *   Copyright (C) Microsoft. All rights reserved.       *
// *                                                       *
// ********************************************************/

using SyslogDecode.Model;
using System;
using System.Collections.Generic;

namespace SyslogDecode.Parsing.VariantParsers
{
    public class Rfc5424SyslogParser : ISyslogVariantParser
    {
        public bool TryParse(ParserContext ctx)
        {
            if (!ctx.Reset())
            {
                return false;
            }

            if (!ctx.Match("1 "))
            {
                return false;
            }

            // It is RFC-5424 entry
            ParsedSyslogMessage entry = ctx.ParsedMessage;
            entry.PayloadType = PayloadType.Rfc5424;
            try
            {
                entry.Header = ParseHeader(ctx);
                ParseStructuredData(ctx);
                entry.Message = ParseMessage(ctx);
                return true;
            }
            catch (Exception ex)
            {
                ctx.AddError(ex.Message);
                return false;
            }
        }

        private static SyslogHeader ParseHeader(ParserContext ctx)
        {
            SyslogHeader header = ctx.ParsedMessage.Header = new SyslogHeader();
            header.Timestamp = ctx.ParseStandardTimestamp();
            header.HostName = ReadHeaderFieldOrNil(ctx);
            header.AppName = ReadHeaderFieldOrNil(ctx);
            header.ProcId = ReadHeaderFieldOrNil(ctx);
            header.MsgId = ReadHeaderFieldOrNil(ctx);
            return header;
        }

        /// <summary>Reads HOSTNAME, APP-NAME, PROCID or MSGID, which RFC-5424 makes printable ASCII up to the next SP, '=', '[' and ']' included. </summary>
        private static string? ReadHeaderFieldOrNil(ParserContext ctx)
        {
            ctx.SkipSpaces();
            int end = ctx.Text.IndexOf(SyslogChars.Space, ctx.Position);
            if (end < 0)
            {
                end = ctx.Text.Length;
            }
            string field = ctx.Text[ctx.Position..end];
            ctx.Position = end;
            return field == SyslogChars.Nil ? null : field;
        }

        private static void ParseStructuredData(ParserContext ctx)
        {
            ctx.SkipSpaces();

            if (ctx.Current == SyslogChars.NilChar)
            {
                ctx.Position++;
                return;
            }

            IDictionary<string, IList<NameValuePair>> data = ctx.ParsedMessage.StructuredData5424;
            try
            {
                if (ctx.Current != SyslogChars.Lbr)
                {
                    // do not report it as an error, some messages out there are a bit malformed
                    // ctx.AddError("Expected [ for structured data.");
                    return;
                }
                // start parsing elements
                while (!ctx.Eof())
                {
                    Tuple<string, List<NameValuePair>>? elem = ParseElement(ctx);
                    if (elem == null)
                    {
                        return;
                    }
                    data[elem.Item1] = elem.Item2;
                }

            }
            catch (Exception ex)
            {
                ctx.AddError(ex.Message);
            }
        }

        private static Tuple<string, List<NameValuePair>>? ParseElement(ParserContext ctx)
        {
            if (ctx.Current != SyslogChars.Lbr)
            {
                return null;
            }
            ctx.Position++;
            string elemName = ctx.ReadWord();
            ctx.SkipSpaces();
            List<NameValuePair> paramList = [];
            Tuple<string, List<NameValuePair>> elem = new(elemName, paramList);
            while (ctx.Current != SyslogChars.Rbr)
            {
                string paramName = ctx.ReadWord();
                _ = ctx.ReadSymbol('=');
                string paramValue = ctx.ReadQuotedString();
                NameValuePair prm = new() { Name = paramName, Value = paramValue };
                paramList.Add(prm);
                ctx.SkipSpaces();
            }

            _ = ctx.ReadSymbol(SyslogChars.Rbr);
            return elem;
        }

        private static string? ParseMessage(ParserContext ctx)
        {
            if (ctx.Eof())
            {
                return null;
            }
            // RFC 5424 separates MSG from STRUCTURED-DATA with one SP; any further spaces are the message's own
            if (ctx.Current == SyslogChars.Space)
            {
                ctx.Position++;
            }
            string msg = ctx.Text[ctx.Position..];
            // RFC 5424 allows BOM (byte order mark, 3 byte sequence) to precede the actual message. 
            // it will be read into the message OK, now 'msg' can contain this prefix - it is invisible
            // and will bring a lot of trouble when working with the string (ex: string comparisons are broken)
            // So we remove it explicitly.
            return msg.CutOffBOM();
        }

    } //class

}
