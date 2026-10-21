// /********************************************************
// *                                                       *
// *   Copyright (C) Microsoft. All rights reserved.       *
// *                                                       *
// ********************************************************/

using System;

namespace SyslogDecode.Parsing.VariantParsers
{
    public class PlainTextParser : ISyslogVariantParser
    {
        public bool TryParse(ParserContext ctx)
        {
            ctx.SkipSpaces();
            ctx.ParsedMessage.PayloadType = Model.PayloadType.PlainText;
            ctx.ParsedMessage.Message = ctx.Text[ctx.Position..];
            // A text with no header of its own is dated when it was received, as ReadAsPlainText and ReadAsNotSyslog date theirs
            ctx.ParsedMessage.Header.Timestamp = ctx.ParsedMessage.Source?.ReceivedOn ?? DateTime.UtcNow;
            return true;
        }
    }
}
