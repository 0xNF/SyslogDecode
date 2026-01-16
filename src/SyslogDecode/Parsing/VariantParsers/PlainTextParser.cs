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
            ctx.ParsedMessage.Header.Timestamp = DateTime.UtcNow;
            return true;
        }
    }
}
