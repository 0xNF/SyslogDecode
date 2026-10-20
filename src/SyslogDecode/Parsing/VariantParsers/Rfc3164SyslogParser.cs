// /********************************************************
// *                                                       *
// *   Copyright (C) Microsoft. All rights reserved.       *
// *                                                       *
// ********************************************************/

namespace SyslogDecode.Parsing.VariantParsers
{
    /// <summary>Parses old-style, BSD syslog, RFC-3164. See https://tools.ietf.org/html/rfc3164 </summary>
    public class Rfc3164SyslogParser : ISyslogVariantParser
    {

        public bool TryParse(ParserContext ctx)
        {
            if (!TimestampParseHelper.TryParseTimestamp(ctx))
            {
                return false;
            }

            Model.ParsedSyslogMessage entry = ctx.ParsedMessage;
            entry.PayloadType = Model.PayloadType.Rfc3164;
            //Next - host name and proc name
            entry.Header.HostName = ctx.ReadWord();
            ctx.SkipSpaces();
            int procStart = ctx.Position;
            int procEnd = ctx.Text.SkipUntil(procStart + 1, ' ', ':', ',');
            if (procEnd < ctx.Text.Length)
            {
                // RFC-5424 appendix A.1 maps the TAG to APP-NAME, and a "[pid]" after it to PROCID
                string tag = ctx.Text.Substring(procStart, procEnd - procStart);
                int bracket = tag.IndexOf('[');
                if (bracket > 0 && tag.EndsWith(']'))
                {
                    entry.Header.AppName = tag[..bracket];
                    entry.Header.ProcId = tag[(bracket + 1)..^1];
                }
                else
                {
                    entry.Header.AppName = tag;
                }
                ctx.Position = procEnd + 1;
            }
            if (ctx.Position < ctx.Text.Length)
            {
                // the rest is message            
                ctx.SkipSpaces();
                entry.Message = ctx.Text.Substring(ctx.Position);
            }
            return true;
        }

    }
}
