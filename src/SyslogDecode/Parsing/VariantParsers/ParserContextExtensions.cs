// /********************************************************
// *                                                       *
// *   Copyright (C) Microsoft. All rights reserved.       *
// *                                                       *
// ********************************************************/

using SyslogDecode.Model;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;

namespace SyslogDecode.Parsing.VariantParsers
{
    public static class ParserContextExtensions
    {
        /// <summary>The highest priority RFC-5424 allows: facility local7 (23) times 8, plus severity debug (7). </summary>
        public const int MaxPriority = 191;

        public static bool ReadSymbol(this ParserContext ctx, char symbol, bool throwIfMismatch = true)
        {
            if (ctx.Current == SyslogChars.Space)
            {
                ctx.SkipSpaces();
            }
            if (ctx.Current == symbol)
            {
                ctx.Position++;
                return true;
            }
            return throwIfMismatch ? throw new Exception($"Invalid input, expected '{symbol}' ") : false;
        }

        public static bool TryReadUntil(this ParserContext ctx, string symbol, out string? text)
        {
            int spos = ctx.Text.IndexOf(symbol, ctx.Position);
            if (spos > 0)
            {
                text = ctx.Text[ctx.Position..spos];
                ctx.Position = spos;
                return true;
            }
            text = null;
            return false;
        }

        public static void SkipSpaces(this ParserContext ctx)
        {
            while (!ctx.Eof() && ctx.Current == SyslogChars.Space)
            {
                ctx.Position++;
            }
        }

        public static string? ReadWordOrNil(this ParserContext ctx)
        {
            string word = ctx.ReadWord();
            return word == SyslogChars.Nil ? null : word;
        }


        public static string ReadWord(this ParserContext ctx)
        {
            if (ctx.Current == SyslogChars.Space)
            {
                ctx.SkipSpaces();
            }

            int separatorPos = ctx.Text.IndexOfAny(SyslogChars.WordSeparators, ctx.Position);
            if (separatorPos < 0)
            {
                separatorPos = ctx.Text.Length;
            }

            string word = ctx.Text[ctx.Position..separatorPos];
            ctx.Position = separatorPos;
            return word;
        }

        public static string ReadQuotedString(this ParserContext ctx)
        {
            _ = ctx.ReadSymbol(SyslogChars.DQuote);
            string result = string.Empty;
            int curr = ctx.Position;
            while (true)
            {
                int next = ctx.Text.IndexOfAny(SyslogChars.QuoteOrEscape, curr);
                string segment = ctx.Text[curr..next];
                result += segment;
                switch (ctx.CharAt(next))
                {
                    case SyslogChars.DQuote:
                        // we are done
                        ctx.Position = next + 1; // after dquote
                        return result;

                    case SyslogChars.Escape:
                        // it is escape symbol, add next char to result, shift to next char and continue loop
                        result += ctx.CharAt(next + 1);
                        curr = next + 2;
                        break;
                }//switch
            } // loop
        }

        public static string? ReadDigits(this ParserContext ctx, int maxDigits = 10)
        {
            int start = ctx.Position;
            for (int i = 0; i < maxDigits; i++)
            {
                if (!char.IsDigit(ctx.Current))
                {
                    break;
                }

                ctx.Position++;
                if (ctx.Position >= ctx.Text.Length)
                {
                    break;
                }
            }
            if (ctx.Position == start)
            {
                return null;
            }

            string res = ctx.Text[start..ctx.Position];
            return res;
        }


        /// <summary>Parser standard (for all levels) prefix &lt;n&gt;. </summary>
        /// <param name="ctx">parser context.</param>
        /// <returns>True if prefix read correctly, with a priority from 0 to 191 as RFC-5424 allows; otherwise, false.</returns>
        public static bool ReadSyslogPrefix(this ParserContext ctx)
        {
            try
            {
                ctx.Position = 0;
                _ = ctx.ReadSymbol(SyslogChars.LT);
                string? digits = ctx.ReadDigits(3);
                _ = ctx.ReadSymbol(SyslogChars.GT);
                if (!int.TryParse(digits, NumberStyles.None, CultureInfo.InvariantCulture, out int pri) || pri > MaxPriority)
                {
                    ctx.Position = 0;
                    return false;
                }
                ctx.Prefix = ctx.Text[..ctx.Position];
                return true;
            }
            catch (Exception)
            {
                ctx.Position = 0;
                return false;
            }
        }

        public static void AssignFacilitySeverity(this ParserContext ctx)
        {

            string priStr = ctx.Prefix.Replace("<", string.Empty).Replace(">", string.Empty).Replace("?", string.Empty);
            if (!int.TryParse(priStr, out int pri))
            {
                ctx.AddError($"Invalid priority value '{priStr}', expected '<?>' where ? is int.");
                return;
            }

            // parse priority -> facility + severity
            int intFacility = pri / 8;
            int intSeverity = pri % 8;
            ctx.ParsedMessage.Facility = (Facility)intFacility;
            ctx.ParsedMessage.Severity = (Severity)intSeverity;
        }

        public static bool Reset(this ParserContext ctx)
        {
            if (ctx.Prefix == string.Empty && !ctx.ReadSyslogPrefix())
            {
                return false;
            }
            ctx.Position = ctx.Prefix.Length;
            return true;
        }

        public static bool Match(this ParserContext ctx, string token,
              StringComparison comparison = StringComparison.OrdinalIgnoreCase)
        {
            if (ctx.Position + token.Length > ctx.Text.Length)
            {
                return false;
            }

            string str = ctx.Text.Substring(ctx.Position, token.Length);
            if (str.Equals(token, comparison))
            {
                ctx.Position += token.Length;
                return true;
            }
            return false;
        }

        public static string? GetValue(this IList<NameValuePair> prms, string name)
        {
            return prms.FirstOrDefault(p => p.Name == name)?.Value;
        }

        public static string CutOffBOM(this string msg)
        {
            if (msg.StartsWith(SyslogChars.BOM, StringComparison.Ordinal))
            {
                msg = msg[SyslogChars.BOM.Length..];
            }

            return msg;
        }

    } //class
}
