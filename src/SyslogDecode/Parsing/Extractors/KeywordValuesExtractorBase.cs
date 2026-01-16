// /********************************************************
// *                                                       *
// *   Copyright (C) Microsoft. All rights reserved.       *
// *                                                       *
// ********************************************************/

using SyslogDecode.Model;
using SyslogDecode.Parsing.VariantParsers;
using System;
using System.Collections.Generic;

namespace SyslogDecode.Parsing.Extractors
{
    /// <summary>Extracts selected keywords and following values from a text message.</summary>
    public abstract class KeywordValuesExtractorBase : IValuesExtractor
    {
        public abstract IList<NameValuePair> ExtractValues(ParserContext ctx);

        protected static bool TryExtractAndAdd(string message, string keyword, IList<NameValuePair> prms, bool grabAll = false)
        {
            try
            {
                if (TryExtractValue(message, keyword, out string? value, grabAll))
                {
                    prms.Add(new NameValuePair() { Name = keyword, Value = value! });
                    return true;
                }
            }
            catch (Exception ex)
            {
                string err = $"Error while extracting keyword {keyword} from message: {ex.Message}";
                prms.Add(new NameValuePair() { Name = "ExtractorError", Value = err });
            }
            return false;
        }

        protected static bool TryExtractValue(string message, string keyword, out string? value, bool grabAll = false)
        {
            value = null;
            int pos = message.IndexOf(keyword, StringComparison.OrdinalIgnoreCase);
            if (pos < 0)
            {
                return false;
            }
            // if preceeded by letter or digit - this is partial match, ignore it
            if (pos > 0 && char.IsLetterOrDigit(message[pos - 1]))
            {
                return false;
            }

            pos += keyword.Length;
            if (pos >= message.Length - 2)
            {
                return false;
            }
            // if followed by letter or digit - this is partial match, ignore it
            if (char.IsLetterOrDigit(message[pos]))
            {
                return false;
            }
            // skip special symbols like =
            int valueStart = _ = message.Skip(pos, ' ', ':', '=');
            char startCh = message[valueStart];
            int valueEnd;
            if (startCh == '"' || startCh == '\'')
            {
                valueStart++;
                valueEnd = message.SkipUntil(valueStart, startCh);
            }
            else
            {
                valueEnd = grabAll ? message.Length : message.SkipUntil(valueStart, ' ', ',', ';', ']', ')');
            }

            if (valueEnd <= valueStart)
            {
                return false;
            }
            value = message[valueStart..valueEnd];
            return true;
        }
    }
}
