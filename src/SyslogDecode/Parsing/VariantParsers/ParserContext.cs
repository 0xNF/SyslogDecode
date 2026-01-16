// /********************************************************
// *                                                       *
// *   Copyright (C) Microsoft. All rights reserved.       *
// *                                                       *
// ********************************************************/

using SyslogDecode.Common;
using SyslogDecode.Model;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;

namespace SyslogDecode.Parsing.VariantParsers
{
    [DebuggerDisplay("P:{Position}, ch: {Current}")]
    public class ParserContext(RawSyslogMessage msg)
    {
        public string Text = msg.Message.CutOffBOM();
        public int Position;
        public string Prefix = string.Empty; // standard <n> prefix identifying 'syslog' message
        public readonly ParsedSyslogMessage ParsedMessage = new(msg);
        public List<string> ErrorMessages => ParsedMessage.ErrorMessages;

        public char Current => Position < Text.Length ? Text[Position] : '\0';
        public char CharAt(int position)
        {
            return Text[position];
        }

        public bool Eof()
        {
            return Position >= Text.Length;
        }

        public ParserContext(string message) : this(new RawSyslogMessage() { Message = message, ReceivedOn = AppTime.UtcNow, SourceIpAddress = IPAddress.Loopback }) { }

        public void AddError(string message)
        {
            ErrorMessages.Add($"{message} (near {Position})");
        }


    }
}
