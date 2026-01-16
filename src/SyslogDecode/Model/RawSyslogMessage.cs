// /********************************************************
// *                                                       *
// *   Copyright (C) Microsoft. All rights reserved.       *
// *                                                       *
// ********************************************************/

using System;
using System.Net;

namespace SyslogDecode.Model
{
    /// <summary>A container for the raw, unparsed syslog message and related information.</summary>
    public class RawSyslogMessage
    {
        /// <summary>Date-time when the message was received. </summary>
        public required DateTime ReceivedOn;

        /// <summary>The IP address of the message sender. </summary>
        public required IPAddress SourceIpAddress;

        /// <summary>The message content. </summary>
        public required string Message;
    }

    /// <summary>A container for the raw, unparsed syslog message and related information.</summary>
    public ref struct RawSyslogMessageSpan
    {
        /// <summary>Date-time when the message was received. </summary>
        public required DateTime ReceivedOn;

        /// <summary>The IP address of the message sender. </summary>
        public required IPAddress SourceIpAddress;

        /// <summary>The message content. </summary>
        public required ReadOnlySpan<char> Message;
    }


}
