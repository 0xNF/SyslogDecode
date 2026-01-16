// /********************************************************
// *                                                       *
// *   Copyright (C) Microsoft. All rights reserved.       *
// *                                                       *
// ********************************************************/

using SyslogDecode.Common;
using SyslogDecode.Model;
using System.Collections.Generic;

namespace SyslogDecode.Parsing
{
    /// <summary>Parses input stream of raw syslog messages on multiple parallel threads. </summary>
    /// <remarks>Creates a new instance of the stream parser. </remarks>
    /// <param name="parser">Optional, message parser. If missing, the default parser is used.</param>
    /// <param name="batchSize">Optional, batch size, a number of messages to read from the input buffering queue to be parsed on a separate thread.</param>
    /// <param name="threadCount">Optional, a number of parsing threads to launch.</param>
    public class SyslogStreamParser(SyslogMessageParser? parser = null, int batchSize = 100, int? threadCount = null) : ParallelStreamProcessorSyslog<ParsedSyslogMessage>(batchSize, threadCount)
    {
        public readonly SyslogMessageParser Parser = parser ?? SyslogMessageParser.CreateDefault();

        protected override void ProcessItem(RawSyslogMessage item)
        {
            ParsedSyslogMessage parsedMsg = Parser.Parse(item);
            Broadcast(parsedMsg);
        }

        /// <summary>Retrieves the health data.</summary>
        /// <param name="data">Data container.</param>
        /// <param name="prefix">Optional key prefix.</param>
        public void AddHealthData(IDictionary<string, object> data, string? prefix = null)
        {
            data[prefix + DataKeyBufferQueueCount] = base.BufferQueueCount;
            data[prefix + DataKeyActiveParseProcessCount] = base.ActiveProcessCount;
            data[prefix + DataKeyInputEps] = base.InputEpsCounter.ReadEps();
            data[prefix + DataKeyOutputEps] = base.OutputEpsCounter.ReadEps();
        }

        public const string DataKeyBufferQueueCount = "Parser_BufferQueueCount";
        public const string DataKeyActiveParseProcessCount = "Parser_ActiveProcessCount";
        public const string DataKeyInputEps = "Parser_InputEps";
        public const string DataKeyOutputEps = "Parser_OutputEps";
    }
}
