// /********************************************************
// *                                                       *
// *   Copyright (C) Microsoft. All rights reserved.       *
// *                                                       *
// ********************************************************/

using SyslogDecode.Model;
using System;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace SyslogDecode.Udp
{
    /// <summary>Sends a stream of Syslog messages to the target remote UDP endpoint. </summary>
    public class SyslogUdpSender : IDisposable
    {
        public UdpClient UdpClient { get; }
        private readonly IPEndPoint _target;

        /// <summary>Creates a new instance of the class. </summary>
        /// <param name="target">The target endpoint. </param>
        public SyslogUdpSender(IPEndPoint target)
        {
            _target = target;
            UdpClient = new UdpClient();
        }

        /// <summary>Creates a new instance of the class. </summary>
        /// <param name="ipAddress">The target IP address.</param>
        /// <param name="port">The target port; defaults to 514.</param>
        public SyslogUdpSender(string ipAddress, int port = 514)
        {
            IPAddress addr = IPAddress.Parse(ipAddress);
            _target = new IPEndPoint(addr, port);
            UdpClient = new UdpClient();
        }

        public void Dispose()
        {
            UdpClient.Dispose();
        }

        /// <summary>
        /// Serializes syslog record into a string for transmission and sends it over a network to an IP endpoint.
        /// </summary>
        /// <param name="entry">SyslogEntry - a SyslogEntry instance.</param>
        public void Send(ParsedSyslogMessage entry)
        {
            string payload = SyslogSerializer.Serialize(entry);
            Send(payload);
        }

        /// <summary>Sends a plain text syslog message. </summary>
        /// <param name="payload">The payload to send.</param>
        public void Send(string payload)
        {
            byte[] dgram = Encoding.UTF8.GetBytes(payload);
            _ = UdpClient.Send(dgram, dgram.Length, _target);
        }
    }
}
