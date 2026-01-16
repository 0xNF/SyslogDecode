// /********************************************************
// *                                                       *
// *   Copyright (C) Microsoft. All rights reserved.       *
// *                                                       *
// ********************************************************/

using SyslogDecode.Model;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;

namespace SyslogDecode.Common
{
    /// <summary>
    ///   Implements a batching queue - concurrent no-lock enqueue-one; dequeue many with lock.
    /// </summary>
    [DebuggerDisplay("Count = {Count}")]
    public sealed class BatchingQueueSyslog : IObserver<RawSyslogMessage>
    {

        public int Count => _count;

        private class Node
        {
            public RawSyslogMessage? Item;
            public Node? Next;
        }

        // We use Interlocked operations when accessing last-in (to push items);
        // we use lock when accessing _lastOut element (dequeuing multiple items)
        private volatile Node _lastIn; //must be marked as volatile for interlocked ops
        private Node _lastOut;
        private readonly Lock _dequeueLock = new();
        private volatile int _count;

        public BatchingQueueSyslog()
        {
            // There's always at least one empty node in linked list; so empty queue holds just one node.
            //  this is necessary to avoid problem with pushing first node (or popping the last one) - when you have
            // to modify both pointers to start and end of the list from null to this first element.  
            _lastIn = _lastOut = new Node();
        }

        public void Enqueue(RawSyslogMessage item)
        {
            // 1. Get node from pool or create new one
            Node newNode = NodePoolTryPop() ?? new Node();
            newNode.Item = item;
            // 2. Quick path
            Node oldLastIn = _lastIn;
            if (Interlocked.CompareExchange(ref _lastIn, newNode, oldLastIn) == oldLastIn)
            {
                oldLastIn.Next = newNode;
            }
            else
            {
                EnqueueSlowPath(newNode);
            }

            _ = Interlocked.Increment(ref _count);
        }

        // Same as Enqueue but in a loop with spin
        private void EnqueueSlowPath(Node newNode)
        {
            SpinWait spinWait = new();
            Node oldLastIn;
            do
            {
                spinWait.SpinOnce();
                oldLastIn = _lastIn;
            } while (Interlocked.CompareExchange(ref _lastIn, newNode, oldLastIn) != oldLastIn);
            oldLastIn.Next = newNode;
        }


        public IList<RawSyslogMessage> DequeueMany(int maxCount = int.MaxValue)
        {
            // iterate over list starting with _lastOut
            List<RawSyslogMessage> list = new(Math.Min(maxCount, Count + 1)); //add extra 1, just in case
            lock (_dequeueLock)
            {
                while (_lastOut.Next?.Item != null && list.Count < maxCount)
                {
                    // save the ref to the node to return it to the pool at the end
                    Node savedLastOut = _lastOut;
                    // Advance _lastOut, copy item to result list.
                    _lastOut = _lastOut.Next;
                    list.Add(_lastOut.Item!);
                    _lastOut.Item = default; //clear the ref to data
                    _ = Interlocked.Decrement(ref _count);
                    NodePoolTryPush(savedLastOut); // return the node to the pool
                }
                return list;
            } //lock
        } //method

        #region Node pooling
        // We pool/reuse Node objects; we save nodes in a simple concurrent stack.
        // The stack is not 100% reliable - it might fail occasionally when pushing/popping up nodes
        private volatile Node? _nodePoolHead;

        private Node? NodePoolTryPop()
        {
            Node? head = _nodePoolHead;
            if (head == null) // stack is empty
            {
                return null;
            }

            if (Interlocked.CompareExchange(ref _nodePoolHead, head.Next, head) == head)
            {
                head.Next = null;
                return head;
            }
            // Node pool is not reliable (push and pop),
            // Hypotethically this may result in pool growth over time: let's say all pushes succeed, but some rare pops fail.  
            // To prevent this from ever happening, we drop the entire pool if we ever fail to pop.
            // This is an EXTREMELY rare event, and if it happens - no impact, just extra objects for GC to collect
            _nodePoolHead = null; //drop the pool
            return null;
        }

        private void NodePoolTryPush(Node node)
        {
            node.Item = default;
            node.Next = _nodePoolHead;
            // we make just one attempt; if it fails, we don't care - node will be GC-d
            _ = Interlocked.CompareExchange(ref _nodePoolHead, node, node.Next);
        }
        #endregion

        #region IObserver<T> implementation
        void IObserver<RawSyslogMessage>.OnCompleted()
        {
        }

        void IObserver<RawSyslogMessage>.OnError(Exception error)
        {
        }

        void IObserver<RawSyslogMessage>.OnNext(RawSyslogMessage value)
        {
            Enqueue(value);
        }
        #endregion

    } //class
}
