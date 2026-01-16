// /********************************************************
// *                                                       *
// *   Copyright (C) Microsoft. All rights reserved.       *
// *                                                       *
// ********************************************************/

using SyslogDecode.Model;
using System;
using System.Collections.Generic;
using System.Threading;

namespace SyslogDecode.Common
{
    /// <summary>Processes stream of messages on multiple parallel threads. </summary>
    public abstract class ParallelStreamProcessorSyslog<Tout>(int batchSize = 100, int? threadCount = null) : Observable<Tout>, IObserver<RawSyslogMessage>
    {
        public int BatchSize = batchSize;
        public int IdlePauseMs = 10;
        public int ThreadCount = threadCount == null ? Environment.ProcessorCount : threadCount.Value;

        public event EventHandler<ItemEventArgs<RawSyslogMessage>>? ItemReceived;
        public event EventHandler<ItemEventArgs<Tout>>? ItemProcessed;
        public readonly EpsCounter InputEpsCounter = new("InputEps");
        public readonly EpsCounter OutputEpsCounter = new("OutputEps");

        public long InputCount => InputEpsCounter.CurrentItemCount;
        public long OutputCount => OutputEpsCounter.CurrentItemCount;
        public int BufferQueueCount => _buffer.Count;
        public int ActiveProcessCount => _activeProcessCount;

        private readonly BatchingQueueSyslog _buffer = new();
        private int _activeProcessCount;
        private bool _running;

        public virtual void Start()
        {
            if (_running)
            {
                return;
            }

            _running = true;
            for (int i = 0; i < ThreadCount; i++)
            {
                Thread thread = new(RunProcessingLoop);
                thread.Start();
            }
        }

        public virtual void Stop()
        {
            OnCompleted();
            _running = false;
            while (!IsIdle)
            {
                Thread.Sleep(10);
            }
        }

        public bool IsIdle => BufferQueueCount == 0 && _activeProcessCount == 0;

        protected abstract void ProcessItem(RawSyslogMessage item);

        #region IObserver members
        public virtual void OnNext(RawSyslogMessage item)
        {
            _buffer.Enqueue(item);
            _ = InputEpsCounter.Increment();
            if (!_running)
            {
                Start();
            }

            ItemReceived?.Invoke(this, new ItemEventArgs<RawSyslogMessage>(item));
        }

        public virtual void OnCompleted()
        {
            while (!IsIdle)
            {
                Thread.Sleep(50);
            }
        }

        public virtual void OnError(Exception error)
        {
            // errors upstream (in UDP listener) should be already reported
        }
        #endregion

        private void RunProcessingLoop()
        {
            while (_running)
            {
                if (_buffer.Count == 0)
                {
                    if (!_running)
                    {
                        return;
                    }

                    Thread.Sleep(IdlePauseMs);
                    continue;
                }
                // if not enough for a full batch, make another wait
                if (_buffer.Count < BatchSize / 2)
                {
                    Thread.Sleep(IdlePauseMs);
                }

                try
                {
                    _ = Interlocked.Increment(ref _activeProcessCount);
                    // get batch
                    IList<RawSyslogMessage> items = _buffer.DequeueMany(BatchSize);
                    if (items.Count == 0)
                    {
                        continue;
                    }
                    ProcessBatch(items);
                }
                catch (Exception ex)
                {
                    BroadcastError(ex);
                }
                finally
                {
                    _ = Interlocked.Decrement(ref _activeProcessCount);
                }
            }
        } //method

        protected virtual void ProcessBatch(IList<RawSyslogMessage> items)
        {
            // var start = AppTime.GetTimestamp();
            foreach (RawSyslogMessage item in items)
            {
                try
                {

                    ProcessItem(item);
                }
                catch (Exception ex)
                {
                    BroadcastError(ex);
                }
            }
            //var timeMs = AppTime.GetDuration(start).TotalMilliseconds;
        }

        public override void Broadcast(Tout item)
        {
            _ = OutputEpsCounter.Increment();
            base.Broadcast(item);
            ItemProcessed?.Invoke(this, new ItemEventArgs<Tout>(item));
        }

    }
}
