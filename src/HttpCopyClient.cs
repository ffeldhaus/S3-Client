/*
Copyright (c) .NET Foundation. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License. You may obtain a copy of the
License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.
*/

using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Internal;
using System.Diagnostics.Contracts;
using System.Threading;
using System.Threading.Tasks;

namespace System.Net.Http
{
    /// <summary>
    /// Provides an <see cref="HttpCopyClient"/> implementation that extends <see cref="HttpClient"/>
    /// with a new method CopyAsync which copies the response stream from a GET response to a PUT request
    /// </summary>
    public class HttpCopyClient: HttpClient {
        public Task CopyAsync(HttpResponseMessage getResponse, HttpRequestMessage putRequest, CancellationToken cancellationToken) {
            putRequest.Content = new PushStreamContent(async (stream, httpContent, transportContext) =>
                {
                    Task copyTask = getResponse.Content.CopyToAsync(stream);
                    await copyTask;
                    stream.Dispose();
                });
            putRequest.Content.Headers.ContentLength = getResponse.Content.Headers.ContentLength;
            this.Timeout = new TimeSpan(0, 0, Math.Max((Int32)(getResponse.Content.Headers.ContentLength / (60 * 1024)), (Int32)60));
            return this.SendAsync(putRequest, cancellationToken);
        }
    }

    /// <summary>
    /// Provides an <see cref="HttpContent"/> implementation that exposes an output <see cref="Stream"/>
    /// which can be written to directly. The ability to push data to the output stream differs from the
    /// <see cref="StreamContent"/> where data is pulled and not pushed.
    /// </summary>
    public class PushStreamContent : HttpContent
    {
        private readonly Func<Stream, HttpContent, System.Net.TransportContext, Task> _onStreamAvailable;

        /// <summary>
        /// Initializes a new instance of the <see cref="PushStreamContent"/> class.
        /// </summary>
        /// <param name="onStreamAvailable">The action to call when an output stream is available. The stream is automatically
        /// closed when the return task is completed.</param>
        public PushStreamContent(Func<Stream, HttpContent, TransportContext, Task> onStreamAvailable)
        {
            if (onStreamAvailable == null)
            {
                throw new ArgumentNullException("onStreamAvailable");
            }
            _onStreamAvailable = onStreamAvailable;
        }

        /// <summary>
        /// When this method is called, it calls the action provided in the constructor with the output
        /// stream to write to. Once the action has completed its work it closes the stream which will
        /// close this content instance and complete the HTTP request or response.
        /// </summary>
        /// <param name="stream">The <see cref="Stream"/> to which to write.</param>
        /// <param name="context">The associated <see cref="TransportContext"/>.</param>
        /// <returns>A <see cref="Task"/> instance that is asynchronously serializing the object's content.</returns>
        protected override async Task SerializeToStreamAsync(Stream stream, System.Net.TransportContext context)
        {
            TaskCompletionSource<bool> serializeToStreamTask = new TaskCompletionSource<bool>();

            Stream wrappedStream = new CompleteTaskOnCloseStream(stream, serializeToStreamTask);
            await _onStreamAvailable(wrappedStream, this, context);

            // wait for wrappedStream.Close/Dispose to get called.
            await serializeToStreamTask.Task;
        }

        /// <summary>
        /// Computes the length of the stream if possible.
        /// </summary>
        /// <param name="length">The computed length of the stream.</param>
        /// <returns><c>true</c> if the length has been computed; otherwise <c>false</c>.</returns>
        protected override bool TryComputeLength(out long length)
        {
            // We can't know the length of the content being pushed to the output stream.
            length = -1;
            return false;
        }

        internal class CompleteTaskOnCloseStream : DelegatingStream
        {
            private TaskCompletionSource<bool> _serializeToStreamTask;

            public CompleteTaskOnCloseStream(Stream innerStream, TaskCompletionSource<bool> serializeToStreamTask)
                : base(innerStream)
            {
                Contract.Assert(serializeToStreamTask != null);
                _serializeToStreamTask = serializeToStreamTask;
            }

#if NETFX_CORE
            protected override void Dispose(bool disposing)
            {
                // We don't dispose the underlying stream because we don't own it. Dispose in this case just signifies
                // that the user's action is finished.
                _serializeToStreamTask.TrySetResult(true);
            }
#else
            public override void Close()
            {
                // We don't Close the underlying stream because we don't own it. Dispose in this case just signifies
                // that the user's action is finished.
                _serializeToStreamTask.TrySetResult(true);
            }
#endif
        }
    }
}

namespace System.Net.Http.Internal
{
    internal abstract class DelegatingStream : Stream
    {
        private readonly Stream _innerStream;

        protected DelegatingStream(Stream innerStream)
        {
            if (innerStream == null)
            {
                throw new ArgumentNullException("innerStream");
            }
            _innerStream = innerStream;
        }

        protected Stream InnerStream
        {
            get { return _innerStream; }
        }

        public override bool CanRead
        {
            get { return _innerStream.CanRead; }
        }

        public override bool CanSeek
        {
            get { return _innerStream.CanSeek; }
        }

        public override bool CanWrite
        {
            get { return _innerStream.CanWrite; }
        }

        public override long Length
        {
            get { return _innerStream.Length; }
        }

        public override long Position
        {
            get { return _innerStream.Position; }
            set { _innerStream.Position = value; }
        }

        public override int ReadTimeout
        {
            get { return _innerStream.ReadTimeout; }
            set { _innerStream.ReadTimeout = value; }
        }

        public override bool CanTimeout
        {
            get { return _innerStream.CanTimeout; }
        }

        public override int WriteTimeout
        {
            get { return _innerStream.WriteTimeout; }
            set { _innerStream.WriteTimeout = value; }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _innerStream.Dispose();
            }
            base.Dispose(disposing);
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            return _innerStream.Seek(offset, origin);
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            return _innerStream.Read(buffer, offset, count);
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            return _innerStream.ReadAsync(buffer, offset, count, cancellationToken);
        }

#if !NETFX_CORE // BeginX and EndX not supported on Streams in portable libraries
        public override IAsyncResult BeginRead(byte[] buffer, int offset, int count, AsyncCallback callback, object state)
        {
            return _innerStream.BeginRead(buffer, offset, count, callback, state);
        }

        public override int EndRead(IAsyncResult asyncResult)
        {
            return _innerStream.EndRead(asyncResult);
        }
#endif

        public override int ReadByte()
        {
            return _innerStream.ReadByte();
        }

        public override void Flush()
        {
            _innerStream.Flush();
        }

        public override Task FlushAsync(CancellationToken cancellationToken)
        {
            return _innerStream.FlushAsync(cancellationToken);
        }

        public override void SetLength(long value)
        {
            _innerStream.SetLength(value);
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            _innerStream.Write(buffer, offset, count);
        }

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            return _innerStream.WriteAsync(buffer, offset, count, cancellationToken);
        }

#if !NETFX_CORE // BeginX and EndX not supported on Streams in portable libraries
        public override IAsyncResult BeginWrite(byte[] buffer, int offset, int count, AsyncCallback callback, object state)
        {
            return _innerStream.BeginWrite(buffer, offset, count, callback, state);
        }

        public override void EndWrite(IAsyncResult asyncResult)
        {
            _innerStream.EndWrite(asyncResult);
        }
#endif

        public override void WriteByte(byte value)
        {
            _innerStream.WriteByte(value);
        }
    }
}