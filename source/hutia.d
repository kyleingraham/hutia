import core.stdc.string : memcpy;
import core.thread : Thread;
import core.time : Duration, nsecs, msecs, MonoTime;
import eventcore.driver : IOMode;
import ldc.intrinsics : llvm_expect;
import lock_free.rwqueue : RWQueue;
import std.algorithm.comparison : min;
import std.array : Appender;
import std.concurrency : ownerTid, receive, receiveOnly, spawn,
                         thisTid, Tid;
import std.conv : to;
import std.exception : enforce;
import std.format : format;
import std.string : toStringz;
import std.typecons : Nullable, Tuple;
import unit_integration;
import vibe.container.dictionarylist : DictionaryList;
import vibe.container.ringbuffer : RingBuffer;
import vibe.core.channel : createChannel, Channel, ChannelPriority, ChannelConfig;
import vibe.core.concurrency : send, prioritySend;
import vibe.core.core : exitEventLoop, runApplication, runTask, yield, createTimer;
import vibe.core.task : Task;
import vibe.core.stream : InputStream;

@safe class WebApplication
{
    private
    {
        RequestFunction handler_;
        WebApplicationContext* webAppContext;
    }

    this(){}

    static WebApplication create()
    {
        return new WebApplication();
    }

    WebApplication map(string route, RequestFunction handler)
    {
        setHandler(handler);
        return this;
    }

    int run()
    {
        auto webAppContext = WebApplicationContext();
        (() @trusted => spawn(&runUnit, webAppContext))();

        // Length of queue
        import core.bitop : bsr;
        auto v = 4096 / 8;
        auto roundPow2 = v ? cast(size_t)1 << bsr(v) : 0;

        logUnit(
            null,
            UnitLogLevel.debug_,
            format("RequestInfoMessage.sizeof=%s roundPow2=%s", RequestInfoMessage.sizeof, roundPow2)
        );
        //

        dispatcherTask = runTask(&runDispatcherNew2);

        runApplication();
        logUnit(
            null,
            UnitLogLevel.debug_,
            format("HttpContext.freeListLength=%s", HttpContext.freeListLength)
        );
        return (() @trusted => receiveOnly!int)();
    }
}

private shared Task dispatcherTask;

private void runDispatcher() @safe nothrow
{
    bool shouldRun = true;

    while (shouldRun)
    {
        void requestInfoHandler(RequestInfoMessage message)
        {
            //auto poppedMessage = requestQueue.pop();
            //dispatch(poppedMessage);
            //auto spinDuration = 5.msecs;
            //auto start = MonoTime.currTime;
            //do
            //{
            //    while (!requestQueue.empty)
            //    {
            //        auto poppedMessage = requestQueue.pop();
            //        dispatch(poppedMessage);
            //    }
            //    Thread.yield();
            //} while (MonoTime.currTime - start < spinDuration);
        }

        void cancelHandler(CancelMessage message)
        {
            shouldRun = false;
        }

        try
        {
            (() @trusted => receive(&requestInfoHandler, &cancelHandler))();
        }
        catch (Exception e)
        {
            auto message = (() @trusted => getExceptionMessage(e))();
            logUnit(null, UnitLogLevel.alert, message);
            shouldRun = false;
        }
    }

    exitEventLoop();
}

Duration delegate() @safe exponentialBackoff() @safe
{
    // Start with an initial value of 0.
    ulong current = 400_000_000;

    return delegate() {
        // Calculate the next backoff value in nanoseconds.
        ulong nextBackoff = min(1_000_000_000, current * 100);
        // Increment the current step to increase the backoff exponentially.
        current++;

        return nextBackoff.nsecs;
    };
}

private void runDispatcherNew2() @safe nothrow
{
    try
    {
        RingBuffer!(RequestInfoMessage, 100, true) buffer;
        RequestInfoMessage message;
        logUnit(null, UnitLogLevel.debug_, "Starting runDispatcherNew2");

        while (true)
        {
            requestChannel.consumeAll(buffer);
            while (!buffer.empty)
            {
                message = buffer.front;
                if (message.requestInfo is null)
                {
                    logUnit(null, UnitLogLevel.debug_, "Stopping runDispatcherNew2");
                    break;
                }
                dispatch(message);
                buffer.removeFront();
            }
        }
    }
    catch (Exception e)
    {
        auto message = (() @trusted => getExceptionMessage(e))();
        logUnit(null, UnitLogLevel.alert, message);
    }

    exitEventLoop();
}

private void runDispatcherNew() @safe nothrow
{
    try
    {
        auto waiter = createTimer(null);
        Duration delegate() @safe backoff;
        logUnit(null, UnitLogLevel.debug_, "Starting runDispatcherNew");

        while (cancelQueue.empty)
        {
            backoff = exponentialBackoff();
            while (requestQueue.empty)
            {
                // High overhead. Max 20k req/sec.
                //waiter.rearm(0.nsecs, false);
                //waiter.wait();
                // No overhead. Max 45k req/sec.
                yield();
            }

            if (!cancelQueue.empty)
            {
                logUnit(null, UnitLogLevel.debug_, "Stopping runDispatcherNew");
                break;
            }

            // should batch these out
            auto message = requestQueue.pop();
            //logUnit(null, UnitLogLevel.debug_, format("Popped=%s", message));
            dispatch(message);
        }
    }
    catch (Exception e)
    {
        auto message = (() @trusted => getExceptionMessage(e))();
        logUnit(null, UnitLogLevel.alert, message);
    }

    exitEventLoop();
}

private struct RequestInfoMessage
{
    shared nxt_unit_request_info_t* requestInfo;
}

private struct CancelMessage{}

private shared(RWQueue!RequestInfoMessage) requestQueue;
private shared(RWQueue!int) cancelQueue;

nxt_unit_request_info_t* getRequestInfo(
    shared(nxt_unit_request_info_t*) requestInfo
) @trusted
{
    return cast(nxt_unit_request_info_t*)requestInfo;
}

private void dispatch(RequestInfoMessage message) @safe
{
    //auto unitRequestInfo = (() @trusted {
    //    /**
    //     * We would normally keep this shared and access it through sychronized blocks.
    //     * sychronized won't do much for us here though because Unit retains control
    //     * of the pointer. We are trusting in Unit's management of it while we have it.
    //     * We are also retaining a single-threaded model for Hutia.
    //     * */
    //    return cast(nxt_unit_request_info_t*)message.requestInfo;
    //})();

    runTask((nxt_unit_request_info_t* requestInfo) nothrow {
        try
        {
            auto httpContext = HttpContext.allocate(requestInfo);
            scope (exit)
            {
                httpContext.response.complete();
                HttpContext.deallocate(httpContext);
            }

            httpContext.response.body.write(
                getHandler()(httpContext)
            );
        }
        catch (Exception e)
        {
            /**
             * Any uncaught exception while writing the repsonse should result in the
             * request being finalized gracefully. Ideally there is another layer above
             * this ensuring the status code is updated to a 500. Uncaught exceptions
             * will break Unit.
             * */
            auto message = (() @trusted => getExceptionMessage(e))();
            logUnit(requestInfo.ctx, UnitLogLevel.alert, message);
        }
    }, getRequestInfo(message.requestInfo));
}

private string getExceptionMessage(Throwable e) @system nothrow
{
    import std.format : FormatException;

    try
        return format("%s", e);
    catch (FormatException)
        return e.msg;
    catch (Exception)
        return e.msg;
}

private alias RequestFunction = extern(C) string function(HttpContext) @safe;

private shared Nullable!RequestFunction handler;

private void setHandler(RequestFunction newHandler) @safe
{
    synchronized
    {
        if ((cast(Nullable!RequestFunction)handler).isNull)
            handler = Nullable!RequestFunction(newHandler);
        else
            throw new InvalidOperationException("Cannot set handler more than once");
    }
}

private const(RequestFunction) getHandler() @safe
{
    return (cast(Nullable!RequestFunction)handler).get;
}

extern(C)
private @safe struct WebApplicationContext{}

private void runUnit(const(WebApplicationContext) webAppContext) @system
{
    int rc;
    nxt_unit_init_t init;
    init.callbacks.request_handler = &(unitRequestHandler);
    init.callbacks.ready_handler   = &(unitReadyHandler);

    nxt_unit_ctx_t* unitContext = nxt_unit_init(&init);
    if (unitContext is null)
    {
        rc = NXT_UNIT_ERROR;
        goto fail;
    }

    rc = nxt_unit_run(unitContext);
    nxt_unit_done(unitContext);

    fail:
    //send(dispatcherTask, CancelMessage());

    //cancelQueue.push(1);
    //requestQueue.push(shared RequestInfoMessage(null));

    requestChannel.put(RequestInfoMessage(null));
    send(ownerTid, rc);
}

shared Channel!RequestInfoMessage requestChannel;

shared static this()
{
    // to use ChannelPriority.overhead one must close channel
    requestChannel = createChannel!RequestInfoMessage(
        ChannelConfig(ChannelPriority.overhead)
    );
}

extern(C)
private void unitRequestHandler(nxt_unit_request_info_t* requestInfo) @system
{
    // We are trusting that Unit manages this pointer safely after passing it to us.
    auto sharedRequestInfo = cast(shared)requestInfo;
    auto message = RequestInfoMessage(sharedRequestInfo);

    //while (requestQueue.full)
        //Thread.yield();
    //requestQueue.push(cast(shared(RequestInfoMessage))message);
    //logUnit(null, UnitLogLevel.debug_, format("Pushed=%s", message));
    //prioritySend(dispatcherTask, RequestInfoMessage(null)); // Let dispatcher no requests available

    requestChannel.put(message);

    //send(dispatcherTask, message);
}

extern(C)
private int unitReadyHandler(nxt_unit_ctx_t* unitContext) @safe
{
    return NXT_UNIT_OK;
}

void logUnit(
    nxt_unit_ctx_t* unitContext,
    UnitLogLevel logLevel,
    string message
) @trusted nothrow
{
    try
        nxt_unit_log(
            cast(nxt_unit_ctx_t*)unitContext, logLevel, ("[Hutia] " ~ message).toStringz
        );
    catch(Exception e){};
}

void logError(HttpContext httpContext, string message) @trusted
{
    logUnit(httpContext.request.requestInfo.ctx, UnitLogLevel.error, message);
}

enum UnitLogLevel : uint
{
    alert = NXT_UNIT_LOG_ALERT,
    error = NXT_UNIT_LOG_ERR,
    warn = NXT_UNIT_LOG_WARN,
    notice = NXT_UNIT_LOG_NOTICE,
    info = NXT_UNIT_LOG_INFO,
    debug_ = NXT_UNIT_LOG_DEBUG,
};

@safe class HttpContext
{
    private
    {
        HttpRequest request_;
        HttpResponse response_;
    }

    private this(HttpRequest request, HttpResponse response)
    {
        request_ = request;
        response_ = response;
    }

    private static HttpContext create(nxt_unit_request_info_t* requestInfo)
    {
        auto request = HttpRequest.create(requestInfo);
        auto response = HttpResponse.create(requestInfo);
        return new HttpContext(request, response);
    }

    HttpRequest request()
    {
        return request_;
    }

    HttpResponse response()
    {
        return response_;
    }

    // Free List

    /**
     * This free list requires implementation of 3 methods:
     *     - an `initialize` method
     *         - Should make the object ready for a request.
     *           Returns void and should accept all required arguments for initialization.
     *     - a `reset` method
     *         - Resets an object to an uninitialized, but allocated state. The object
     *           should have no remnants of the last request it participated in.
     *           Returns void and accepts no arguments.
     * */

    private static HttpContext freeList;

    private static HttpContext allocate(nxt_unit_request_info_t* requestInfo)
    {
        HttpContext httpContext;

        if (freeList)
        {
            httpContext = freeList;
            freeList = httpContext.next;
            httpContext.initialize(requestInfo);
        }
        else
            httpContext = HttpContext.create(requestInfo);

        return httpContext;
    }

    private static void deallocate(HttpContext httpContext)
    {
        httpContext.reset();
        httpContext.next = freeList;
        freeList = httpContext;
    }

    private HttpContext next;

    private static size_t freeListLength()
    {
        HttpContext element = freeList;
        size_t count;
        while (element !is HttpContext.init)
        {
            element = element.next;
            count += 1;
        }

        return count;
    }

    // Memory management methods

    private void initialize(nxt_unit_request_info_t* requestInfo)
    {
        request_.initialize(requestInfo);
        response_.initialize(requestInfo);
    }

    private void reset()
    {
        request_.reset();
        response_.reset();
    }
}

@safe class HttpRequest
{
    private 
    {    
        InputStream body_;
        HttpHeadersDictionary headers_;
        string path_;
        string method_;
        nxt_unit_request_info_t* requestInfo;
    }

    private this(
        nxt_unit_request_info_t* requestInfo,
        string path,
        string method,
        HttpHeadersDictionary headers
    )
    {
        this.requestInfo = requestInfo;
        path_ = path;
        method_ = method;
        headers_ = headers;
        body_ = new HttpRequestBodyStream(this.requestInfo);
    }

    private static RequestValues getRequestValues(
        nxt_unit_request_info_t* requestInfo
    )
    {
        auto unitRequest = requestInfo.request;
        auto path = (() @trusted => getString(
            &unitRequest.target, unitRequest.target_length
        ))();
        auto method = (() @trusted => getString(
            &unitRequest.method, unitRequest.method_length
        ))();
        auto headers = getHeaders(unitRequest);

        return RequestValues(
            path, method, headers
        );
    }

    private static HttpRequest create(nxt_unit_request_info_t* requestInfo)
    {
        auto requestValues = getRequestValues(requestInfo);
        auto httpRequest =  new HttpRequest(
            requestInfo,
            requestValues.path,
            requestValues.method,
            requestValues.headers
        );

        return httpRequest;
    }

    InputStream body()
    {
        return body_;
    }

    Nullable!ulong contentLength()
    {
        string contentLength = headers_.get("Content-Length");
        if (contentLength == string.init)
            return Nullable!ulong();

        return Nullable!ulong(to!ulong(contentLength));
    }

    string method()
    {
        return method_;
    }

    string path()
    {
        return path_;
    }

    override string toString()
    {
        return "HttpRequest(\"" ~ method ~ "\", \"" ~ path ~ "\")";
    }

    // Memory management methods

    private void initialize(nxt_unit_request_info_t* requestInfo)
    {
        (cast(HttpRequestBodyStream)body_).initialize(requestInfo);
        auto requestValues = getRequestValues(requestInfo);
        path_ = requestValues.path;
        method_ = requestValues.method;
        headers_ = requestValues.headers;
        this.requestInfo = requestInfo;
    }

    private void reset()
    {
        (cast(HttpRequestBodyStream)body_).reset();
        headers_ = HttpHeadersDictionary.init;
        path_ = string.init;
        method_ = string.init;
        nxt_unit_request_info_t* requestInfo = null;
    }
}

private string getString(nxt_unit_sptr_t* stringPointer, size_t length) @system
{
    auto start = nxt_unit_sptr_get(stringPointer);
    return cast(string)(start[0..length]);
}

private HttpHeadersDictionary getHeaders(nxt_unit_request_t* unitRequest) @safe
{
    auto headers = HttpHeadersDictionary();

    foreach (i; 0..unitRequest.fields_count)
    {
        auto field = (() @trusted => getField(unitRequest, i))();
        headers.addField(
            (() @trusted => getString(&field.name, field.name_length))(), 
            (() @trusted => getString(&field.value, field.value_length))()
        );
    }

    return headers;
}

private nxt_unit_field_t* getField(
    nxt_unit_request_t* unitRequest,
    size_t fieldOffset
) @system
{
    return cast(nxt_unit_field_t*)unitRequest.fields + fieldOffset;
}

alias RequestValues = Tuple!(
    string, "path", string, "method", HttpHeadersDictionary, "headers"
);

private @safe class HttpRequestBodyStream : InputStream
{
    private 
    {
        Nullable!ulong contentLength;
        bool isEmpty = false;
        ulong position;
        nxt_unit_request_info_t* requestInfo;
    }

    this(nxt_unit_request_info_t* requestInfo)
    {
        this.requestInfo = requestInfo;
        this.contentLength = (() @trusted => getContentLength(requestInfo.request))();
    }

    bool empty()
    {
        return isEmpty;
    }

    const(ubyte)[] peek()
    {
        // Our stream has no internal buffer so we return an empty
        // slice (as per the InputStream API).
        return [];
    }

    ulong read(scope ubyte[] dst, IOMode mode)
    {
        if (empty)
            return 0;

        auto bytesRead = (() @trusted => nxt_unit_request_read(
            requestInfo, dst.ptr, dst.length
        ))();

        if (bytesRead < 0)
            throw new UnitRequestReadException(
                "nxt_unit_request_read return code=" ~ to!string(bytesRead)
            );

        position += bytesRead;

        if (contentLength.isNull)
            isEmpty = bytesRead == 0;
        
        else
            isEmpty = position >= contentLength.get;
        

        // leastSize()'s output determines the size of dst.
        // This must match the value returned by leastSize().
        // If not, we will fail vibe.d's assert after read() returns.
        return bytesRead;
    }

    private ulong availableBytes(nxt_unit_buf_t* buffer) 
    {
        ulong totalAvailable = 0;

        while (buffer != null)
        {
            totalAvailable += buffer.end - buffer.free;
            buffer = (() @trusted => nxt_unit_buf_next(buffer))();
        }

        return totalAvailable;
    }

    // Deprecated InputStream interface members

    bool dataAvailableForRead()
    {
        return 0 < leastSize();
    }

    ulong leastSize() @property
    {
        // If the stream is already empty, return 0
        if (empty)
        {
            return 0;
        }

        // If content length is known, return the remaining size
        if (!contentLength.isNull)
        {
            auto remainingContentLength = contentLength.get > position ? contentLength.get - position : 0;
            return remainingContentLength;
        }

        // For cases with no content length, check Unit's buffers directly
        auto remainingBuffer = (() @trusted => availableBytes(requestInfo.content_buf))();
        
        // If no bytes are available, we should mark the stream as empty
        if (remainingBuffer == 0)
        {
            isEmpty = true;
            return 0;
        }

        // Otherwise, we return remainingBuffer bytes for further reading
        return remainingBuffer;
    }

    // Memory management methods

    private void initialize(nxt_unit_request_info_t* requestInfo)
    {
        this.requestInfo = requestInfo;
        this.contentLength = (() @trusted => getContentLength(requestInfo.request))();
    }

    private void reset()
    {
        requestInfo = null;
        Nullable!ulong contentLength = Nullable!ulong();
        isEmpty = false;
        position = ulong.init;
    }
}

private Nullable!ulong getContentLength(nxt_unit_request_t* unitRequest) @safe
{
    Nullable!ulong contentLength;

    if (unitRequest.content_length_field == NXT_UNIT_NONE_FIELD)
        return contentLength;

    auto field = (() @trusted => getField(unitRequest, unitRequest.content_length_field))();
    contentLength = to!ulong(
        (() @trusted => getString(&field.value, field.value_length))()
    );
    return contentLength;
}

@safe class UnitRequestReadException : Exception
{
    this(string msg, string file = __FILE__, size_t line = __LINE__) {
        super(msg, file, line);
    }
}

@safe class HttpResponse
{
    private
    {
        HttpResponseBody body_;
        string contentType_;
        bool hasStarted_ = false;
        HttpResponseHeaders headers_;
        nxt_unit_request_info_t* requestInfo_;
        ushort statusCode_;
    }

    private this(nxt_unit_request_info_t* requestInfo)
    {
        requestInfo_ = requestInfo;
        body_ = new HttpResponseBody(this);
        headers_ = new HttpResponseHeaders(this);
    }

    private static HttpResponse create(nxt_unit_request_info_t* requestInfo)
    {
        return new HttpResponse(requestInfo);
    }

    HttpResponseBody body()
    {
        return body_;
    }

    void complete()
    {
        // Expect that we only get here on the happy path.
        body_.finalize(NXT_UNIT_OK, "");
    }

    string contentType()
    {
        return contentType_;
    }

    void contentType(string value)
    {
        enforce!InvalidOperationException(
            !hasStarted, 
            "Cannot modify content type after the response has started"
        );

        contentType_ = value;
    }

    bool hasStarted()
    {
        return hasStarted_;
    }

    private nxt_unit_request_info_t* requestInfo()
    {
        return requestInfo_;
    }

    private void writeHeaders() @system
    {    
        enforce!InvalidOperationException(
            !hasStarted,
            "Cannot write headers for a request more than once"
        );

        headers_.setDefault("Content-Type", "text/html; charset=utf-8");

        hasStarted_ = true;

        enforce!InvalidOperationException(
            headers_.count < uint.max,
            "Header count larger than Unit's max"
        );
        enforce!InvalidOperationException(
            headers_.length < uint.max,
            "Header key value length larger than Unit's max"
        );

        auto rc = nxt_unit_response_init(
            requestInfo_,
            statusCode_,
            cast(uint)headers_.count,
            cast(uint)headers_.length
        );
        if (llvm_expect(rc != NXT_UNIT_OK, 0))
            body.finalize(rc, "Response initialization failed");

        foreach(key, value; headers_.byKeyValue)
        {
            enforce!InvalidOperationException(
                key.length < ubyte.max,
                format("Header key longer than Unit's max: %s", key)
            );
            enforce!InvalidOperationException(
                value.length < uint.max,
                format("Header value larger than Unit's max: %s", value)
            );

            rc = (() @trusted => nxt_unit_response_add_field(
                requestInfo_,
                key.toStringz,
                cast(ubyte)key.length,
                value.toStringz,
                cast(uint)value.length
            ))();
            if (llvm_expect(rc != NXT_UNIT_OK, 0))
                body.finalize(rc, "Adding header to response failed");
        }

        rc = nxt_unit_response_send(requestInfo);
        if (llvm_expect(rc != NXT_UNIT_OK, 0))
            body.finalize(rc, "Sending header response failed");
    }

    ushort statusCode()
    {
        return statusCode_;
    }

    void statusCode(ushort value)
    {
        enforce!InvalidOperationException(
            !hasStarted, 
            "Cannot modify status code after the response has started"
        );

        statusCode_ = value;
    }

    HttpResponseHeaders headers()
    {
        return headers_;
    }

    // Memory management methods

    private void initialize(nxt_unit_request_info_t* requestInfo)
    {
        requestInfo_ = requestInfo;
        // These are null at program startup
        body_.initialize(this);
        headers_.initialize(this);
    }

    private void reset()
    {
        body_.reset();
        contentType_ = string.init;
        hasStarted_ = false;
        headers_.reset();
        requestInfo_ = null;
        statusCode_ = ushort.init;
    }
}

private @safe class HttpResponseHeaders
{
    private
    {
        HttpHeadersDictionary httpHeaders_;
        HttpResponse httpResponse;
        ulong length_;
    }

    private this(HttpResponse httpResponse)
    {
        httpHeaders_ = HttpHeadersDictionary();
        this.httpResponse = httpResponse;
    }

    void addField(string key, string value)
    {
        enforce!InvalidOperationException(
            !httpResponse.hasStarted, 
            "Cannot modify headers after the response has started"
        );

        updateLength(key, value);

        httpHeaders_.addField(key, value);
    }

    auto byKey() inout
    {
        return httpHeaders_.byKey();
    }

    auto byKeyValue() const
    {
        return httpHeaders_.byKeyValue();
    }

    private size_t count()
    {
        return httpHeaders_.length;
    }

    string get(string key)
    {
        return httpHeaders_.get(key);
    }

    void getAll(string key, scope void delegate(const(string)) @safe del) const
    {
        httpHeaders_.getAll(key, del);
    }

    private ulong length()
    {
        return length_;
    }

    string opIndex(string key)
    {
        return httpHeaders_[key];
    }

    void opIndexAssign(string value, string key)
    {
        enforce!InvalidOperationException(
            !httpResponse.hasStarted, 
            "Cannot modify headers after the response has started"
        );

        updateLength(key, value);

        httpHeaders_[key] = value;
    }

    string setDefault(string key, string defaultValue)
    {
        if (key in httpHeaders_)
            return httpHeaders_[key];
        
        httpHeaders_[key] = defaultValue;
        updateLength(key, defaultValue);
        return defaultValue;
    }

    override string toString()
    {
        return httpHeaders_.toString();
    }

    private void updateLength(string key, string value)
    {
        length_ += key.length + value.length;
    }

    // Memory management methods

    private void initialize(HttpResponse httpResponse)
    {
        this.httpResponse = httpResponse;
        httpHeaders_ = HttpHeadersDictionary();
    }

    private void reset()
    {
        httpHeaders_ = HttpHeadersDictionary.init;
        httpResponse = null; // HttpResponseBody doesn't control HtttpResponse initialization
        length_ = ulong.init;
    }
}

private alias HttpHeadersDictionary = DictionaryList!(string,false,12L,false);

@safe class HttpResponseBody
{
    private
    {
        bool hasFinalized = false;
        HttpResponse httpResponse;
    }

    private this(HttpResponse httpResponse)
    {
        this.httpResponse = httpResponse;
    }

    void write(const string response)
    {
        if (!httpResponse.hasStarted)
            (() @trusted => httpResponse.writeHeaders())();
        
        enforce!InvalidOperationException(
            !hasFinalized,
            "Cannot write to the body of a complete response"
        );

        auto rc = sendResponse(httpResponse.requestInfo(), response);
        if (llvm_expect(rc != NXT_UNIT_OK, 0))
            finalize(rc, "Writing response body failed");
    }

    private void finalize(int unitReturnCode, string message)
    {
        if (hasFinalized)
            return;

        hasFinalized = true;

        (() @trusted => nxt_unit_request_done(
            httpResponse.requestInfo(),
            unitReturnCode
        ))();
        if (unitReturnCode != NXT_UNIT_OK)
            // Halt further response processing now that we have cleaned up the response.
            throw new UnitOperationException(message, unitReturnCode);
    }

    // Memory management methods

    private void initialize(HttpResponse httpResponse)
    {
        this.httpResponse = httpResponse;
    }

    private void reset()
    {
        hasFinalized = false;
        httpResponse = null; // HttpResponseBody doesn't control HttpResponse initialization
    }
}

private int sendResponse(nxt_unit_request_info_t* requestInfo, string response) @safe
{
    nxt_unit_read_info_t readInfo = nxt_unit_read_info_t.init;
    readInfo.read = &(writeResponseCallback);
    readInfo.eof = 0;
    readInfo.buf_size = 8192;
    auto data = ResponseData(response);
    // We're taking references to stack variables here.
    // Usually that's a no-no, but we're sure those references won't live beyond this scope.
    readInfo.data = (() @trusted => cast(void*)&data)();
    return (() @trusted => nxt_unit_response_write_cb(requestInfo, &readInfo))();
}

extern(C)
private ptrdiff_t writeResponseCallback(
    nxt_unit_read_info_t* readInfo,
    void* destination,
    size_t size
) @safe
{
    auto data = (() @trusted => cast(ResponseData*)readInfo.data)();

    if (data.empty)
    {    
        return 0;
    }

    // NGINX Unit interprets a negative return as an error.
    auto bytesCopied = data.copyTo(destination, size);
    readInfo.eof = data.empty;

    return bytesCopied;
}

extern(C)
private @safe struct ResponseData
{
    private
    {
        string data;
        ulong position = 0;
    }

    this(string data) {
        this.data = data;
    }

    bool empty() const
    {
        return position >= data.length;
    }

    long copyTo(void* dst, size_t maxBytes)
    {
        auto remainingBytes = data.length - position;
        auto bytesToCopy = min(maxBytes, remainingBytes);
        auto start = 0 + position;
        auto sourceStart = &this.data[start];

        // NGINX Unit interprets a negative return as an error.
        if (llvm_expect(maxBytes < bytesToCopy, 0))
            return -1; // Destination out of bounds access.

        auto accessingSourceOob = (
            sourceStart < &this.data[0] ||
            &this.data[$ - 1] < &this.data[start + bytesToCopy - 1]
        );
        if (llvm_expect(accessingSourceOob, 0))
            return -1; // Source out of bounds access.

        (() @trusted => memcpy(dst, cast(void*)(sourceStart), bytesToCopy))();
        position += bytesToCopy;
        return bytesToCopy;
    }
}

@safe class InvalidOperationException : Exception
{
    this(string msg, string file = __FILE__, size_t line = __LINE__)
    {
        super(msg, file, line);
    }
}

@safe class UnitOperationException : Exception
{
    int returnCode;

    this(string msg, int returnCode, string file = __FILE__, size_t line = __LINE__)
    {
        this.returnCode = returnCode;
        auto message = msg ~ " with return code " ~ to!string(returnCode);
        super(message, file, line);
    }
}
