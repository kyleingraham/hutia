import core.stdc.string : memcpy;
import eventcore.driver : IOMode;
import std.algorithm : startsWith;
import std.algorithm.comparison : min;
import std.algorithm.searching : endsWith;
import std.array : Appender, join, split;
import std.concurrency : ownerTid, receive, receiveOnly, spawn;
import std.conv : to;
import std.exception : enforce;
import std.format : format;
import std.range : empty;
import std.regex : matchFirst, regex, Regex;
import std.string : toStringz;
import std.traits : isCallable, Parameters, ParameterIdentifierTuple, ReturnType;
import std.typecons : Nullable, tuple, Tuple;
import std.uuid : UUID;
import std.variant : Variant;
import unit_integration;
import vibe.container.dictionarylist : DictionaryList;
import vibe.core.concurrency : send;
import vibe.core.core : exitEventLoop, runApplication, runTask;
import vibe.core.log : logTrace;
import vibe.core.task : Task;
import vibe.core.stream : InputStream;
import vibe.http.common : HTTPMethod, httpMethodFromString;
import vibe.inet.webform : parseURLEncodedForm;

@safe class WebApplication
{
    private
    {
        Router router;
    }

    this()
    {
        router = new Router();
    }

    static WebApplication create()
    {
        return new WebApplication();
    }

    EndpointCustomizer mapGet(alias handler)(string routeTemplate)
    {
        return router.mapImpl!(handler)(routeTemplate, HTTPMethod.GET);
    }

    int run() @trusted
    {
        (() @trusted => spawn(&runUnit))();

        dispatcherTask = runTask(
            &runDispatcher,
            router.toImmutable()
        );

        runApplication();

        return (() @trusted => receiveOnly!int)();
    }
}

private shared Task dispatcherTask;

private void runDispatcher(immutable(Router) router) @safe nothrow
{
    bool shouldRun = true;

    while (shouldRun)
    {
        void requestInfoHandler(RequestInfoMessage message)
        {
            dispatch(message, router);
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

private struct RequestInfoMessage
{
    shared nxt_unit_request_info_t* requestInfo;
}

private struct CancelMessage{}

nxt_unit_request_info_t* getRequestInfo(
    shared(nxt_unit_request_info_t*) requestInfo
) @trusted
{
    /**
     * We would normally keep this shared and access it through sychronized blocks.
     * sychronized won't do much for us here though because Unit retains control
     * of the pointer. We are trusting in Unit's management of it while we have it.
     * We are also retaining a single-threaded model for Hutia.
     * */
    return cast(nxt_unit_request_info_t*)requestInfo;
}

private void dispatch(RequestInfoMessage message, immutable(Router) router) @safe
{
    runTask((nxt_unit_request_info_t* requestInfo, immutable(Router) router) nothrow {
        try
        {
            auto httpContext = new HttpContext(requestInfo);
            // TODO: should middleware complete?
            scope(exit) httpContext.response.complete();

            auto handler = router.getHandler(httpContext);

            if (handler.isNull)
            {
                // TODO: move this to middleware
                if (!httpContext.response.hasStarted)
                    httpContext.response.statusCode = 404;
            }
            else
                handler.get()(httpContext);
        }
        catch (Exception e)
        {
            /**
             * Any uncaught exception while writing the repsonse should result in the
             * request being finalized gracefully. Ideally there is another layer above
             * this ensuring the status code is updated to a 500. Uncaught exceptions
             * will break Unit. TODO: move this to middleware
             * */
            auto message = (() @trusted => getExceptionMessage(e))();
            logUnit(requestInfo.ctx, UnitLogLevel.alert, message);
        }
    }, getRequestInfo(message.requestInfo), router);
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

private alias RequestFunction = string function(HttpContext) @safe;

private void runUnit() @system
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
    send(dispatcherTask, CancelMessage());
    send(ownerTid, rc);
}

extern(C)
private void unitRequestHandler(nxt_unit_request_info_t* requestInfo) @system
{
    // We are trusting that Unit manages this pointer safely after passing it to us.
    auto sharedRequestInfo = cast(shared)requestInfo;
    auto message = RequestInfoMessage(sharedRequestInfo);

    send(dispatcherTask, message);
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

    this(nxt_unit_request_info_t* requestInfo)
    {
        request_ = new HttpRequest(requestInfo);
        response_ = new HttpResponse(requestInfo);
    }

    HttpRequest request()
    {
        return request_;
    }

    HttpResponse response()
    {
        return response_;
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
        string[string] routeValues_;
        Nullable!QueryStringDictionary queryString_;
        nxt_unit_request_info_t* requestInfo;
    }

    this(nxt_unit_request_info_t* requestInfo)
    {
        this.requestInfo = requestInfo;
        auto requestValues = getRequestValues(this.requestInfo);
        path_ = requestValues.path;
        method_ = requestValues.method;
        headers_ = requestValues.headers;
        body_ = new HttpRequestBodyStream(this.requestInfo);
    }

    private static RequestValues getRequestValues(
        nxt_unit_request_info_t* requestInfo
    )
    {
        auto unitRequest = requestInfo.request;
        auto path = (() @trusted => getString(
            &unitRequest.path, unitRequest.path_length
        ))();
        auto method = (() @trusted => getString(
            &unitRequest.method, unitRequest.method_length
        ))();
        auto headers = getHeaders(unitRequest);

        return RequestValues(
            path, method, headers
        );
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

    const(QueryStringDictionary) queryString()
    {
        QueryStringDictionary temp;

        if (queryString_.isNull)
        {
            auto unitQuery = (() @trusted => getString(
                &requestInfo.request.query, requestInfo.request.query_length
            ))();
            parseURLEncodedForm(unitQuery, temp);
            queryString_ = temp;
        }

        return queryString_.get();
    }

    const(string[string]) routeValues()
    {
        return routeValues_;
    }

    override string toString()
    {
        return "HttpRequest(\"" ~ method ~ "\", \"" ~ path ~ "\")";
    }
}

alias QueryStringDictionary = DictionaryList!(string,true,16L,false);

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
            if (contentLength.get > position)
                return contentLength.get - position;
            else
                return 0;
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

    this(nxt_unit_request_info_t* requestInfo)
    {
        body_ = new HttpResponseBody(this);
        headers_ = new HttpResponseHeaders(this);
        requestInfo_ = requestInfo;
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

        if (!statusCode_)
            statusCode_ = 200;

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
        if (rc != NXT_UNIT_OK)
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
            if (rc != NXT_UNIT_OK)
                body.finalize(rc, "Adding header to response failed");
        }

        rc = nxt_unit_response_send(requestInfo);
        if (rc != NXT_UNIT_OK)
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
}

private @safe class HttpResponseHeaders
{
    private
    {
        HttpHeadersDictionary httpHeaders_;
        HttpResponse httpResponse;
        ulong length_;
    }

    this(HttpResponse httpResponse)
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
}

private alias HttpHeadersDictionary = DictionaryList!(string,false,12L,false);

@safe class HttpResponseBody
{
    private
    {
        bool hasFinalized = false;
        HttpResponse httpResponse;
    }

    this(HttpResponse httpResponse)
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
        if (rc != NXT_UNIT_OK)
            finalize(rc, "Writing response body failed");
    }

    private void finalize(int unitReturnCode, string message)
    {
        if (hasFinalized)
            return;

        hasFinalized = true;

        if (!httpResponse.hasStarted)
            (() @trusted => httpResponse.writeHeaders())();

        (() @trusted => nxt_unit_request_done(
            httpResponse.requestInfo(),
            unitReturnCode
        ))();
        if (unitReturnCode != NXT_UNIT_OK)
            // Halt further response processing now that we have cleaned up the response.
            throw new UnitOperationException(message, unitReturnCode);
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
        if (maxBytes < bytesToCopy)
            return -1; // Destination out of bounds access.

        auto accessingSourceOob = (
            sourceStart < &this.data[0] ||
            &this.data[$ - 1] < &this.data[start + bytesToCopy - 1]
        );
        if (accessingSourceOob)
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

/**
 * ROUTING
 * */

RouteConstraint[] defaultRouteConstraints = [
    routeConstraint!int("int", "[0-9]+"),
    routeConstraint!string("string", "[^/]+"),
    routeConstraint!string("slug", "[-a-zA-Z0-9_]+"),
    routeConstraint!UUID(
        "uuid",
        "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    ),
    routeConstraint!string("path", ".+")
];

struct RouteConstraint
{
    string name;
    string regex;
    FromRouteDelegate fromRouteDelegate;
    ToRouteDelegate toRouteDelegate;
}

alias FromRouteDelegate = Variant delegate(string value) @safe;
alias ToRouteDelegate = string delegate(Variant value) @safe;

RouteConstraint routeConstraint(
    ConstraintType
)(string name, string regex) @safe
{
    FromRouteDelegate frd = (value) @trusted {
        return Variant(to!ConstraintType(value));
    };

    ToRouteDelegate trd = (value) @trusted {
        return to!string(value.get!ConstraintType());
    };

    return RouteConstraint(name, regex, frd, trd);
}

private @safe class TrieNode {
    string staticSegment;           // Fixed path segment (e.g. "hello")
    Regex!char dynamicSegmentRegex; // Regex for dynamic segments (e.g. <string:name>)
    string dynamicSegmentName;      // Name of a dynamic segment (e.g. "name")
    string dynamicConstraintKey;    // Constraint key for a dynamic segment (e.g. "string")
    TrieRouterHandler handler;      // Route handler if isTerminal=true
    TrieNode[string] children;      // Child nodes
    bool isTerminal;                // True if this node has no children

    this(string staticSegment = "") {
        this.staticSegment = staticSegment;
    }
}

private alias TrieRouterHandler = void delegate(
    HttpContext httpContext,
    CapturedValueData capturedValueData
) @safe;

private alias RouteParameter = string;
private alias RouteValue = string;
private alias RouteConstraintName = string;

private @safe struct CapturedValueData
{
    RouteValue[RouteParameter] capturedValues;
    RouteConstraintName[RouteParameter] capturedValueConstraints;
}

private alias TrieRouterMatch = Nullable!(
    Tuple!(
        TrieRouterHandler,
        "handler",
        CapturedValueData,
        "capturedValueData"
    )
);

private @safe class TrieRouter {
    private TrieNode root = new TrieNode();

    void addRoute(
        string routeTemplate,
        TrieRouterHandler handler,
        RouteConstraint[RouteConstraintName] constraints
    )
    {
        auto segments = routeTemplate.split('/');
        auto currentNode = root;

        foreach (segment; segments) {
            if (segment.empty) continue;

            if (segment.startsWith("{") && segment.endsWith("}"))
            {
                // Handle dynamic segments' route constraints
                // Dynamic nodes are reference by routeParameter
                auto parts = segment[1 .. $ - 1].split(':');
                string routeConstraintName;
                string routeParameter;

                if (parts.length == 2)
                {
                    routeParameter = parts[0];
                    routeConstraintName = parts[1];
                }
                else if (parts.length == 1)
                {
                    routeParameter = parts[0];
                    routeConstraintName = "string";
                }
                else
                    throw new ImproperlyConfigured(
                        format("Invalid route constraint %s", segment)
                    );

                auto routeConstraintPtr = routeConstraintName in constraints;
                if (!routeConstraintPtr)
                {
                    throw new ImproperlyConfigured(
                        "Route constraint for `" ~ routeConstraintName ~ "` not found"
                    );
                }
                auto routeConstraint = *routeConstraintPtr;

                if (!(routeParameter in currentNode.children))
                {
                    auto dynamicNode = new TrieNode();
                    dynamicNode.dynamicSegmentRegex = regex(routeConstraint.regex);
                    dynamicNode.dynamicSegmentName = routeParameter;
                    dynamicNode.dynamicConstraintKey = routeConstraintName;
                    currentNode.children[routeParameter] = dynamicNode;
                }

                currentNode = currentNode.children[routeParameter];
            } else
            {
                // Handle static segments
                // Static nodes are reference by segment
                if (!(segment in currentNode.children)) {
                    currentNode.children[segment] = new TrieNode(segment);
                }
                currentNode = currentNode.children[segment];
            }
        }

        // Terminal node so we set a handler
        currentNode.isTerminal = true;
        currentNode.handler = handler;
    }

    TrieRouterMatch match(string path) inout
    {
        auto segments = path.split('/');
        inout(TrieNode)* currentNode = &root;

        RouteValue[RouteParameter] capturedValues;
        RouteConstraintName[RouteParameter] capturedValueConstraints;

        foreach (segment; segments) {
            if (segment.empty) continue;

            bool matched = false;

            // Check static children
            auto childNode = segment in currentNode.children;
            if (childNode)
            {
                currentNode = &(*childNode);
                matched = true;
            }
            else
            {
                // Check dynamic children in trie
                foreach (key, _; currentNode.children)
                {
                    auto child = currentNode.children[key];
                    if (child.dynamicSegmentRegex !is Regex!char.init
                        && matchFirst(segment, child.dynamicSegmentRegex))
                    {
                        // We matched on a dynamic segment
                        // Save the route value against the route parameter
                        capturedValues[child.dynamicSegmentName] = segment;
                        // Save the constraint name against the route parameter
                        capturedValueConstraints[child.dynamicSegmentName] =
                            child.dynamicConstraintKey;
                        // Pointer to AA entry instead of loop variable.
                        // Helps with lifetime issues in loop.
                        currentNode = &currentNode.children[key];
                        matched = true;
                        break;
                    }
                }
            }

            if (!matched) {
                return TrieRouterMatch();
            }
        }

        if (currentNode.isTerminal)
        {
            return TrieRouterMatch(
                tuple!("handler", "capturedValueData")(
                    cast(TrieRouterHandler)currentNode.handler,
                    CapturedValueData(capturedValues, capturedValueConstraints)
                )
            );
        }

        return TrieRouterMatch();
    }
}

alias RouteName = string;

private @safe class Router
{
    private
    {
        RouteConstraint[RouteConstraintName] constraints;
        TrieRouter[HTTPMethod] routes;
    }

    this()
    {
        addRouteContraints();
    }

    private this(
        immutable RouteConstraint[RouteConstraintName] constraints,
        immutable TrieRouter[HTTPMethod] routes
    ) immutable
    {
        this.constraints = constraints;
        this.routes = routes;
    }

    immutable(Router) toImmutable() @system
    {
        return new immutable Router(
            cast(immutable)this.constraints,
            cast(immutable)this.routes
        );
    }

    Nullable!HandlerDelegate getHandler(HttpContext httpContext) inout
    {
        auto httpMethod = httpMethodFromString(httpContext.request.method);

        auto methodPresent = httpMethod in routes;

        if (methodPresent is null)
            return Nullable!HandlerDelegate();

        auto trieRouter = routes[httpMethod];
        auto trieRouterMatch = trieRouter.match(httpContext.request.path);
        if (trieRouterMatch.isNull)
            return Nullable!HandlerDelegate();

        auto capturedValueData = trieRouterMatch.get().capturedValueData;

        foreach (capturedValue; capturedValueData.capturedValues.byKeyValue())
            httpContext.request.routeValues_[capturedValue.key] = capturedValue.value;

        return Nullable!HandlerDelegate((httpContext) {
            trieRouterMatch.get().handler(httpContext, capturedValueData);
        });
    }

    EndpointCustomizer mapImpl(alias handler)(
        string routeTemplate,
        HTTPMethod httpMethod
    )
    {
        // ParameterIdentifierTuple returns empty strings. Alternatives do as well:
        // https://forum.dlang.org/post/mailman.1197.1379014886.1719.digitalmars-d-learn@puremagic.com
        // Apparently, identifiers aren't guaranteed for function pointers and delegates:
        // https://github.com/dlang/phobos/pull/3620

        static assert(isCallable!handler, handler, " must be a callable.");

        TrieRouterHandler trh = (httpContext, capturedValueData) @safe {
            static if (
                Parameters!(handler).length == 0
                && is(ReturnType!handler : string)
            )
            {
                httpContext.response.body.write(
                    handler()
                );
            }
            else static if (
                Parameters!(handler).length == 1
                && is(Parameters!handler[0] : HttpContext)
                && is(ReturnType!handler : string)
            )
            {
                httpContext.response.body.write(
                    handler(httpContext)
                );
            }
            else static if (
                1 < Parameters!(handler).length
                && is(ReturnType!handler : string)
            )
            {
                auto args = tuple!(Parameters!(handler));
                static if(is(typeof(handler) Params == __parameters))
                static foreach(idx, _; Params)
                {
                    static if (is(Params[idx] : HttpContext))
                        args[idx] = httpContext;
                    else static if (
                        0 < __traits(getAttributes, Params[idx .. idx + 1]).length
                        && is(typeof(__traits(getAttributes, Params[idx .. idx + 1])[0]) == FromRoute)
                    )
                    {
                        args[idx] = (
                            __traits(getAttributes, Params[idx .. idx + 1])[0].routeParameter is null ?
                            FromRoute(ParameterIdentifierTuple!handler[idx]) :
                            __traits(getAttributes, Params[idx .. idx + 1])[0]
                        ).get!(
                            Parameters!handler[idx]
                        )(
                            httpContext.request,
                            this,
                            capturedValueData
                        );
                    }
                    else
                        static assert(
                            0, Parameters!handler[idx], " is not a valid argument type"
                        );
                }

                httpContext.response.body.write(
                    handler(args.expand)
                );
            }
            else
                static assert(0, handler, " is not a valid handler");
        };

        auto methodPresent = httpMethod in routes;

        if (methodPresent is null)
            routes[httpMethod] = new TrieRouter();

        routes[httpMethod].addRoute(routeTemplate, trh, constraints);

        logTrace("Added %s route: %s", to!string(httpMethod), routeTemplate);

        rehashMaps();

        return new EndpointCustomizer();
    }

    private void rehashMaps() @trusted
    {
        constraints = constraints.rehash();
        routes = routes.rehash();
    }

    void addRouteContraints(RouteConstraint[] routeContraints = [])
    {
        // This method must be called before adding handlers.
        foreach (routeConstraint; [defaultRouteConstraints, routeContraints].join)
        {
            constraints[routeConstraint.name] = routeConstraint;
        }
    }
}

// https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.builder.routingendpointconventionbuilderextensions.withname?view=aspnetcore-8.0
@safe class EndpointCustomizer
{
    EndpointCustomizer withName(string name)
    {
        // TODO: implement
        return this;
    }
}

private alias HandlerDelegate = void delegate(
    HttpContext httpContext
) @safe;

@safe struct FromRoute
{
    string routeParameter;

    T get(T)(
        HttpRequest httpRequest,
        Router router,
        CapturedValueData capturedValueData
    )
    {
        // Set value from request route
        // At the time this is called there is no way we will have key errors
        // Route values will be in place
        // TODO: How did this compile with `HttpRequest HttpRequest` in the constructor?
        // TODO: Better message for non-existent route/query name.
        auto routeConstraintName =
            capturedValueData.capturedValueConstraints[routeParameter];
        auto routeConstraint = router.constraints[routeConstraintName];
        return (() @trusted => routeConstraint.fromRouteDelegate(
            httpRequest.routeValues[routeParameter]
        ).get!T())();
    }
}

class ImproperlyConfigured : Exception
{
    this(string msg, string file = __FILE__, size_t line = __LINE__) @safe
    {
        super(msg, file, line);
    }
}
