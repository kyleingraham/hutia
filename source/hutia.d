import core.stdc.string : memcpy;
import eventcore.driver : IOMode;
import ldc.intrinsics : llvm_expect;
import std.algorithm.comparison : min;
import std.array : Appender;
import std.concurrency : thisTid;
import std.conv : to;
import std.exception : enforce;
import std.format : format;
import std.string : toStringz;
import std.typecons : Nullable;
import unit_integration;
import vibe.container.dictionarylist : DictionaryList;
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
		handler_ = handler;
		return this;
	}

	int run()
	{
		webAppContext = new WebApplicationContext(handler_);
		return (() @trusted => runUnit(webAppContext))();
	}
}

alias RequestFunction = extern(C) string function(HttpContext) @safe;

extern(C)
@safe struct WebApplicationContext
{
	RequestFunction handler;
}

package int runUnit(WebApplicationContext* webAppContext) @system
{
	nxt_unit_init_t init;
	init.callbacks.request_handler = &(unitRequestHandler);
    //init.callbacks.add_port        = &(unitAddPort); // OPTIONAL
    //init.callbacks.remove_port     = &(unitRemovePort); // OPTIONAL
    //init.callbacks.port_send       = &(unitPortSend); // OPTIONAL
    //init.callbacks.port_recv       = &(unitPortReceive); // OPTIONAL
    //init.callbacks.shm_ack_handler = &(unitShmAckHandler); // OPTIONAL
    init.callbacks.ready_handler   = &(unitReadyHandler);

    nxt_unit_ctx_t* unitContext = nxt_unit_init(&init);
    if (unitContext is null)
        return NXT_UNIT_ERROR;

    unitContext.data = cast(void*)webAppContext;

 	auto rc = nxt_unit_run(unitContext);
    nxt_unit_done(unitContext);
	return rc;
}

extern(C)
package void unitRequestHandler(nxt_unit_request_info_t* requestInfo) @safe
{
	auto httpContext = HttpContext.create(requestInfo);
	scope (exit) httpContext.response.complete();
	auto webAppContext = (() @trusted => cast(WebApplicationContext*)requestInfo.ctx.data)();
	try
	{
		httpContext.response.body.write(
			webAppContext.handler(httpContext)
		);
	}
	catch (Exception e)
	{
		// Any uncaught exception while writing the repsonse should result in the request being finalized gracefully.
		// Ideally there is another layer above this ensuring the status code is updated to a 500.
		// Uncaught exceptions will break Unit.
		auto responseSent = (() @trusted => nxt_unit_response_is_sent(requestInfo))();
		logUnit(requestInfo.ctx, UnitLogLevel.debug_, format("unitRequestHandler - Response sent? %s", responseSent));
		auto message = (() @trusted => format("unitRequestHandler - %s", e))();
		logUnit(requestInfo.ctx, UnitLogLevel.error, message);
	}
}

extern(C)
package int unitReadyHandler(nxt_unit_ctx_t* unitContext) @safe
{
	return NXT_UNIT_OK;
}

package void appWorker(nxt_unit_ctx_t* unitContext) @trusted
{
	nxt_unit_run(unitContext);
	nxt_unit_done(unitContext);
}

package void logUnit(nxt_unit_ctx_t* unitContext, UnitLogLevel logLevel, string message) @trusted
{
	nxt_unit_log(unitContext, logLevel, ("[D] " ~ message).toStringz);
}

void logError(HttpContext httpContext, string message) @trusted
{
	logUnit(httpContext.request.requestInfo.ctx, UnitLogLevel.error, message);
}

package enum UnitLogLevel : uint 
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

	static HttpContext create(nxt_unit_request_info_t* requestInfo)
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
}

@safe class HttpRequest
{
	immutable string path;
	immutable string method;
	immutable HttpHeadersDictionary headers;
	private 
	{	
		InputStream _body;
		nxt_unit_request_info_t* requestInfo;
	}

	private this(nxt_unit_request_info_t* requestInfo, string path, string method, HttpHeadersDictionary headers)
	{
		this.requestInfo = requestInfo;
		this.path = path;
		this.method = method;
		this.headers = (() @trusted => cast(immutable(HttpHeadersDictionary))headers)();
		_body = new HttpRequestBodyStream(this.requestInfo);
	}

	static HttpRequest create(nxt_unit_request_info_t* requestInfo)
	{
		auto unitRequest = requestInfo.request;
		auto path = (() @trusted => getString(&unitRequest.target, unitRequest.target_length))();
		auto method = (() @trusted => getString(&unitRequest.method, unitRequest.method_length))();
		auto headers = getHeaders(unitRequest);
		auto httpRequest =  new HttpRequest(requestInfo, path, method, headers);
		return httpRequest;
	}

	InputStream body()
	{
		return _body;
	}

	Nullable!ulong contentLength()
	{
		string contentLength = this.headers.get("Content-Length");
		if (contentLength == string.init)
			return Nullable!ulong();

		return Nullable!ulong(to!ulong(contentLength));
	}

	override string toString()
	{
		return "HttpRequest(\"" ~ method ~ "\", \"" ~ path ~ "\")";
	}
}

package string getString(nxt_unit_sptr_t* serializedPointer, size_t length) @system
{
	auto start = nxt_unit_sptr_get(serializedPointer);
	return cast(string)(start[0..length]);
}

package HttpHeadersDictionary getHeaders(nxt_unit_request_t* unitRequest) @safe
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

package nxt_unit_field_t* getField(nxt_unit_request_t* unitRequest, size_t fieldOffset) @system
{
	return cast(nxt_unit_field_t*)unitRequest.fields + fieldOffset;
}

package @safe class HttpRequestBodyStream : InputStream
{
	private 
	{
		nxt_unit_request_info_t* requestInfo;
		Nullable!ulong contentLength;
		bool isEmpty = false;
		ulong position;
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
		// Our stream has no internal buffer so we return an empty slice (as per the InputStream API).
		return [];
	}

	ulong read(scope ubyte[] dst, IOMode mode)
	{
		if (empty)
			return 0;

		auto bytesRead = (() @trusted => nxt_unit_request_read(requestInfo, dst.ptr, dst.length))();

		if (bytesRead < 0)
			throw new UnitRequestReadException("nxt_unit_request_read return code=" ~ to!string(bytesRead));

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
}

package Nullable!ulong getContentLength(nxt_unit_request_t* unitRequest) @safe
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
		requestInfo_ = requestInfo;
		body_ = new HttpResponseBody(this);
		headers_ = new HttpResponseHeaders(this);
	}

	static HttpResponse create(nxt_unit_request_info_t* requestInfo)
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
		enforce!InvalidOperationException(!hasStarted, "Cannot write headers for a request more than once");

		headers_.setDefault("Content-Type", "text/html; charset=utf-8");

		hasStarted_ = true;

		enforce!InvalidOperationException(headers_.count < uint.max, "Header count larger than Unit's max");
		enforce!InvalidOperationException(headers_.length < uint.max, "Header key value length larger than Unit's max");

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
			enforce!InvalidOperationException(key.length < ubyte.max, format("Header key longer than Unit's max: %s", key));
			enforce!InvalidOperationException(value.length < uint.max, format("Header value larger than Unit's max: %s", value));

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
}

@safe class HttpResponseHeaders
{
	private
	{
		HttpHeadersDictionary httpHeaders_;
		HttpResponse httpResponse;
		ulong length_;
	}

	this(HttpResponse httpResponse)
	{
		this.httpResponse = httpResponse;
		httpHeaders_ = HttpHeadersDictionary();
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

	size_t count()
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

	ulong length()
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

alias HttpHeadersDictionary = DictionaryList!(string,false,12L,false);

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
		
		enforce!InvalidOperationException(!hasFinalized, "Cannot write to the body of a complete response");

		auto rc = sendResponse(httpResponse.requestInfo(), response);
		if (llvm_expect(rc != NXT_UNIT_OK, 0))
			finalize(rc, "Writing response body failed");
	}

	private void finalize(int unitReturnCode, string message)
	{
		if (hasFinalized)
			return;

		hasFinalized = true;

		(() @trusted => nxt_unit_request_done(httpResponse.requestInfo(), unitReturnCode))();
		if (unitReturnCode != NXT_UNIT_OK)
			throw new UnitOperationException(message, unitReturnCode); // Halt further response processing now that we have cleaned up the response.
	}
}

package int sendResponse(nxt_unit_request_info_t* requestInfo, string response) @safe
{
	nxt_unit_read_info_t readInfo = nxt_unit_read_info_t.init;
	readInfo.read = &(writeResponseCallback);
    readInfo.eof = 0;
    readInfo.buf_size = 8192;
    auto data = new ResponseData(response);
    readInfo.data = cast(void*)data;
    return (() @trusted => nxt_unit_response_write_cb(requestInfo, &readInfo))();
}

extern(C)
package ptrdiff_t writeResponseCallback(nxt_unit_read_info_t *readInfo, void *destination, size_t size) @safe
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
package @safe struct ResponseData
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

		if (llvm_expect(sourceStart < &this.data[0] || &this.data[$ - 1] < &this.data[start + bytesToCopy - 1], 0))
			return -1; // Source out of bounds access.

		(() @trusted => memcpy(dst, cast(void*)(sourceStart), bytesToCopy))();
		position += bytesToCopy;
		return bytesToCopy;
	}
}

@safe class InvalidOperationException : Exception
{
    this(string msg, string file = __FILE__, size_t line = __LINE__) {
        super(msg, file, line);
    }
}

@safe class UnitOperationException : Exception
{
	int returnCode;

	this(string msg, int returnCode, string file = __FILE__, size_t line = __LINE__) {
		this.returnCode = returnCode;
		auto message = msg ~ " with return code " ~ to!string(returnCode);
        super(message, file, line);
    }
}