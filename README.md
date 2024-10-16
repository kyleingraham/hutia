# Hutia  
A web framework built on [NGINX Unit](https://unit.nginx.org).

There aren't many features today and the API isn't anywhere near stable. Hutia's main purpose for now is to provide a place to:  
- Learn what goes into making a performant web framework.
- Explore NGINX Unit's application server API

## Examples
If you would like to see Hutia in action, take a look at the [examples](examples) folder. There you will find demonstration apps for Hutia's features.

## NGINX Unit Integration Details  
NGINX Unit provides a C API for integrating frameworks directly with Unit's lifecycle. After integration, one can build applications that can be directly managed by Unit which brings:
- [dynamic scaling](https://unit.nginx.org/configuration/#application-processes)
- [performance statistics](https://unit.nginx.org/statusapi/#configuration-stats)
- [process isolation](https://unit.nginx.org/configuration/#configuration-proc-mgmt-isolation)
- [dynamic configuration](https://unit.nginx.org/controlapi/#configuration-api)
- [and many more features](https://unit.nginx.org/keyfeatures/#)

### C API
The overall flow for using the Unit C API is as follows:
- Provide a main function that performs any initialization your application requires. Unit will run your main when it starts your application executable.
- Initialize Unit with callback functions for key parts of Unit's request/response lifecycle.
- Transfer control to Unit with optional context data that you can later load within your callbacks.
- Respond to requests using your callbacks.
- Shutdown Unit once it returns control to your application.
- Cleanup your application.

Key considerations:
- You must prevent exceptions crossing into C. Catch all exceptions and convert them into return codes for Unit's C API.
- Don't interfere with the event loop. This is hard to run afoul of but I found that using D's standard library logger breaks Unit unrecoverably (and I do not know why).
- You must close Unit's requests. Failing to do so results in hung clients.

Do the above and you should have nothing but smooth sailing.

Unit's C API is accessed through the following headers:
- `nxt_unit.h`
- `nxt_unit_request.h`

### How Hutia Interacts with Unit
### Setup
Hutia first initializes a `nxt_unit_init_t` struct. This struct contains a `callbacks` member on which you should store references to your callbacks. My current understanding of `nxt_unit_init_t.callbacks` is as follows:
- `callbacks.request_handler`
    - Signature: `extern(C) void function(nxt_unit_request_info_t*)` 
    - Purpose: Called whenever Unit has a request that is ready for processing.
    - Required?: Yes.
- `callbacks.ready_handler`
    - Signature: `extern(C) int function(nxt_unit_ctx_t*)`
    - Purpose: Called after Unit is ready. Here you can perform further application setup e.g. [spawn worker threads](https://github.com/nginx/unit/blob/cc2a1cc3651593fbc5ede99ceab8161c364998f3/src/test/nxt_unit_app_test.c#L110). Return `NXT_UNIT_OK` on success. Unit will loop forever should you return `NXT_UNIT_ERROR` (why this happens is unclear).
    - Required?: No.

All other callbacks are optional but I am unclear on their purposes.

After setting up callbacks, Hutia calls `nxt_unit_init` with a reference to the `nxt_unit_init_t` struct. `nxt_unit_init` returns a `nxt_unit_ctx_t*` context struct that will be null on failure. Hutia will abort in this case. If the struct is valid, Hutia stores its own context data on the struct's `void*` `data` member.

It is now time to run Unit. Hutia calls `nxt_unit_run` with the `nxt_unit_ctx_t*` setup previously. This gives control to Unit and interaction with it from here on will be through callbacks until Unit transfers control back to Hutia.

### Request Handling
When Unit has a request that is ready for processing it will call the request handler callback registered by Hutia. The `nxt_unit_request_info_t*` provided by Unit has everything needed to service the request.

#### Request Metadata  
Hutia first extracts information on the request. Each `nxt_unit_request_info_t*` has a `request` member consisting mainly of strings representing items like request path and method. To fetch pointers to the strings you must call `nxt_unit_sptr_get` using a named pointer on the `request` member then convert the returned pointer to a string using the named pointer's corresponding length e.g. 
```D
auto start = nxt_unit_sptr_get(&requestInfo.request.method); 
auto method = cast(string)(start[0..requestInfo.request.method_length]);
```

Extracting header data is more involved but requires the same string fetching method as above. Unit stores the number of headers present in `nxt_unit_request_info_t.request.fields_count`. Hutia iterates `fields_count` times incrementing an offset starting from 0. Each field can then be fetched by creating a `nxt_unit_field_t*` using the result of summing `nxt_unit_request_info_t.request.fields` and the offset e.g.
```D
cast(nxt_unit_field_t*)requestInfo.request.fields + fieldOffset;
```

On the field returned, Hutia fetches header key/value strings using `name`, `name_length`. `value`, and `value_length`. The strings are saved to an internal dictionary of headers.

#### Request Body  
The overall flow for reading the request body is to, in a loop:
- Determine how much of the request body is available to be read.
- Read the available request body into your own buffer until Unit reports that there is no more body to read.

To determine how much of the request body is available to be read, Hutia first tries to read the request's content length. If that is not available, it checks Unit's buffers directly. 

Unit stores content length as a `nxt_unit_field_t*` at `nxt_unit_request_info_t.request.content_length_field` with a value of `NXT_UNIT_NONE_FIELD` if no content length is available. If one is available, Hutia reads it the same way header fields are. The difference in this case is that the offset is `content_length_field` and only `value` and `value_length` need to be used.

Unit stores body data that is ready for reading in a linked list of buffers starting at `nxt_unit_request_info_t.content_buf`. When there is no content length, Hutia traverses this list until a `null` buffer is found using `nxt_unit_buf_next`. At each buffer Hutia sums `buffer.end - buffer.free`. 

Once Hutia has successfully determined how much response body is available, it creates a buffer of appropriate length, copies into it using `nxt_unit_request_read`, then repeats the process of determining the number of body bytes available and copying bytes into Hutia's buffers until no more are present.

#### Response Metadata  
The overall flow for setting request metadata is:
- Initialize the response.
- Set header values.
- Send the partially constructed response.

Key considerations:
- You must close out Unit responses immediately on encountering any return code outside `NXT_UNIT_OK` from Unit's API. Failing to do so results in hung clients. 

To initialize the response, Hutia calls `nxt_unit_response_init`. In addition to a `nxt_unit_request_info_t*`, it requires a status code, the number of headers being sent, and the length of all header key-value pair strings. If `nxt_unit_response_init` returns an error, Hutia calls `nxt_unit_request_done` with a `nxt_unit_request_info_t*` and the error. This closes the response with Unit and with the client. While writing responses, this step follows all Unit API calls.

Once the response is initialized, Hutia then writes header values using `nxt_unit_response_add_field` supplying a `nxt_unit_request_info_t*`, a header key null-terminated string and its length, and a header value null-terminated string and its length. As above, errors here result in calls to `nxt_unit_request_done`.

After all header values have been set, Hutia calls `nxt_unit_response_send` to begin sending ready request components to the client.

#### Response Body  
To write and send the response body, Hutia uses Unit's callback-based `nxt_unit_response_write_cb` method. One difficult part about writing responses in Unit is knowing when Unit is ready to accept data. `nxt_unit_response_write_cb` inverts control of when writes happen by accepting a callback for writing data at times that Unit chooses.  

`nxt_unit_response_write_cb` accepts a `nxt_unit_request_info_t*` and a `nxt_unit_read_info_t*`. On `nxt_unit_read_info_t` Hutia sets a buffer size for reading data to be written via `buf_size`, the data to be written on `data`, and a callback for writing to Unit's buffers on `read`. 

Unit calls the given callback with the `nxt_unit_read_info_t` that Hutia configured, a destination buffer, and a maximum number of bytes to write to the buffer. Hutia performs checks to prevent out of bounds access then uses `memcpy` to write to Unit.

Once all of the body is written Hutia calls `nxt_unit_request_done` as described earlier to close the response.

### Cleanup
Cleanup is simple with Unit. On shutdown, Unit will return from `nxt_unit_run`, returning control to Hutia. At this time, Hutia calls `nxt_unit_done` with the `nxt_unit_ctx_t*` created at startup to shutdown its link with Unit then returns from main to exit to the OS.