#include "proxy.h"
#include <string.h>
#include <stdio.h>

// TODO: turn this into a real client library (maybe)
void http_handle(uint32_t arg, uint32_t arg0) {

}

typedef struct HttpResponse {
    int err;
    int statusCode;
} http_response_t;

http_response_t request(uint8_t method_tag, uint8_t scheme_tag, const char *authority_str, const char* path_str, const char* query_str, const char* body, char* buffer, size_t buffer_len) {
    http_response_t result = {
        .err = true,
        .statusCode = 0,
    };
    types_tuple2_string_string_t content_type[] = {{
        .f0 = { .ptr = "User-agent", .len = 10 },
        .f1 = { .ptr = "WASI-HTTP/0.0.1", .len = 15},
    }};
    types_list_tuple2_string_string_t headers_list = {
        .ptr = &content_type[0],
        .len = 1,
    };
    types_fields_t headers = types_new_fields(&headers_list);
    types_method_t method = { .tag = method_tag };
    types_scheme_t scheme = { .tag = scheme_tag };
    proxy_string_t path, authority, query;
    proxy_string_set(&path, path_str);
    proxy_string_set(&authority, authority_str);
    proxy_string_set(&query, query_str);

    default_outgoing_http_outgoing_request_t req = types_new_outgoing_request(&method, &path, &query, &scheme, &authority, headers);
    default_outgoing_http_future_incoming_response_t res;

    if (req == 0) {
        result.err = 1;
        return result;
    }
    if (body != NULL) {
        types_outgoing_stream_t ret;
        if (!types_outgoing_request_write(req, &ret)) {
            result.err = 2;
            return result;
        }
        streams_list_u8_t buf = {
            .ptr = (uint8_t *) body,
            .len = strlen(body),
        };
        uint64_t ret_val;
        streams_write(ret, &buf, &ret_val, NULL);
    }

    res = default_outgoing_http_handle(req, NULL);
    if (res == 0) {
        result.err = 3;
        return result;
    }
    
    types_result_incoming_response_error_t result_err;
    if (!types_future_incoming_response_get(res, &result_err)) {
        result.err = 4;
        return result;
    }

    if (result_err.is_err) {
        result.err = 5;
        return result;
    }
    // poll_drop_pollable(res);

    types_status_code_t code = types_incoming_response_status(result_err.val.ok);
    result.statusCode = code;

    types_headers_t header_handle = types_incoming_response_headers(result_err.val.ok);
    types_list_tuple2_string_string_t header_list;
    types_fields_entries(header_handle, &header_list);

    for (int i = 0; i < header_list.len; i++) {
        char name[128];
        char value[128];
        strncpy(name, header_list.ptr[i].f0.ptr, header_list.ptr[i].f0.len);
        name[header_list.ptr[i].f0.len] = 0;
        strncpy(value, header_list.ptr[i].f1.ptr, header_list.ptr[i].f1.len);
        value[header_list.ptr[i].f1.len] = 0;
    }


    types_incoming_stream_t stream;
    if (!types_incoming_response_consume(result_err.val.ok, &stream)) {
        result.err = 6;
        return result;
    }

    int32_t len = 64 * 1024;
    streams_tuple2_list_u8_bool_t body_res;
    streams_stream_error_t err;
    if (!streams_read(stream, len, &body_res, &err)) {
        result.err = 7;
        return result;
    }
    streams_tuple2_list_u8_bool_free(&body_res);
    strncpy(buffer, (const char*)body_res.f0.ptr, buffer_len);

    types_drop_outgoing_request(req);
    streams_drop_input_stream(stream);
    types_drop_incoming_response(result_err.val.ok);

    result.err = 0;
    return result;
}

http_response_t get(const char* url, const char* headers, char* buffer, size_t length) {
    char host[100];
    char path[100];

    char* host_ix = strstr(url, "://");
    char* path_ix = strstr(host_ix + 4, "/");
    char* query_ix = strstr(url, "?");

    int i;
    for (i = 0; i < path_ix - host_ix - 3; i++) {
        host[i] = *(host_ix + 3 + i);
    }
    host[i] = 0;

    const char* end = query_ix == NULL ? url + strlen(url) : query_ix;
    for (i = 0; i < end - path_ix; i++) {
        path[i] = *(path_ix + i);
    }
    path[i] = 0;

    return request(TYPES_METHOD_GET, TYPES_SCHEME_HTTPS, host, path, query_ix, NULL, buffer, length);
}

int main() {
    const char* url =  "https://postman-echo.com/get";
    const char* headers = "Content-type: text/html\nUser-agent: wasm32-wasi-http";
    size_t length = 1024 * 1024;
    char* buffer = (char*) malloc(length);
    http_response_t resp = get(url, headers, buffer, length);

    if (resp.err) {
        printf("Request Failed: (%d)\n", resp.err);
    } else {
        printf("Request succeeded: %d\n", resp.statusCode);
        printf("%s\n", buffer);
    }
    free(buffer);
}