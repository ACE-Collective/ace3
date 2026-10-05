// Calling the ACE API (/api/v2, aceapi_v2) from a GUI page.
//
// The page's Flask session cookie authenticates the request; the API accepts a cookie-authenticated
// write only from this origin, which a same-origin fetch satisfies. Every call resolves to the
// parsed JSON body (null for an empty one) or rejects with an Error whose message is the API's
// own sentence rather than its envelope.

var aceApi = (function() {
    "use strict";

    const BASE = "/api/v2";

    // FastAPI reports a failure as {"detail": "..."}, {"detail": {"message": "..."}} or, for a
    // body that fails validation, {"detail": [{"loc": [...], "msg": "..."}, ...]}
    function error_message(text, response) {
        try {
            const detail = JSON.parse(text).detail;
            if (typeof detail === "string") {
                return detail;
            }
            if (Array.isArray(detail)) {
                return detail.map(function(error) { return error.msg || JSON.stringify(error); }).join("; ");
            }
            if (detail && typeof detail.message === "string") {
                return detail.message;
            }
        } catch (e) {
            // not JSON; fall through to the raw text
        }
        return text || response.statusText || ("request failed: " + response.status);
    }

    function request(method, path, body) {
        const options = {method: method, credentials: "same-origin", headers: {}};
        if (body !== undefined) {
            options.headers["Content-Type"] = "application/json";
            options.body = JSON.stringify(body);
        }

        return fetch(BASE + path, options).then(function(response) {
            return response.text().then(function(text) {
                if (!response.ok) {
                    throw new Error(error_message(text, response));
                }
                return text ? JSON.parse(text) : null;
            });
        });
    }

    // a query string from an object; an array value repeats its key (?f=a&f=b)
    function query(params) {
        const search = new URLSearchParams();
        Object.keys(params || {}).forEach(function(key) {
            const value = params[key];
            if (value === undefined || value === null) {
                return;
            }
            (Array.isArray(value) ? value : [value]).forEach(function(item) { search.append(key, item); });
        });
        const text = search.toString();
        return text ? "?" + text : "";
    }

    return {
        BASE: BASE,
        request: request,
        query: query,
        get: function(path) { return request("GET", path); },
        post: function(path, body) { return request("POST", path, body); },
        put: function(path, body) { return request("PUT", path, body); },
        patch: function(path, body) { return request("PATCH", path, body); },
        del: function(path) { return request("DELETE", path); },
    };
})();
