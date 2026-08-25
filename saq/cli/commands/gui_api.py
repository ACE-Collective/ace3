import argparse
import logging
import os
import sys

from saq.cli.cli_main import get_cli_subparsers


# ============================================================================
# start GUI (non-apache version)
#

def create_api_v2_proxy():
    """Create a WSGI app that proxies requests to the FastAPI v2 API server.

    DispatcherMiddleware strips the /api/v2 prefix before calling this app,
    so PATH_INFO will be e.g. /observable-types/ which matches FastAPI routes
    directly.
    """
    import urllib.request
    import urllib.error

    api_host = os.environ.get('ACE_API_V2_HOST', 'http-api-v2')
    api_port = os.environ.get('ACE_API_V2_PORT', '3032')

    def proxy_app(environ, start_response):
        method = environ.get('REQUEST_METHOD', 'GET')
        path = environ.get('PATH_INFO', '/')
        query_string = environ.get('QUERY_STRING', '')
        url = f'http://{api_host}:{api_port}{path}'
        if query_string:
            url = f'{url}?{query_string}'

        # Read the request body if present
        content_length = environ.get('CONTENT_LENGTH')
        body = None
        if content_length:
            try:
                body = environ['wsgi.input'].read(int(content_length))
            except (ValueError, KeyError):
                pass

        # Forward the incoming headers. A previous version copied only Content-Type, Cookie and
        # Accept, which silently dropped the headers the API relies on: Origin/Sec-Fetch-Site (used
        # to reject cross-site cookie-authenticated writes) and Authorization/x-ace-auth (header
        # auth). Forward everything except hop-by-hop headers, which are per-connection.
        hop_by_hop = {
            'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
            'te', 'trailer', 'transfer-encoding', 'upgrade', 'host', 'content-length',
        }
        headers = {}
        for env_key, env_value in environ.items():
            if not env_key.startswith('HTTP_'):
                continue
            header_name = env_key[len('HTTP_'):].replace('_', '-').title()
            if header_name.lower() in hop_by_hop:
                continue
            headers[header_name] = env_value

        if environ.get('CONTENT_TYPE'):
            headers['Content-Type'] = environ['CONTENT_TYPE']

        # urllib rewrites Host to the upstream, so pass the browser-facing host separately: the API
        # compares it against Origin when deciding whether a cookie-authenticated write is same-origin
        if environ.get('HTTP_HOST'):
            headers['X-Forwarded-Host'] = environ['HTTP_HOST']

        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            resp = urllib.request.urlopen(req)
            status = f'{resp.status} {resp.reason}'
            resp_headers = [(k, v) for k, v in resp.getheaders() if k.lower() not in ('transfer-encoding',)]
            resp_body = resp.read()
            start_response(status, resp_headers)
            return [resp_body]
        except urllib.error.HTTPError as e:
            status = f'{e.code} {e.reason}'
            resp_headers = [(k, v) for k, v in e.headers.items() if k.lower() not in ('transfer-encoding',)]
            resp_body = e.read()
            start_response(status, resp_headers)
            return [resp_body]
        except (urllib.error.URLError, OSError) as e:
            start_response('502 Bad Gateway', [('Content-Type', 'text/plain')])
            return [f'API v2 proxy error: {e}'.encode()]

    return proxy_app

def start_gui(args):
    from app import create_app
    from werkzeug.serving import run_simple
    from werkzeug.middleware.dispatcher import DispatcherMiddleware
    from werkzeug.wrappers import Response

    def not_found(environ, start_response):
        response = Response("unknown page", status=404)
        return response(environ, start_response)

    app = create_app()
    app.jinja_env.auto_reload = True
    app.config['TEMPLATES_AUTO_RELOAD'] = True
    app.config['DEBUG'] = True
    #app.config['APPLICATION_ROOT'] = '/ace'
    app.config['SESSION_COOKIE_PATH'] = '/'
    app.wsgi_app = DispatcherMiddleware(not_found, {
        "/ace": app.wsgi_app,
        "/api/v2": create_api_v2_proxy(),
    })

    # add the "do" template command
    app.jinja_env.add_extension('jinja2.ext.do')

    if args.print_uri_paths:
        for rule in app.url_map.iter_rules():
            print(rule)
        sys.exit(0)

    # This ensures that the development environment returns unique objects every time something in the GUI
    # uses get_db().query() to fetch something from the database. Without this, it would serve stale data to
    # the application. For instance, this is the cause in the development containers of sometimes the event
    # pages saying "Alerts are still analyzing" and not showing FA Queue results when in fact the alerts
    # were finished analyzing.
    #get_db() = get_db().session

    from saq.configuration import get_config

    logging.info("ssl_cert = %s exists %s", get_config().gui.ssl_cert, os.path.exists(get_config().gui.ssl_cert))
    logging.info("ssl_key = %s exists %s", get_config().gui.ssl_key, os.path.exists(get_config().gui.ssl_key))

    listen_address = args.address or get_config().gui.listen_address
    listen_port = args.port or get_config().gui.listen_port
    #run_simple(get_config().gui.listen_address, get_config().gui.listen_port, app,
    run_simple(listen_address, listen_port, app,
               ssl_context=(get_config().gui.ssl_cert, get_config().gui.ssl_key),
               #ssl_context="adhoc",
               use_reloader=True)

# start-gui
start_gui_parser = get_cli_subparsers().add_parser('start-gui',
    help="Start the SAQ GUI.")
start_gui_parser.add_argument('args', nargs=argparse.REMAINDER,
    help="Parameters to pass to the GUI command shell.")
start_gui_parser.add_argument("--address", default=None, help="Address to bind to. Defaults to configuration setting.")
start_gui_parser.add_argument("--port", default=None, type=int, help="Port to bind to. Defaults to configuration setting.")
start_gui_parser.add_argument('--print-uri-paths', default=False, action='store_true',
    help="Print all of the availble URL paths and exit, without starting the GUI.")
start_gui_parser.set_defaults(func=start_gui)

# ============================================================================
# start API (non-apache version)
#

def start_api(args):
    from aceapi import create_app
    from saq.configuration import get_config

    app = create_app(testing=True)
    from werkzeug.serving import run_simple
    from werkzeug.middleware.dispatcher import DispatcherMiddleware
    app.config['DEBUG'] = True
    app.config['APPLICATION_ROOT'] = '/api'
    app.wsgi_app = DispatcherMiddleware(app.wsgi_app, {
        app.config['APPLICATION_ROOT']: app,
    })

    if args.print_uri_paths:
        for rule in app.url_map.iter_rules():
            print(rule)
        sys.exit(0)

    run_simple(get_config().api.listen_address, get_config().api.listen_port, app,
               ssl_context=(get_config().api.ssl_cert, get_config().api.ssl_key),
               use_reloader=False)

# start-api
start_api_parser = get_cli_subparsers().add_parser('start-api',
    help="Start the ACE API server in DEBUG mode.")
start_api_parser.add_argument('args', nargs=argparse.REMAINDER,
    help="Parameters to pass to the API command shell.")
start_api_parser.add_argument('--print-uri-paths', default=False, action='store_true',
    help="Print all of the availble URL paths and exit, without starting the API.")
start_api_parser.set_defaults(func=start_api)
