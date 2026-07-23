from interceptor.http_proxy import create_http_guard_app


def build_app(config):
    return create_http_guard_app(config)
