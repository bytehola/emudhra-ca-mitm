"""mitmproxy 流式转发 addon。"""

from mitmproxy import http


class StreamingForwarder:
    """请求和响应正文都不在本地聚合。"""

    def requestheaders(self, flow: http.HTTPFlow) -> None:
        flow.request.stream = True

    def responseheaders(self, flow: http.HTTPFlow) -> None:
        flow.response.stream = True
