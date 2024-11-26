import asyncio
import logging

from seleniumwire import storage
from seleniumwire.handler import InterceptRequestHandler
from seleniumwire.modifier import RequestModifier
from mitmproxy import addons
from mitmproxy.master import Master
from mitmproxy.options import Options
from mitmproxy.tools import dump

from seleniumwire.utils import build_proxy_args, extract_cert_and_key, get_upstream_proxy

logger = logging.getLogger(__name__)

DEFAULT_VERIFY_SSL = False
DEFAULT_STREAM_WEBSOCKETS = True
DEFAULT_SUPPRESS_CONNECTION_ERRORS = True


class MitmProxy:
    """Run and manage a mitmproxy server instance."""

    def __init__(self, host, port, options):
        self.host=host
        self.port=port

        self.options = options

        # Used to stored captured requests
        self.storage = storage.create(**self._get_storage_args())
        extract_cert_and_key(self.storage.home_dir, cert_path=options.get('ca_cert'), key_path=options.get('ca_key'))

        # Used to modify requests/responses passing through the server
        # DEPRECATED. Will be superceded by request/response interceptors.
        self.modifier = RequestModifier()

        # The scope of requests we're interested in capturing.
        self.scopes = []

        self.request_interceptor = None
        self.response_interceptor = None

        self._event_loop = asyncio.new_event_loop()

        self.opts = Options()
        self.opts.update(
            confdir=self.storage.home_dir,
            listen_host=host,
            listen_port=port,
            ssl_insecure=not options.get('verify_ssl', DEFAULT_VERIFY_SSL),
            websocket=DEFAULT_STREAM_WEBSOCKETS,
            # suppress_connection_errors=options.get('suppress_connection_errors', DEFAULT_SUPPRESS_CONNECTION_ERRORS),
            **build_proxy_args(get_upstream_proxy(self.options)),
            # Options that are prefixed mitm_ are passed through to mitmproxy
            **{k[5:]: v for k, v in options.items() if k.startswith('mitm_')},
        )
        self.master = dump.DumpMaster(
            self.opts,
            loop=self._event_loop,
            with_termlog=True,
            with_dumper=True,
        )
        # self.master.addons.add(*addons.default_addons())
        self.master.addons.add(SendToLogger())
        self.master.addons.add(InterceptRequestHandler(self))

        if options.get('disable_capture', False):
            self.scopes = ['$^']
    async def start_proxy(self,host, port):
        await self.master.run()
        return self.master
    
    def serve_forever(self):
        """Run the server."""
        asyncio.run(self.start_proxy('localhost', 8080))
    def address(self):
        """Get a tuple of the address and port the proxy server
        is listening on.
        """
        return self.host,self.port

    def shutdown(self):
        """Shutdown the server and perform any cleanup."""
        self.master.shutdown()
        self.storage.cleanup()

    def _get_storage_args(self):
        storage_args = {
            'memory_only': self.options.get('request_storage') == 'memory',
            'base_dir': self.options.get('request_storage_base_dir'),
            'maxsize': self.options.get('request_storage_max_size'),
        }

        return storage_args


class SendToLogger:
    def log(self, entry):
        """Send a mitmproxy log message through our own logger."""
        getattr(logger, entry.level.replace('warn', 'warning'), logger.info)(entry.msg)
