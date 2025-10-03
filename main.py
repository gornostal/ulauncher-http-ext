import json
import logging
import socket
import ssl
import time
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from ulauncher.api.client.Extension import Extension
from ulauncher.api.client.EventListener import EventListener
from ulauncher.api.shared.event import KeywordQueryEvent, ItemEnterEvent
from ulauncher.api.shared.item.ExtensionResultItem import ExtensionResultItem
from ulauncher.api.shared.action.RenderResultListAction import RenderResultListAction
from ulauncher.api.shared.action.ExtensionCustomAction import ExtensionCustomAction
from ulauncher.api.shared.action.HideWindowAction import HideWindowAction
from ulauncher.api.shared.action.CopyToClipboardAction import CopyToClipboardAction

logger = logging.getLogger(__name__)


class HTTPSTroubleshooterExtension(Extension):

    def __init__(self):
        super(HTTPSTroubleshooterExtension, self).__init__()
        self.subscribe(KeywordQueryEvent, KeywordQueryEventListener())
        self.subscribe(ItemEnterEvent, ItemEnterEventListener())


class KeywordQueryEventListener(EventListener):

    def on_event(self, event, extension):
        items = []
        test_url = extension.preferences.get('test_url', 'https://www.google.com')

        items.append(ExtensionResultItem(
            icon='images/icon.png',
            name='Test HTTPS Connection',
            description=f'Click to test: {test_url}',
            on_enter=ExtensionCustomAction({'action': 'test', 'url': test_url}, keep_app_open=True)
        ))

        items.append(ExtensionResultItem(
            icon='images/icon.png',
            name='Test DNS Resolution',
            description=f'Check if domain resolves',
            on_enter=ExtensionCustomAction({'action': 'dns', 'url': test_url}, keep_app_open=True)
        ))

        items.append(ExtensionResultItem(
            icon='images/icon.png',
            name='Test SSL Certificate',
            description=f'Check SSL certificate validity',
            on_enter=ExtensionCustomAction({'action': 'ssl', 'url': test_url}, keep_app_open=True)
        ))

        items.append(ExtensionResultItem(
            icon='images/icon.png',
            name='Check Proxy Settings',
            description='Display system proxy configuration',
            on_enter=ExtensionCustomAction({'action': 'proxy'}, keep_app_open=True)
        ))

        return RenderResultListAction(items)


class ItemEnterEventListener(EventListener):

    def on_event(self, event, extension):
        data = event.get_data()
        action = data.get('action')
        url = data.get('url', '')
        timeout = int(extension.preferences.get('timeout_seconds', '10'))

        results = []

        if action == 'test':
            results = self.test_https_connection(url, timeout)
        elif action == 'dns':
            results = self.test_dns_resolution(url)
        elif action == 'ssl':
            results = self.test_ssl_certificate(url, timeout)
        elif action == 'proxy':
            results = self.check_proxy_settings()

        return RenderResultListAction(results)

    def test_https_connection(self, url, timeout):
        """Test HTTPS connection and log detailed diagnostics"""
        results = []
        log_entries = []

        try:
            parsed = urlparse(url)
            if not parsed.scheme:
                url = 'https://' + url
                parsed = urlparse(url)

            log_entries.append(f"Testing URL: {url}")
            log_entries.append(f"Timeout: {timeout}s")
            logger.info(f"Testing HTTPS connection to {url}")

            # Test connection timing
            start_time = time.time()

            request = Request(url)
            request.add_header('User-Agent', 'Mozilla/5.0 (Ulauncher HTTPS Troubleshooter)')

            try:
                response = urlopen(request, timeout=timeout)
                end_time = time.time()
                elapsed = end_time - start_time

                status_code = response.getcode()
                headers = dict(response.headers)

                log_entries.append(f"✓ Success! Status: {status_code}")
                log_entries.append(f"Response time: {elapsed:.2f}s")
                log_entries.append(f"Content-Type: {headers.get('Content-Type', 'N/A')}")
                log_entries.append(f"Server: {headers.get('Server', 'N/A')}")

                results.append(ExtensionResultItem(
                    icon='images/icon.png',
                    name=f'✓ Connection Successful ({elapsed:.2f}s)',
                    description=f'Status: {status_code}, Server: {headers.get("Server", "N/A")}',
                    on_enter=CopyToClipboardAction('\n'.join(log_entries))
                ))

                logger.info(f"Connection successful: {status_code} in {elapsed:.2f}s")

            except socket.timeout:
                log_entries.append(f"✗ Connection timeout after {timeout}s")
                log_entries.append("Possible causes: slow network, server overload, firewall")
                results.append(ExtensionResultItem(
                    icon='images/icon.png',
                    name='✗ Connection Timeout',
                    description=f'No response within {timeout}s - check network/firewall',
                    on_enter=CopyToClipboardAction('\n'.join(log_entries))
                ))
                logger.error(f"Connection timeout to {url}")

            except HTTPError as e:
                log_entries.append(f"✗ HTTP Error: {e.code} {e.reason}")
                log_entries.append(f"URL: {e.url}")
                results.append(ExtensionResultItem(
                    icon='images/icon.png',
                    name=f'✗ HTTP Error: {e.code}',
                    description=f'{e.reason} - Server returned error',
                    on_enter=CopyToClipboardAction('\n'.join(log_entries))
                ))
                logger.error(f"HTTP error {e.code}: {e.reason}")

            except URLError as e:
                reason = str(e.reason)
                log_entries.append(f"✗ URL Error: {reason}")

                if 'timed out' in reason.lower():
                    log_entries.append("Connection attempt timed out")
                elif 'refused' in reason.lower():
                    log_entries.append("Connection refused - server not responding")
                elif 'certificate' in reason.lower() or 'ssl' in reason.lower():
                    log_entries.append("SSL/Certificate error - check certificate validity")
                elif 'name or service not known' in reason.lower():
                    log_entries.append("DNS resolution failed - domain not found")
                else:
                    log_entries.append("Network error occurred")

                results.append(ExtensionResultItem(
                    icon='images/icon.png',
                    name='✗ Connection Failed',
                    description=reason[:80],
                    on_enter=CopyToClipboardAction('\n'.join(log_entries))
                ))
                logger.error(f"URL error: {reason}")

        except Exception as e:
            log_entries.append(f"✗ Unexpected error: {type(e).__name__}")
            log_entries.append(str(e))
            results.append(ExtensionResultItem(
                icon='images/icon.png',
                name=f'✗ Error: {type(e).__name__}',
                description=str(e)[:80],
                on_enter=CopyToClipboardAction('\n'.join(log_entries))
            ))
            logger.exception(f"Unexpected error testing {url}")

        # Add option to copy full log
        results.append(ExtensionResultItem(
            icon='images/icon.png',
            name='Copy full log to clipboard',
            description=f'{len(log_entries)} log entries',
            on_enter=CopyToClipboardAction('\n'.join(log_entries))
        ))

        return results

    def test_dns_resolution(self, url):
        """Test DNS resolution"""
        results = []
        log_entries = []

        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or url.replace('https://', '').replace('http://', '').split('/')[0]

            log_entries.append(f"Testing DNS resolution for: {hostname}")
            logger.info(f"Testing DNS for {hostname}")

            start_time = time.time()
            ip_addresses = socket.getaddrinfo(hostname, None)
            end_time = time.time()
            elapsed = end_time - start_time

            unique_ips = list(set([addr[4][0] for addr in ip_addresses]))

            log_entries.append(f"✓ DNS resolved in {elapsed:.3f}s")
            log_entries.append(f"IP addresses: {', '.join(unique_ips)}")

            results.append(ExtensionResultItem(
                icon='images/icon.png',
                name=f'✓ DNS Resolution OK ({elapsed:.3f}s)',
                description=f'Resolved to: {unique_ips[0]}' + (f' +{len(unique_ips)-1} more' if len(unique_ips) > 1 else ''),
                on_enter=CopyToClipboardAction('\n'.join(log_entries))
            ))

            logger.info(f"DNS resolved: {hostname} -> {unique_ips}")

        except socket.gaierror as e:
            log_entries.append(f"✗ DNS resolution failed: {e}")
            log_entries.append("Possible causes: invalid domain, DNS server issue, no internet")
            results.append(ExtensionResultItem(
                icon='images/icon.png',
                name='✗ DNS Resolution Failed',
                description='Domain name could not be resolved',
                on_enter=CopyToClipboardAction('\n'.join(log_entries))
            ))
            logger.error(f"DNS resolution failed: {e}")

        except Exception as e:
            log_entries.append(f"✗ Error: {type(e).__name__}: {e}")
            results.append(ExtensionResultItem(
                icon='images/icon.png',
                name=f'✗ Error: {type(e).__name__}',
                description=str(e)[:80],
                on_enter=CopyToClipboardAction('\n'.join(log_entries))
            ))
            logger.exception(f"DNS test error")

        results.append(ExtensionResultItem(
            icon='images/icon.png',
            name='Copy full log to clipboard',
            description=f'{len(log_entries)} log entries',
            on_enter=CopyToClipboardAction('\n'.join(log_entries))
        ))

        return results

    def test_ssl_certificate(self, url, timeout):
        """Test SSL certificate validity"""
        results = []
        log_entries = []

        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or url.replace('https://', '').replace('http://', '').split('/')[0]
            port = parsed.port or 443

            log_entries.append(f"Testing SSL certificate for: {hostname}:{port}")
            logger.info(f"Testing SSL for {hostname}:{port}")

            context = ssl.create_default_context()

            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

                    log_entries.append(f"✓ SSL connection established")
                    log_entries.append(f"Protocol: {version}")
                    log_entries.append(f"Cipher: {cipher[0]} ({cipher[2]} bits)")
                    log_entries.append(f"Subject: {dict(x[0] for x in cert['subject'])}")
                    log_entries.append(f"Issuer: {dict(x[0] for x in cert['issuer'])}")
                    log_entries.append(f"Valid from: {cert['notBefore']}")
                    log_entries.append(f"Valid until: {cert['notAfter']}")

                    results.append(ExtensionResultItem(
                        icon='images/icon.png',
                        name=f'✓ SSL Certificate Valid',
                        description=f'{version}, {cipher[0]}, expires: {cert["notAfter"]}',
                        on_enter=CopyToClipboardAction('\n'.join(log_entries))
                    ))

                    logger.info(f"SSL certificate valid for {hostname}")

        except ssl.SSLError as e:
            log_entries.append(f"✗ SSL Error: {e}")
            log_entries.append("Possible causes: expired cert, self-signed cert, hostname mismatch")
            results.append(ExtensionResultItem(
                icon='images/icon.png',
                name='✗ SSL Certificate Error',
                description=str(e)[:80],
                on_enter=CopyToClipboardAction('\n'.join(log_entries))
            ))
            logger.error(f"SSL error: {e}")

        except socket.timeout:
            log_entries.append(f"✗ Connection timeout after {timeout}s")
            results.append(ExtensionResultItem(
                icon='images/icon.png',
                name='✗ Connection Timeout',
                description=f'No response within {timeout}s',
                on_enter=CopyToClipboardAction('\n'.join(log_entries))
            ))
            logger.error(f"SSL test timeout")

        except Exception as e:
            log_entries.append(f"✗ Error: {type(e).__name__}: {e}")
            results.append(ExtensionResultItem(
                icon='images/icon.png',
                name=f'✗ Error: {type(e).__name__}',
                description=str(e)[:80],
                on_enter=CopyToClipboardAction('\n'.join(log_entries))
            ))
            logger.exception(f"SSL test error")

        results.append(ExtensionResultItem(
            icon='images/icon.png',
            name='Copy full log to clipboard',
            description=f'{len(log_entries)} log entries',
            on_enter=CopyToClipboardAction('\n'.join(log_entries))
        ))

        return results

    def check_proxy_settings(self):
        """Check proxy configuration"""
        results = []
        log_entries = []

        try:
            import os

            log_entries.append("Checking proxy environment variables:")

            proxy_vars = ['http_proxy', 'https_proxy', 'HTTP_PROXY', 'HTTPS_PROXY',
                         'no_proxy', 'NO_PROXY', 'all_proxy', 'ALL_PROXY']

            found_proxies = False
            for var in proxy_vars:
                value = os.environ.get(var)
                if value:
                    log_entries.append(f"{var}={value}")
                    found_proxies = True

            if not found_proxies:
                log_entries.append("No proxy environment variables set")

            logger.info("Proxy check completed")

            results.append(ExtensionResultItem(
                icon='images/icon.png',
                name='Proxy Settings' if found_proxies else 'No Proxy Configured',
                description=f'{len([v for v in proxy_vars if os.environ.get(v)])} proxy variables set' if found_proxies else 'No proxy environment variables found',
                on_enter=CopyToClipboardAction('\n'.join(log_entries))
            ))

        except Exception as e:
            log_entries.append(f"✗ Error: {type(e).__name__}: {e}")
            results.append(ExtensionResultItem(
                icon='images/icon.png',
                name=f'✗ Error: {type(e).__name__}',
                description=str(e)[:80],
                on_enter=CopyToClipboardAction('\n'.join(log_entries))
            ))
            logger.exception(f"Proxy check error")

        results.append(ExtensionResultItem(
            icon='images/icon.png',
            name='Copy full log to clipboard',
            description=f'{len(log_entries)} log entries',
            on_enter=CopyToClipboardAction('\n'.join(log_entries))
        ))

        return results


if __name__ == '__main__':
    HTTPSTroubleshooterExtension().run()
