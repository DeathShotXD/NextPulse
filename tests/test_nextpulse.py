import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import nextpulse as np


class TargetTests(unittest.TestCase):
    def test_https_with_port(self):
        self.assertEqual(np.parse_target("https://x.test:8443/a"), ("x.test", 8443, True))

    def test_http_default_port(self):
        self.assertEqual(np.parse_target("http://x.test/a"), ("x.test", 80, False))

    def test_bare_host(self):
        host, port, use_ssl = np.parse_target("x.test")
        self.assertEqual(host, "x.test")
        self.assertEqual(port, 80)
        self.assertFalse(use_ssl)


class FingerprintTests(unittest.TestCase):
    def test_is_nextjs(self):
        self.assertTrue(np.is_nextjs('<script src="/_next/static/x.js"></script>'))
        self.assertFalse(np.is_nextjs("<html>plain</html>"))

    def test_parse_ver(self):
        self.assertEqual(np.parse_ver("Next.js 15.5.15"), (15, 5, 15))
        self.assertIsNone(np.parse_ver("no version here"))

    def test_vulnerable(self):
        self.assertTrue(np.is_vulnerable((15, 5, 15)))
        self.assertFalse(np.is_vulnerable((15, 5, 16)))
        self.assertTrue(np.is_vulnerable((16, 2, 4)))
        self.assertFalse(np.is_vulnerable((16, 2, 5)))
        self.assertIsNone(np.is_vulnerable(None))


class HeaderTests(unittest.TestCase):
    def test_proxy_detection(self):
        self.assertIn("Nginx", np.analyze_headers({"Server": "nginx"})["proxies"])
        self.assertIn("Cloudflare", np.analyze_headers({"Server": "cloudflare"})["proxies"])
        self.assertIn("AWS CloudFront", np.analyze_headers({"Via": "cloudfront"})["proxies"])

    def test_powered_by_is_lowered(self):
        self.assertEqual(np.analyze_headers({"X-Powered-By": "Next.js"})["powered_by"], "next.js")


if __name__ == "__main__":
    unittest.main()
