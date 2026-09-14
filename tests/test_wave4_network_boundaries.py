import unittest
from deep_tests.security_model import BoundaryViolation, validate_outbound_url


class Wave4NetworkBoundaryTests(unittest.TestCase):
    def test_private_and_metadata_ips_fail_closed_even_when_allowlisted(self):
        for host in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "::1"):
            url = f"https://[{host}]/v1" if ":" in host else f"https://{host}/v1"
            with self.assertRaises(BoundaryViolation):
                validate_outbound_url(url, {host})

    def test_suffix_and_userinfo_authority_confusion_fail_closed(self):
        allowed = {"api.example.test"}
        for url in ("https://api.example.test.attacker.invalid/v1", "https://api.example.test@attacker.invalid/v1", "https://attacker.invalid/api.example.test"):
            with self.assertRaises(BoundaryViolation):
                validate_outbound_url(url, allowed)

    def test_fragments_are_rejected_before_upstream_dispatch(self):
        with self.assertRaises(BoundaryViolation):
            validate_outbound_url("https://api.example.test/v1#secret", {"api.example.test"})


if __name__ == "__main__":
    unittest.main()
