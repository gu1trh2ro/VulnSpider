from __future__ import annotations

import unittest

from vulnspider.discovery.navigation_safety import (
    authentication_state_change_token,
)


class NavigationSafetyTests(unittest.TestCase):
    def test_clear_authentication_termination_segments_are_suppressed(self) -> None:
        cases = {
            "http://example.test/logout.php": "logout",
            "http://example.test/auth/signout": "signout",
            "http://example.test/LOGOFF": "logoff",
            "http://example.test/auth/LOGOUT.HTML?next=/": "logout",
            "http://example.test/auth/%73ignout": "signout",
        }

        for url, expected in cases.items():
            with self.subTest(url=url):
                self.assertEqual(authentication_state_change_token(url), expected)

    def test_substrings_and_non_path_values_are_not_suppressed(self) -> None:
        for url in (
            "http://example.test/docs/logout-behavior",
            "http://example.test/logout-history.html",
            "http://example.test/account?next=/logout.php",
            "http://example.test/account#logout",
        ):
            with self.subTest(url=url):
                self.assertIsNone(authentication_state_change_token(url))

    def test_classification_is_deterministic(self) -> None:
        url = "http://example.test/auth/SignOut.PHP?nonce=ignored"
        self.assertEqual(
            [authentication_state_change_token(url) for _ in range(3)],
            ["signout", "signout", "signout"],
        )


if __name__ == "__main__":
    unittest.main()
