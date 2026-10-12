import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


class ComposeSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
        cls.services = cls.compose["services"]
        cls.env_template = dict(
            line.split("=", 1)
            for line in (ROOT / ".env.template").read_text().splitlines()
            if line and not line.startswith("#") and "=" in line
        )

    def test_postgres_is_authenticated_and_loopback_only(self) -> None:
        service = self.services["postgres"]

        self.assertEqual(
            service["environment"]["POSTGRES_PASSWORD"], "${POSTGRES_PASSWORD:-}"
        )
        self.assertNotIn("POSTGRES_HOST_AUTH_METHOD", service["environment"])
        self.assertEqual(
            service["environment"]["POSTGRES_INITDB_ARGS"],
            "--auth-host=scram-sha-256",
        )
        self.assertIn("127.0.0.1:5432:5432", service["ports"])

    def test_redis_requires_a_password_and_does_not_mutate_in_healthcheck(self) -> None:
        service = self.services["redis"]
        command = "\n".join(service["command"])

        self.assertEqual(service["environment"]["REDIS_PASSWORD"], "${REDIS_PASSWORD:-}")
        self.assertIn('if [ -z "$${REDIS_PASSWORD}" ]', command)
        self.assertIn(
            'exec redis-server --appendonly yes --requirepass "$${REDIS_PASSWORD}"',
            command,
        )
        self.assertIn("127.0.0.1:6379:6379", service["ports"])
        self.assertIn(
            "redis-cli ping", service["healthcheck"]["test"][1]
        )
        self.assertNotIn("incr", service["healthcheck"]["test"][1].lower())

    def test_grafana_requires_a_password_and_is_loopback_only(self) -> None:
        service = self.services["grafana"]
        environment = dict(item.split("=", 1) for item in service["environment"])
        command = "\n".join(service["command"])

        self.assertEqual(
            environment["GF_SECURITY_ADMIN_PASSWORD"],
            "${GRAFANA_ADMIN_PASSWORD:-}",
        )
        self.assertEqual(service["entrypoint"], ["/bin/sh", "-ec"])
        self.assertIn("GRAFANA_ADMIN_PASSWORD must be set", command)
        self.assertIn("exec /run.sh", command)
        self.assertIn("127.0.0.1:3001:3000", service["ports"])

    def test_api_jwt_secrets_are_required_and_have_no_fixed_defaults(self) -> None:
        service = self.services["api"]
        environment = dict(item.split("=", 1) for item in service["environment"])

        self.assertEqual(environment["JWT_SECRET"], "${JWT_SECRET:?JWT_SECRET must be set}")
        self.assertEqual(
            environment["SOTYHUB_PROXY_JWT_SECRET"],
            "${SOTYHUB_PROXY_JWT_SECRET:?SOTYHUB_PROXY_JWT_SECRET must be set}",
        )
        self.assertEqual(self.env_template["JWT_SECRET"], "")
        self.assertEqual(self.env_template["SOTYHUB_PROXY_JWT_SECRET"], "")

    def test_environment_template_has_no_database_cache_or_grafana_password_defaults(
        self,
    ) -> None:
        for key in (
            "DATABASE_URL",
            "POSTGRES_PASSWORD",
            "REDIS_URL",
            "REDIS_PASSWORD",
            "GRAFANA_ADMIN_PASSWORD",
        ):
            with self.subTest(key=key):
                self.assertEqual(self.env_template[key], "")


if __name__ == "__main__":
    unittest.main()
