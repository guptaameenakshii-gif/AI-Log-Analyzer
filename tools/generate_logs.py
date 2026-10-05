from pathlib import Path
from datetime import datetime, timedelta
import random


BASE_DIR = Path(__file__).resolve().parent.parent
EXAMPLES_DIR = BASE_DIR / "examples"

EXAMPLES_DIR.mkdir(exist_ok=True)

random.seed(42)

users = [
    "admin",
    "root",
    "alice",
    "bob",
    "service_account",
]

ips = [
    "192.168.1.20",
    "192.168.1.21",
    "10.10.10.15",
    "10.10.10.25",
    "172.16.0.50",
]

services = [
    "ssh",
    "auth",
    "firewall",
    "api",
    "database",
    "web",
]


def timestamp(start, offset):
    return (
        start + timedelta(seconds=offset)
    ).strftime("%Y-%m-%d %H:%M:%S")


def generate_security_logs(count=300):
    start = datetime(2026, 9, 25, 10, 0, 0)

    lines = []

    for i in range(count):
        ts = timestamp(start, i * 7)

        ip = random.choice(ips)
        user = random.choice(users)
        service = random.choice(services)

        pattern = i % 12

        if pattern in {0, 1, 2, 3}:
            line = (
                f"{ts} WARN ssh "
                f"Failed login for {user} from {ip}"
            )

        elif pattern == 4:
            line = (
                f"{ts} ERROR auth "
                f"Account temporarily locked for {user}"
            )

        elif pattern == 5:
            line = (
                f"{ts} WARN firewall "
                f"Rejected request from {ip}"
            )

        elif pattern == 6:
            line = (
                f"{ts} WARN api "
                f"Unauthorized request using invalid token"
            )

        elif pattern == 7:
            line = (
                f"{ts} ERROR database "
                f"Database connection timeout"
            )

        elif pattern == 8:
            line = (
                f"{ts} WARN auth "
                f"Permission denied for {user}"
            )

        elif pattern == 9:
            line = (
                f"{ts} CRITICAL system "
                f"Privilege escalation attempt detected for {user}"
            )

        elif pattern == 10:
            line = (
                f"{ts} INFO {service} "
                f"Normal service activity"
            )

        else:
            line = (
                f"{ts} ERROR {service} "
                f"Request processing failed with status 500"
            )

        lines.append(line)

    return lines


def generate_auth_logs(count=300):
    start = datetime(2026, 9, 25, 11, 0, 0)

    lines = []

    for i in range(count):
        ts = timestamp(start, i * 5)

        user = random.choice(users)
        ip = random.choice(ips)

        pattern = i % 8

        if pattern in {0, 1}:
            line = (
                f"{ts} WARN auth "
                f"Failed login for {user} from {ip}"
            )

        elif pattern == 2:
            line = (
                f"{ts} INFO auth "
                f"Successful login for {user} from {ip}"
            )

        elif pattern == 3:
            line = (
                f"{ts} WARN auth "
                f"Invalid token presented by {user}"
            )

        elif pattern == 4:
            line = (
                f"{ts} ERROR auth "
                f"Account temporarily locked for {user}"
            )

        elif pattern == 5:
            line = (
                f"{ts} WARN auth "
                f"Permission denied for {user}"
            )

        elif pattern == 6:
            line = (
                f"{ts} INFO auth "
                f"Session expired for {user}"
            )

        else:
            line = (
                f"{ts} ERROR auth "
                f"Authentication service timeout"
            )

        lines.append(line)

    return lines


def generate_mixed_logs(count=300):
    start = datetime(2026, 9, 25, 12, 0, 0)

    lines = []

    for i in range(count):
        ts = timestamp(start, i * 4)

        service = random.choice(services)
        ip = random.choice(ips)
        user = random.choice(users)

        pattern = i % 10

        messages = [
            f"{ts} INFO {service} Normal service activity",
            f"{ts} DEBUG {service} Request received",
            f"{ts} INFO {service} Health check completed",
            f"{ts} WARN ssh Failed login for {user} from {ip}",
            f"{ts} WARN firewall Rejected request from {ip}",
            f"{ts} ERROR api Request processing failed with status 500",
            f"{ts} WARN auth Permission denied for {user}",
            f"{ts} ERROR database Database connection timeout",
            f"{ts} CRITICAL system Privilege escalation attempt detected for {user}",
            f"{ts} WARN auth Invalid token presented by {user}",
        ]

        lines.append(messages[pattern])

    return lines


def write_file(name, lines):
    path = EXAMPLES_DIR / name
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"{path}: {len(lines)} lines")


if __name__ == "__main__":
    write_file(
        "security_300.log",
        generate_security_logs(300),
    )

    write_file(
        "auth_300.log",
        generate_auth_logs(300),
    )

    write_file(
        "mixed_300.log",
        generate_mixed_logs(300),
    )

    print("\nGenerated test logs successfully.")