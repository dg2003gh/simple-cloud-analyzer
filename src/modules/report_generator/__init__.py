import csv

from builtins import open
from modules.utils import Utils
from colorama import Fore, init


# Initialize colorama
init(autoreset=True)


class ReportGenerator:
    def __init__(self, findings: list, logger) -> None:
        self.findings = findings
        self.logger = logger
        self.utils = Utils(logger)

    def add_finding(self, service, finding_type, resource, description, _from):
        self.findings.append(
            {
                "Service": service,
                "Type": finding_type,
                "Resource": resource,
                "Description": description,
                "From": _from,
            }
        )

    def generate(self, output_file, headers):
        self.utils.section("Generating CSV Report...", output_file)

        with open(output_file, mode="w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            for row in self.findings:
                writer.writerow(row)

        print(Fore.GREEN + f"Report generated: {output_file}")
        self.logger.info(f"Report generated: {output_file}")
