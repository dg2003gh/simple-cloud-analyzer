from logging import Logger
from tabulate import tabulate

from modules.utils import Utils


class TableGenerator:
    def __init__(self, findings: list, logger: Logger) -> None:
        self.logger = logger
        self.utils = Utils(self.logger)
        self.findings = findings

    def generate(self):
        print(
            tabulate(
                self.utils.rm_column(self.findings, "Description"),
                headers="keys",
                tablefmt="github",
                showindex=True,
            )
        )
