from datetime import datetime, timezone
from logging import Logger

from modules.cli.table_generator import TableGenerator
from modules.report_generator import ReportGenerator
from modules.utils import Utils

"""
Base class for all clouds, holds common things between them.
"""


class Provider:
    IPV4_INTERNET_IP = "0.0.0.0/0"
    IPV6_INTERNET_IP = "::/0"

    def __init__(
        self,
        ports: list[int],
        findings: list,
        logger: Logger,
        report_generator: ReportGenerator,
    ) -> None:
        self.now = datetime.now(timezone.utc)
        self.ports = ports
        self.findings = findings
        self.logger = logger
        self.utils = Utils(self.logger)
        self.table_generator = TableGenerator(self.findings, self.logger)
        self.report_generator = report_generator

    def __del__(self):
        self.utils.section(self.__class__.__name__, "TABLE")
        self.table_generator.generate()
