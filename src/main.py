#!/usr/bin/env python

import logging

from CONSTS import CLOUDS
from modules.cli.arg_parser import ArgParser
from modules.clouds.aws import AWSAnalyzer
from modules.clouds.gcp import GCPAnalyzer
from modules.report_generator import ReportGenerator


class Main:
    findings = []
    args = ArgParser().parse_args()
    analyzers_enabled: list[str] = []
    report_generator = ReportGenerator(findings, logger=logging)

    def _run(self):
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s",
            handlers=[logging.FileHandler("aws_analyzer.log"), logging.StreamHandler()],
        )

        if not self.args.debug:
            logging.disable(logging.CRITICAL)

        PROVIDERS = self.args.providers

        if CLOUDS[12319] in PROVIDERS:  # AWS
            self.analyzers_enabled.append(CLOUDS[12319])
        if CLOUDS[7316] in PROVIDERS:  # GCP
            self.analyzers_enabled.append(CLOUDS[7316])

        self.__active_analyzers()

    def __active_analyzers(self):
        if CLOUDS[12319] in self.analyzers_enabled:
            AWSAnalyzer(
                ports=self.args.ports,
                regions=self.args.aws_regions.split(","),
                logger=logging,
                findings=self.findings,
                report_generator=self.report_generator,
            )
        if CLOUDS[7316] in self.analyzers_enabled:
            GCPAnalyzer(
                ports=self.args.ports,
                projects=self.args.gcp_projects.split(","),
                logger=logging,
                findings=self.findings,
                report_generator=self.report_generator,
            )

    def __del__(self):
        self.report_generator.generate(
            self.args.output or "report.csv",
            headers=["Service", "Type", "Resource", "Description", "From"],
        )


if __name__ == "__main__":
    app = Main()
    app._run()
