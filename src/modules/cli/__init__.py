import argparse

"""
CRITICAL_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    27017: "MongoDB",
    6379: "Redis",
    9200: "Elasticsearch",
}
"""


class CLI(argparse.ArgumentParser):

    def __init__(self):
        super().__init__(
            description="Simple Cloud Analyzer - Multi-cloud Security Scanner"
        )

        self.add_argument(
            "--provider",
            choices=["aws"],
            default="aws",
            help="Provedor de nuvem para analisar (ex: aws)",
        )

        self.add_argument(
            "--ports",
            nargs="+",
            type=int,
            default=[22, 3389, 3306, 5432, 27017, 6379, 9200],
            help="Portas para verificar exposição pública (ex: --ports 22 80 443)",
        )

        self.add_argument(
            "--output",
            type=str,
            default="report.csv",
            help="Caminho para salvar o relatório final em CSV",
        )

        self.add_argument(
            "--aws-regions",
            type=str,
            default="",
            help="Lista de regiões AWS que devem ser escaneadas (ex: --aws-regions 'us-east-1,sa-east-1')",
        )

        self.add_argument(
            "--debug",
            action="store_true",
            help="Enable logging",
        )
