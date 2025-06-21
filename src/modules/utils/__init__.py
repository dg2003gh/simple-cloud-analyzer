from colorama import Fore, Style, init


# Initialize colorama
init(autoreset=True)


class Utils:
    def __init__(self, logger) -> None:
        self.logger = logger

    def rm_column(self, data, term: str):
        return [{k: v for k, v in row.items() if k != term} for row in data]

    def section(self, title, region):
        msg = f"{'=' * 10} {title.upper()} [{region}] {'=' * 10}"
        print(f"\n{Fore.GREEN}{msg}{Style.RESET_ALL}")
        self.logger.info(msg)
