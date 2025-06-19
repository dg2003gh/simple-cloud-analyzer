class Utils:
    def __init__(self) -> None:
        pass

    def rm_column(self, data, term: str):
        return [{k: v for k, v in row.items() if k != term} for row in data]
