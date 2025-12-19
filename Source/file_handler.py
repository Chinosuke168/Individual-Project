class FileHandler:
    @staticmethod
    def save(path: str, data: bytes):
        with open(path, "wb") as f:
            f.write(data)

    @staticmethod
    def load(path: str) -> bytes:
        with open(path, "rb") as f:
            return f.read()