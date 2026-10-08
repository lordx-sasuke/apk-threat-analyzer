import zipfile
import hashlib
import re
import os

class APKContainer:
    def __init__(self, apk_path):
        self.apk_path = apk_path
        self.filename = os.path.basename(apk_path)
        self.sha256 = self._calculate_hash()
        self.dex_strings = []
        self.archive_files = []

    def _calculate_hash(self):
        sha256 = hashlib.sha256()
        with open(self.apk_path, "rb") as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()

    def parse(self):
        with zipfile.ZipFile(self.apk_path, "r") as z:
            self.archive_files = z.namelist()
            # Extract printable ASCII/UTF-8 strings from all classes*.dex files
            for fname in self.archive_files:
                if fname.startswith("classes") and fname.endswith(".dex"):
                    raw_dex = z.read(fname)
                    # Extract strings of length 4 or greater from compiled bytecode
                    strings = re.findall(b"[\x20-\x7e]{4,}", raw_dex)
                    self.dex_strings.extend([s.decode("ascii", errors="ignore") for s in strings])
        # Deduplicate strings
        self.dex_strings = list(set(self.dex_strings))
