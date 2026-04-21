import os
import sys


class payloadFactory:
    def loadFiletypes(self, filetypeArg):
        if not filetypeArg:
            return [""]
        if os.path.isfile(filetypeArg):
            try:
                with open(filetypeArg, "r") as f:
                    extensions = [line.strip() for line in f if line.strip()]
                if not extensions:
                    print(f"Error: {filetypeArg} is empty.", file=sys.stderr)
                    sys.exit(1)
                return extensions
            except Exception as e:
                print(f"Error reading {filetypeArg}: {e}", file=sys.stderr)
                sys.exit(1)
        return [filetypeArg]

    def iteratePayloads(self, target, wordlistPath, filetypes=None, postData=False):
        filetypes = filetypes or [""]
        with open(wordlistPath, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                path = line.strip()
                if not path:
                    continue
                for ext in filetypes:
                    if ext.startswith("."):
                        ext = ext.lstrip(".")
                    pathFull = path + (("." + ext) if ext else "")
                    payload = target.replace("{SWARM}", pathFull, 1)

                    if postData:
                        # For POST, yield URL and payload as data
                        yield payload, pathFull
                    else:
                        yield payload

    def generatePayloads(self, target, wordlistPath, filetypeArg=None, postData=False):
        filetypes = self.loadFiletypes(filetypeArg)
        return list(self.iteratePayloads(target, wordlistPath, filetypes, postData))
