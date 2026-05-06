import os
import sys


class payloadFactory:
    def __init__(self, wordlist, recursion):
        self.wordlist = wordlist
        self.recursion = recursion

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

    def iteratePayloads(self, target, filetypes=None, postData=False):
        filetypes = filetypes or [""]

        with open(self.wordlist, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                path = line.strip()
                if not path:
                    continue
                for ext in filetypes:
                    if ext.startswith("."):
                        ext = ext.lstrip(".")
                    pathFull = path + (("." + ext) if ext else "")

                    if postData:
                        yield {
                            "url": target,
                            "data": pathFull,
                            "method": "POST",
                            "payload": pathFull,
                        }
                    else:
                        requestUrl = target.replace("{SWARM}", pathFull, 1)
                        yield {
                            "url": requestUrl,
                            "data": None,
                            "method": "GET",
                            "payload": requestUrl,
                        }

    def generatePayloads(self, target, filetypeArg=None, postData=False):
        filetypes = self.loadFiletypes(filetypeArg)
        return list(self.iteratePayloads(target, self.wordlist, filetypes, postData))
