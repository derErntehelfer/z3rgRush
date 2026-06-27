import os
import sys
import logging

logger = logging.getLogger("z3rgRush.payloadFactory")


class payloadFactory:
    def __init__(self, wordlist, recursion):
        self.wordlist = wordlist
        self.recursion = recursion
        logger.debug(f"PayloadFactory initialized with wordlist: {wordlist}")

    def loadFiletypes(self, filetypeArg):
        if not filetypeArg:
            return [""]

        if os.path.isfile(filetypeArg):
            try:
                with open(filetypeArg, "r") as f:
                    extensions = [line.strip() for line in f if line.strip()]
                if not extensions:
                    logger.error(f"{filetypeArg} is empty")
                    sys.exit(1)
                logger.debug(f"Loaded {len(extensions)} filetypes from {filetypeArg}")
                return extensions
            except Exception as e:
                logger.error(f"Error reading {filetypeArg}: {e}")
                sys.exit(1)

        logger.debug(f"Using single filetype: {filetypeArg}")
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
                    pathFull = path + ("." + ext if ext else "")

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
        return list(self.iteratePayloads(target, filetypes, postData))
