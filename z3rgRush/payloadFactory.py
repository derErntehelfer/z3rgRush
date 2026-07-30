import os
import sys
import logging
import json

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

    def iteratePayloads(
        self, target, filetypes=None, method="GET", postData=False, bodyTemplate=None
    ):
        filetypes = filetypes or [""]

        # Respect -m override over --post-data as per CLI documentation
        effectiveMethod = method.upper()
        if postData and effectiveMethod == "GET":
            effectiveMethod = "POST"

        hasBody = postData or bodyTemplate is not None

        with open(self.wordlist, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                path = line.strip()
                if not path:
                    continue
                for ext in filetypes:
                    if ext.startswith("."):
                        ext = ext.lstrip(".")
                    pathFull = path + ("." + ext if ext else "")

                # Always replace {SWARM} in URL if present, regardless of body
                requestUrl = (
                    target.replace("{SWARM}", pathFull)
                    if "{SWARM}" in target
                    else target
                )

                requestData = None
                requestJson = None
                contentType = None

                if bodyTemplate:
                    injectedBody = bodyTemplate.replace("{SWARM}", pathFull).strip()
                    # Auto-detect JSON structure
                    if (
                        injectedBody.startswith("{") and injectedBody.endswith("}")
                    ) or (injectedBody.startswith("[") and injectedBody.endswith("]")):
                        try:
                            requestJson = json.loads(injectedBody)
                            contentType = "application/json"
                        except json.JSONDecodeError:
                            requestData = injectedBody
                            contentType = "text/plain"
                    else:
                        requestData = injectedBody
                        contentType = "application/x-www-form-urlencoded"
                elif postData:
                    requestData = pathFull
                    contentType = "text/plain"

                yield {
                    "url": requestUrl,
                    "data": requestData,
                    "json": requestJson,
                    "method": effectiveMethod,
                    "payload": pathFull,
                    "contentType": contentType,
                }

    def generatePayloads(self, target, filetypeArg=None, postData=False):
        filetypes = self.loadFiletypes(filetypeArg)
        return list(self.iteratePayloads(target, filetypes, postData=postData))
