# /z3rgRush/payloadFactory.py
import os
import sys
import logging
import json

logger = logging.getLogger("z3rgRush.payloadFactory")


class payloadFactory:
    def __init__(self, wordlist, recursion=0):
        self.wordlist = wordlist
        self.recursion = recursion

        logger.debug(f"PayloadFactory initialized with wordlist: {wordlist}")

    def loadFiletypes(self, filetypeArg):
        if not filetypeArg:
            return [""]

        if os.path.isfile(filetypeArg):
            try:
                with open(filetypeArg, "r", encoding="utf-8", errors="replace") as f:
                    extensions = [line.strip() for line in f if line.strip()]

                if not extensions:
                    logger.error(f"{filetypeArg} is empty")
                    sys.exit(1)

                logger.debug(f"Loaded {len(extensions)} filetypes from {filetypeArg}")

                return extensions

            except Exception as err:
                logger.error(f"Error reading {filetypeArg}: {err}")
                sys.exit(1)

        logger.debug(f"Using single filetype: {filetypeArg}")
        return [filetypeArg]

    def iteratePayloads(
        self,
        target,
        filetypes=None,
        method=None,
        postData=False,
        bodyTemplate=None,
    ):
        filetypes = filetypes or [""]
        target = str(target or "")

        if bodyTemplate is not None:
            bodyTemplate = str(bodyTemplate)

        method = (method or "").upper()

        if not method:
            if postData or bodyTemplate is not None:
                effectiveMethod = "POST"
            else:
                effectiveMethod = "GET"
        else:
            effectiveMethod = method

            if postData and effectiveMethod == "GET":
                effectiveMethod = "POST"

            if bodyTemplate is not None and effectiveMethod == "GET":
                effectiveMethod = "POST"

        try:
            wordlistHandle = open(
                self.wordlist,
                "r",
                encoding="utf-8",
                errors="replace",
            )
        except OSError as err:
            logger.error(f"Could not open wordlist {self.wordlist}: {err}")
            return

        with wordlistHandle:
            for line in wordlistHandle:
                path = line.strip()

                if not path:
                    continue

                for ext in filetypes:
                    if ext.startswith("."):
                        ext = ext.lstrip(".")

                    pathFull = path + ("." + ext if ext else "")

                    requestUrl = (
                        target.replace("{SWARM}", pathFull)
                        if "{SWARM}" in target
                        else target
                    )

                    requestData = None
                    requestJson = None
                    contentType = None

                    if bodyTemplate:
                        rawBody = bodyTemplate.replace("{SWARM}", pathFull).strip()

                        try:
                            escapedPayload = json.dumps(pathFull)[1:-1]
                        except Exception:
                            escapedPayload = pathFull

                        escapedBody = bodyTemplate.replace(
                            "{SWARM}",
                            escapedPayload,
                        ).strip()

                        for candidate in (rawBody, escapedBody):
                            looksLikeJson = (
                                candidate.startswith("{") and candidate.endswith("}")
                            ) or (candidate.startswith("[") and candidate.endswith("]"))

                            if not looksLikeJson:
                                continue

                            try:
                                requestJson = json.loads(candidate)
                                contentType = "application/json"
                                break
                            except json.JSONDecodeError:
                                continue

                        if requestJson is None:
                            requestData = rawBody
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

    def generatePayloads(
        self,
        target,
        filetypeArg=None,
        method=None,
        postData=False,
        bodyTemplate=None,
    ):
        filetypes = self.loadFiletypes(filetypeArg)

        return list(
            self.iteratePayloads(
                target=target,
                filetypes=filetypes,
                method=method,
                postData=postData,
                bodyTemplate=bodyTemplate,
            )
        )
