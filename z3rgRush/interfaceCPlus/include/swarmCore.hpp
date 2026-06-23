#pragma once

#include <string>
#include <vector>

struct RequestSpec {
    std::string url;
    std::string method;
    std::string data;
    std::string payload;
};

std::vector<RequestSpec> expandPayloads(
    const std::string& target,
    const std::vector<std::string>& wordlist,
    const std::vector<std::string>& filetypes,
    bool postData);

std::vector<std::string> rotateHeaders(
    int rotationIndex,
    const std::vector<std::string>& userAgents,
    const std::vector<std::string>& acceptHeaders,
    const std::vector<std::string>& acceptLanguages,
    const std::vector<std::string>& acceptEncodings,
    const std::vector<std::string>& referers,
    const std::vector<std::string>& secFetchDest,
    const std::vector<std::string>& secFetchMode,
    const std::vector<std::string>& secFetchSite,
    const std::vector<std::string>& secCHUAMobile,
    const std::vector<std::string>& secCHUAPlatform);
