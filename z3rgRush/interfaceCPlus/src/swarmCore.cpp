#include "/home/der_erntehelfer/codeProjects/z3rgRush/z3rgRush/interfaceCPlus/include/swarmCore.hpp"

static std::string replaceSwarmOnce(const std::string& target, const std::string& payload)
{
    std::string result = target;
    std::size_t pos = result.find("{SWARM}");
    if (pos != std::string::npos) {
        result.replace(pos, 7, payload);
    }
    return result;
}

static std::string normalizeExt(std::string ext)
{
    if (!ext.empty() && ext.front() == '.') {
        ext.erase(0, 1);
    }
    return ext;
}

std::vector<RequestSpec> expandPayloads(
    const std::string& target,
    const std::vector<std::string>& wordlist,
    const std::vector<std::string>& filetypes,
    bool postData)
{
    std::vector<RequestSpec> out;
    out.reserve(wordlist.size() * (filetypes.empty() ? 1 : filetypes.size()));

    const std::vector<std::string> effectiveFiletypes = filetypes.empty()
        ? std::vector<std::string> { "" }
        : filetypes;

    for (const auto& path : wordlist) {
        if (path.empty())
            continue;

        for (auto ext : effectiveFiletypes) {
            ext = normalizeExt(ext);
            std::string fullPath = path;
            if (!ext.empty()) {
                fullPath += "." + ext;
            }

            RequestSpec spec;
            if (postData) {
                spec.url = target;
                spec.method = "POST";
                spec.data = fullPath;
                spec.payload = fullPath;
            } else {
                spec.url = replaceSwarmOnce(target, fullPath);
                spec.method = "GET";
                spec.data = "";
                spec.payload = spec.url;
            }
            out.push_back(std::move(spec));
        }
    }

    return out;
}

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
    const std::vector<std::string>& secCHUAPlatform)
{
    auto pick = [rotationIndex](const std::vector<std::string>& v, int offset) -> std::string {
        if (v.empty())
            return "";
        return v[(rotationIndex + offset) % v.size()];
    };

    return {
        pick(userAgents, 0),
        pick(acceptHeaders, 1),
        pick(acceptLanguages, 2),
        pick(acceptEncodings, 3),
        pick(referers, 4),
        pick(secFetchDest, 5),
        pick(secFetchMode, 6),
        pick(secFetchSite, 7),
        pick(secCHUAMobile, 8),
        pick(secCHUAPlatform, 9)
    };
}
