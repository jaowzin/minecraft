#include "pattern.hpp"

#include <charconv>
#include <sstream>

std::optional<BytePattern> parsePattern(const std::string& text, std::string& error) {
    BytePattern result;
    std::istringstream stream(text);
    std::string token;

    while (stream >> token) {
        if (token == "?" || token == "??") {
            result.push_back(PatternByte{0, true});
            continue;
        }

        if (token.size() != 2) {
            error = "Invalid token in pattern: " + token;
            return std::nullopt;
        }

        unsigned int value = 0;
        const auto* begin = token.data();
        const auto* end = token.data() + token.size();
        auto [ptr, ec] = std::from_chars(begin, end, value, 16);
        if (ec != std::errc{} || ptr != end || value > 0xFF) {
            error = "Invalid hex byte in pattern: " + token;
            return std::nullopt;
        }

        result.push_back(PatternByte{static_cast<std::uint8_t>(value), false});
    }

    if (result.empty()) {
        error = "Pattern is empty.";
        return std::nullopt;
    }

    return result;
}

std::vector<std::size_t> findPatternMatches(const std::vector<std::uint8_t>& data, const BytePattern& pattern) {
    std::vector<std::size_t> matches;
    if (pattern.empty() || data.size() < pattern.size()) {
        return matches;
    }

    const std::size_t last = data.size() - pattern.size();
    for (std::size_t i = 0; i <= last; ++i) {
        bool matched = true;
        for (std::size_t j = 0; j < pattern.size(); ++j) {
            if (!pattern[j].wildcard && data[i + j] != pattern[j].value) {
                matched = false;
                break;
            }
        }
        if (matched) {
            matches.push_back(i);
        }
    }

    return matches;
}
