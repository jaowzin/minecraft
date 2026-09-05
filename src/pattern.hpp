#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

struct PatternByte {
    std::uint8_t value{};
    bool wildcard{};
};

using BytePattern = std::vector<PatternByte>;

std::optional<BytePattern> parsePattern(const std::string& text, std::string& error);
std::vector<std::size_t> findPatternMatches(const std::vector<std::uint8_t>& data, const BytePattern& pattern);
