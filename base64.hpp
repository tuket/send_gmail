#pragma once

#include <string>
#include <vector>

namespace tl
{
namespace base64
{

std::string encode(const unsigned char* data, std::size_t length);
std::string encode(const std::vector<unsigned char> data);
std::string encode(const std::string& data);


std::vector<unsigned char> decode(const char* str, std::size_t length);
std::vector<unsigned char> decode(const std::string& str);

}
}