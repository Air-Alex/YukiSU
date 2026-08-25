/*
 * Minimal self-contained JSON (value / parse / dump). Header-only and suitable
 * for small ksud and zygiskd configuration files.
 */
#pragma once

#include <array>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <string>
#include <vector>

namespace json {

enum class Type { Null, Bool, Number, String, Array, Object };

struct Value;

using Array = std::vector<Value>;
using Object = std::map<std::string, Value>;

struct Value {
    Type type = Type::Null;
    bool b = false;
    double n = 0;
    std::string s;
    Array a;
    Object o;

    Value() = default;
    Value(bool v) : type(Type::Bool), b(v) {}
    Value(int v) : type(Type::Number), n(static_cast<double>(v)) {}
    Value(double v) : type(Type::Number), n(v) {}
    Value(const char* v) : type(Type::String), s(v) {}
    Value(const std::string& v) : type(Type::String), s(v) {}
    Value(const Array& v) : type(Type::Array), a(v) {}
    Value(const Object& v) : type(Type::Object), o(v) {}

    static Value object() { return Value(Object{}); }
    static Value array() { return Value(Array{}); }

    Value& operator[](const std::string& key) {
        if (type != Type::Object) {
            type = Type::Object;
            o.clear();
        }
        return o[key];
    }

    // const lookup that doesn't insert; returns a Null Value if absent.
    const Value& at(const std::string& key) const {
        static const Value null_value;
        if (type != Type::Object)
            return null_value;
        auto it = o.find(key);
        return it == o.end() ? null_value : it->second;
    }
    bool contains(const std::string& key) const {
        return type == Type::Object && o.count(key) != 0;
    }

    void push_back(const Value& v) {
        if (type != Type::Array) {
            type = Type::Array;
            a.clear();
        }
        a.push_back(v);
    }

    bool as_bool() const { return b; }
    double as_number() const { return n; }
    std::string as_string() const { return s; }
    const Array& as_array() const { return a; }
    const Object& as_object() const { return o; }
};

inline std::string escape_string(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 2);
    out += '"';
    for (char c : s) {
        if (c == '"')
            out += "\\\"";
        else if (c == '\\')
            out += "\\\\";
        else if (c == '\b')
            out += "\\b";
        else if (c == '\f')
            out += "\\f";
        else if (c == '\n')
            out += "\\n";
        else if (c == '\r')
            out += "\\r";
        else if (c == '\t')
            out += "\\t";
        else if ((unsigned char)c < 0x20) {
            std::array<char, 7> esc{};
            (void)snprintf(esc.data(), esc.size(), "\\u%04x", (unsigned)(unsigned char)c);
            out += esc.data();
        } else
            out += c;
    }
    out += '"';
    return out;
}

inline std::string dump(const Value& v, int indent = -1, int level = 0) {
    switch (v.type) {
    case Type::Null:
        return "null";
    case Type::Bool:
        return v.b ? "true" : "false";
    case Type::Number: {
        std::string s = std::to_string(v.n);
        s.erase(s.find_last_not_of('0') + 1, std::string::npos);
        if (!s.empty() && s.back() == '.')
            s.pop_back();
        return s;
    }
    case Type::String:
        return escape_string(v.s);
    case Type::Array: {
        if (v.a.empty())
            return "[]";
        std::string out = "[";
        if (indent >= 0)
            out += '\n';
        for (size_t i = 0; i < v.a.size(); ++i) {
            if (indent >= 0)
                out.append((size_t)((level + 1) * indent), ' ');
            out += dump(v.a[i], indent, level + 1);
            if (i + 1 < v.a.size())
                out += (indent >= 0) ? ",\n" : ", ";
        }
        if (indent >= 0) {
            out += '\n';
            out.append((size_t)(level * indent), ' ');
        }
        out += ']';
        return out;
    }
    case Type::Object: {
        if (v.o.empty())
            return "{}";
        std::string out = "{";
        if (indent >= 0)
            out += '\n';
        size_t i = 0;
        for (const auto& kv : v.o) {
            if (indent >= 0)
                out.append((size_t)((level + 1) * indent), ' ');
            out += escape_string(kv.first);
            out += ':';
            if (indent >= 0)
                out += ' ';
            out += dump(kv.second, indent, level + 1);
            if (++i < v.o.size())
                out += (indent >= 0) ? ",\n" : ", ";
        }
        if (indent >= 0) {
            out += '\n';
            out.append((size_t)(level * indent), ' ');
        }
        out += '}';
        return out;
    }
    }
    return "";
}

class Parser {
    const std::string& str;
    size_t pos = 0;

    void skip_whitespace() {
        while (pos < str.size() && std::isspace((unsigned char)str[pos]))
            pos++;
    }

    Value parse_value() {
        skip_whitespace();
        if (pos >= str.size())
            return Value();
        char c = str[pos];
        if (c == 'n') {
            pos += 4;
            return Value();
        }
        if (c == 't') {
            pos += 4;
            return Value(true);
        }
        if (c == 'f') {
            pos += 5;
            return Value(false);
        }
        if (c == '"')
            return parse_string();
        if (c == '[')
            return parse_array();
        if (c == '{')
            return parse_object();
        if (c == '-' || std::isdigit((unsigned char)c))
            return parse_number();
        return Value();
    }

    Value parse_string() {
        std::string s;
        pos++;  // skip "
        while (pos < str.size()) {
            char c = str[pos++];
            if (c == '"')
                break;
            if (c == '\\') {
                if (pos >= str.size())
                    break;
                char next = str[pos++];
                if (next == 'n')
                    s += '\n';
                else if (next == 't')
                    s += '\t';
                else if (next == '"')
                    s += '"';
                else if (next == '\\')
                    s += '\\';
                else
                    s += next;
            } else {
                s += c;
            }
        }
        return Value(s);
    }

    Value parse_number() {
        const size_t start = pos;
        while (pos < str.size() &&
               (std::isdigit((unsigned char)str[pos]) || str[pos] == '-' || str[pos] == '.'))
            pos++;
        // strtod lives in libc, so it costs nothing here, while std::from_chars
        // for double drags in libc++'s float conversion tables. The token is a
        // substring of a std::string, so it is NUL-terminated at its own end
        // only after the copy; keep the copy for that reason.
        const std::string token = str.substr(start, pos - start);
        char* end = nullptr;
        errno = 0;
        const double value = std::strtod(token.c_str(), &end);
        if (end != token.c_str() + token.size() || errno == ERANGE)
            return Value(0.0);
        return Value(value);
    }

    Value parse_array() {
        Value v;
        v.type = Type::Array;
        pos++;  // skip [
        while (pos < str.size()) {
            skip_whitespace();
            if (pos >= str.size() || str[pos] == ']') {
                if (pos < str.size())
                    pos++;
                break;
            }
            v.a.push_back(parse_value());
            skip_whitespace();
            if (pos < str.size() && str[pos] == ',')
                pos++;
        }
        return v;
    }

    Value parse_object() {
        Value v;
        v.type = Type::Object;
        pos++;  // skip {
        while (pos < str.size()) {
            skip_whitespace();
            if (pos >= str.size() || str[pos] == '}') {
                if (pos < str.size())
                    pos++;
                break;
            }
            Value key = parse_string();
            skip_whitespace();
            if (pos < str.size() && str[pos] == ':')
                pos++;
            v.o[key.s] = parse_value();
            skip_whitespace();
            if (pos < str.size() && str[pos] == ',')
                pos++;
        }
        return v;
    }

public:
    explicit Parser(const std::string& s) : str(s) {}
    Value parse() { return parse_value(); }
};

inline Value parse(const std::string& s) {
    return Parser(s).parse();
}

}  // namespace json
