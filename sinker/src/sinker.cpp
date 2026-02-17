#include <array>
#include <cassert>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <istream>
#include <sha256.hpp>
#include <windows.h>

#include <sinker/sinker.hpp>

namespace sinker {
std::size_t SizeOfType(Type type) {
    switch (type) {
    case Type::None:
        return 0;
    case Type::U8:
    case Type::I8:
        return 1;
    case Type::U16:
    case Type::I16:
        return 2;
    case Type::U32:
    case Type::I32:
        return 4;
    case Type::U64:
    case Type::I64:
        return 8;
    case Type::PTR:
        return sizeof(void *);
    }
    assert(!"Unreachable");
    return 0;
}

char const *TypeToString(Type type) {
    switch (type) {
    case Type::None:
        return "none";
    case Type::U8:
        return "u8";
    case Type::U16:
        return "u16";
    case Type::U32:
        return "u32";
    case Type::U64:
        return "u64";
    case Type::I8:
        return "i8";
    case Type::I16:
        return "i16";
    case Type::I32:
        return "i32";
    case Type::I64:
        return "i64";
    case Type::PTR:
        return "ptr";
    }
    assert(!"Unreachable");
    return nullptr;
}

template <typename T>
std::optional<expression_value_t>
CheckedDereferenceT(expression_value_t value) {
    T result = {};
    SIZE_T in_size = sizeof(result);
    SIZE_T out_size = 0;

    BOOL success = ReadProcessMemory(GetCurrentProcess(), (LPCVOID)value,
                                     &result, in_size, &out_size);

    if (success && in_size == out_size) {
        return static_cast<expression_value_t>(result);
    }

    return {};
}

std::optional<expression_value_t> CheckedDereference(expression_value_t value,
                                                     Type type) {
    switch (type) {
    case Type::U8:
        return CheckedDereferenceT<std::uint8_t>(value);
    case Type::U16:
        return CheckedDereferenceT<std::uint16_t>(value);
    case Type::U32:
        return CheckedDereferenceT<std::uint32_t>(value);
    case Type::U64:
        return CheckedDereferenceT<std::uint64_t>(value);
    case Type::I8:
        return CheckedDereferenceT<std::int8_t>(value);
    case Type::I16:
        return CheckedDereferenceT<std::int16_t>(value);
    case Type::I32:
        return CheckedDereferenceT<std::int32_t>(value);
    case Type::I64:
        return CheckedDereferenceT<std::int64_t>(value);
    case Type::PTR:
        return CheckedDereferenceT<std::uintptr_t>(value);
    default:
        return {};
    }
}

std::ostream &operator<<(std::ostream &out,
                         attribute_value_t const &attribute_value) {
    if (std::holds_alternative<expression_value_t>(attribute_value)) {
        out << std::get<expression_value_t>(attribute_value);
    } else if (std::holds_alternative<bool>(attribute_value)) {
        out << std::boolalpha << std::get<bool>(attribute_value);
    } else {
        out << "\"" << std::get<std::string>(attribute_value) << "\"";
    }
    return out;
}

Symbol *Module::get_symbol(std::string_view symbol_name) {
    for (Symbol &symbol : symbols) {
        if (symbol_name == symbol.get_name()) {
            return &symbol;
        }
    }
    return nullptr;
}
Symbol *Module::emplace_symbol(std::string const &name,
                               std::string const &type) {
    if (get_symbol(name)) {
        return nullptr;
    }
    symbols.push_back(Symbol(name, type, this));
    return &symbols.back();
}
void Module::add_variant(
    std::string const &name,
    std::variant<sha256_digest_t, std::shared_ptr<Expression>> const
        &variant_condition) {
    variants.push_back({name, variant_condition});
}
bool Module::has_variant(std::string_view name) const {
    for (auto const &variant : variants) {
        if (variant.first == name) {
            return true;
        }
    }
    return false;
}
void Module::dump(std::ostream &out) const {
    out << "module " << name;
    if (lpModuleName) {
        out << ", \"" << lpModuleName.value() << "\"";
    }
    out << ";\n";

    for (auto const &attribute : get_attributes()) {
        out << "set " << name << ", " << attribute.first << ", "
            << attribute.second << ";\n";
    }

    for (auto it = tags.begin(); it != tags.end(); ++it) {
        out << "tag " << name << ", " << *it << ";\n";
    }

    for (auto variant : variants) {
        out << "variant " << name << ", " << variant.first << ", ";
        if (sha256_digest_t const *hash =
                std::get_if<sha256_digest_t>(&variant.second)) {
            char hash_string[SHA256_STR_LENGTH];
            hash_to_string(*hash, hash_string, sizeof(hash_string));
            out << '"' << hash_string << "\"";
        } else if (std::shared_ptr<Expression> const *expression =
                       std::get_if<std::shared_ptr<Expression>>(
                           &variant.second)) {
            out << **expression;
        }
        out << ";\n";
    }

    for (Symbol const &symbol : symbols) {
        symbol.dump(out);
    }
}

identifier_set_t const &Context::get_symbol_tags() const { return symbol_tags; }

void Module::dump_def(std::ostream &out) const {
    out << "#ifndef SINKER_" << name << "_SYMBOL\n";
    out << "#define SINKER_" << name << "_SYMBOL(symbol_name, symbol_type)\n";
    out << "#endif\n";
    for (auto it = get_context()->get_symbol_tags().begin();
         it != get_context()->get_symbol_tags().end(); ++it) {
        out << "#ifndef SINKER_" << name << "_TAG_" << *it << "_SYMBOL\n";
        out << "#define SINKER_" << name << "_TAG_" << *it
            << "_SYMBOL(symbol_name, symbol_type)\n";
        out << "#endif\n";
    }
    out << "SINKER_MODULE(" << name << ")\n";

    for (auto it = tags.begin(); it != tags.end(); ++it) {
        out << "SINKER_TAG_" << *it << "_MODULE(" << name << ")\n";
    }

    for (Symbol const &symbol : symbols) {
        symbol.dump_def(out);
    }

    for (auto it = get_context()->get_symbol_tags().rbegin();
         it != get_context()->get_symbol_tags().rend(); ++it) {
        out << "#undef SINKER_" << name << "_TAG_" << *it << "_SYMBOL\n";
    }
    out << "#undef SINKER_" << name << "_SYMBOL\n";
}
std::optional<expression_value_t> Module::get_relocated_base_address() const {
    return relocated_base_address;
}
HMODULE Module::get_hModule() const { return hModule; }
std::optional<expression_value_t> Module::get_preferred_base_address() const {
    return preferred_base_address;
}
std::string const &Module::get_name() const { return name; }
std::string const &Module::get_real_variant() const { return real_variant; }

bool Module::concretize() {
    if (lpModuleName) {
        hModule = GetModuleHandleA(lpModuleName.value().c_str());
    } else {
        hModule = GetModuleHandleA(NULL);
    }

    if (hModule == NULL) {
        return false;
    }

    IMAGE_DOS_HEADER *pDOSHeader = (IMAGE_DOS_HEADER *)hModule;
    IMAGE_NT_HEADERS *pNTHeaders =
        (IMAGE_NT_HEADERS *)((BYTE *)pDOSHeader + pDOSHeader->e_lfanew);

    preferred_base_address = pNTHeaders->OptionalHeader.ImageBase;
    relocated_base_address = (expression_value_t)hModule;

    char path[MAX_PATH + 1];
    if (!GetModuleFileNameA(hModule, path, MAX_PATH + 1)) {
        hModule = NULL;
        return false;
    }

    sha256_digest_t hash;
    if (!sha256_file(path, hash)) {
        hModule = NULL;
        return false;
    }

    for (auto variant : variants) {
        sha256_digest_t const *expected_hash =
            std::get_if<sha256_digest_t>(&variant.second);
        if (expected_hash && *expected_hash == hash) {
            real_variant = variant.first;
            break;
        }

        std::shared_ptr<Expression> const *expression =
            std::get_if<std::shared_ptr<Expression>>(&variant.second);
        if (expression && (*expression)->calculate(this).has_value()) {
            real_variant = variant.first;
            break;
        }
    }

    return true;
}

bool Module::is_concrete() const { return hModule; }

Module *Symbol::get_module() const { return module; }

void Symbol::add_address(identifier_set_t const &variant_set,
                         std::shared_ptr<Expression> expression) {
    addresses.push_back({variant_set, std::move(expression)});
}

std::map<std::string, attribute_value_t, std::less<>> const &
Attributable::get_attributes() const {
    return attributes;
}

void Symbol::dump_def(std::ostream &out) const {
    out << "SINKER_SYMBOL(" << module->get_name() << ", " << name << ", "
        << type << ")\n";
    for (auto it = tags.begin(); it != tags.end(); ++it) {
        out << "SINKER_TAG_" << *it << "_SYMBOL(" << module->get_name() << ", "
            << name << ", " << type << ")\n";
    }
    out << "SINKER_" << module->get_name() << "_SYMBOL(" << name << ", " << type
        << ")\n";
    for (auto it = tags.begin(); it != tags.end(); ++it) {
        out << "SINKER_" << module->get_name() << "_TAG_" << *it << "_SYMBOL("
            << name << ", " << type << ")\n";
    }
}

void Context::dump(std::ostream &out) const {
    for (Module const *module : modules) {
        module->dump(out);
    }
}

void Context::dump_def(std::ostream &out) const {
    out <<
        R"%(#ifndef SINKER_MODULE
#define SINKER_MODULE(module_name)
#endif
#ifndef SINKER_SYMBOL
#define SINKER_SYMBOL(module_name, symbol_name, symbol_type)
#endif
)%";

    for (auto it = module_tags.begin(); it != module_tags.end(); ++it) {
        out << "#ifndef SINKER_TAG_" << *it << "_MODULE\n"
            << "#define SINKER_TAG_" << *it << "_MODULE(module_name)\n"
            << "#endif\n";
    }

    for (auto it = symbol_tags.begin(); it != symbol_tags.end(); ++it) {
        out << "#ifndef SINKER_TAG_" << *it << "_SYMBOL\n"
            << "#define SINKER_TAG_" << *it
            << "_SYMBOL(module_name, symbol_name, symbol_type)\n"
            << "#endif\n";
    }

    out << '\n';

    for (Module const *module : modules) {
        module->dump_def(out);
        out << "\n";
    }

    for (auto it = symbol_tags.rbegin(); it != symbol_tags.rend(); ++it) {
        out << "#undef SINKER_TAG_" << *it << "_SYMBOL\n";
    }

    for (auto it = module_tags.rbegin(); it != module_tags.rend(); ++it) {
        out << "#undef SINKER_TAG_" << *it << "_MODULE\n";
    }

    out <<
        R"%(#undef SINKER_MODULE
#undef SINKER_SYMBOL
)%";
}

Module *Context::get_module(std::string_view module_name) {
    for (Module *module : modules) {
        if (module_name == module->get_name()) {
            return module;
        }
    }

    return nullptr;
}

std::string const &UserOp::get_name() const { return name; }
expression_value_t(__cdecl *UserOp::get_fn() const)(...) { return fn; }
std::size_t UserOp::get_min_arity() const { return min_arity; }
std::optional<std::size_t> UserOp::get_max_arity() const { return max_arity; }
bool UserOp::accepts_arity(std::size_t arity) const {
    if (arity < min_arity) {
        return false;
    }
    if (max_arity && arity > max_arity.value()) {
        return false;
    }
    return true;
}

UserOp *Context::get_user_op(std::string_view user_op_name) {
    for (UserOp *user_op : user_ops) {
        if (user_op_name == user_op->get_name()) {
            return user_op;
        }
    }

    return nullptr;
}

Context::~Context() {
    for (Module *module : modules) {
        delete module;
    }
    for (UserOp *user_op : user_ops) {
        delete user_op;
    }
}

Module *Context::emplace_module(std::string_view name,
                                std::optional<std::string> lpModuleName) {
    if (get_module(name)) {
        return nullptr;
    }
    Module *module = new Module(name, lpModuleName, this);
    modules.push_back(module);
    return module;
}

UserOp *Context::emplace_user_op_impl(
    std::string_view name, expression_value_t(__cdecl *fn)(...),
    std::size_t min_arity, std::optional<std::size_t> max_arity) {
    if (get_user_op(name)) {
        return nullptr;
    }
    UserOp *user_op = new UserOp(name, fn, min_arity, max_arity);
    user_ops.push_back(user_op);
    return user_op;
}

void Symbol::dump(std::ostream &out) const {
    out << "symbol " << module->get_name() << "::" << name << ", \"" << type
        << "\";\n";

    for (auto const &attribute : get_attributes()) {
        out << "set " << module->get_name() << "::" << name << ", "
            << attribute.first << ", " << attribute.second << ";\n";
    }

    for (auto it = tags.begin(); it != tags.end(); ++it) {
        out << "tag " << module->get_name() << "::" << name << ", " << *it
            << ";\n";
    }

    for (auto const &address : addresses) {
        out << "address " << module->get_name() << "::" << name << ", [";
        if (address.first.empty()) {
            out << "*";
        } else {
            auto it = address.first.begin();
            out << *it;
            ++it;

            for (; it != address.first.end(); ++it) {
                out << ", " << *it;
            }
        }
        out << "], " << *address.second << ";\n";
    }
}

Context *Module::get_context() const { return context; }

void Symbol::add_tag(std::string const &tag) {
    tags.insert(tag);
    get_module()->get_context()->add_symbol_tag(tag);
}

void Module::add_tag(std::string const &tag) {
    tags.insert(tag);
    get_context()->add_module_tag(tag);
}

void Context::add_module_tag(std::string const &tag) {
    module_tags.insert(tag);
}

void Context::add_symbol_tag(std::string const &tag) {
    symbol_tags.insert(tag);
}

std::ostream &operator<<(std::ostream &os, Expression const &expression) {
    expression.dump(os);
    return os;
}

std::ostream &operator<<(std::ostream &os, Module const &module) {
    module.dump(os);
    return os;
}

std::ostream &operator<<(std::ostream &os, Symbol const &symbol) {
    symbol.dump(os);
    return os;
}

std::ostream &operator<<(std::ostream &os, Context const &context) {
    context.dump(os);
    return os;
}

} // namespace sinker
