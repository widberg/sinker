#ifndef SINKER_HPP
#define SINKER_HPP

#include <Windows.h>
#include <detours.h>

#include <map>
#include <set>
#include <variant>
#include <string>
#include <string_view>
#include <optional>
#include <ostream>
#include <iostream>
#include <iomanip>
#include <memory>
#include <set>
#include <cstdint>
#include <cstddef>
#include <vector>
#include <algorithm>
#include <functional>
#include <cassert>

namespace sinker
{

    enum class Language
    {
        SINKER,
        SOURCE_CODE,
    };

    typedef unsigned long long expression_value_t;
    typedef std::variant<expression_value_t, bool, std::string> attribute_value_t;
    typedef std::set<std::string> identifier_set_t;

    std::ostream &operator<<(std::ostream &out, attribute_value_t const &attribute_value);

    struct MaskedByte
    {
        std::uint8_t value;
        std::uint8_t mask;
    };

    class Context;
    class Symbol;

    class Expression
    {
    public:
        virtual std::optional<expression_value_t> calculate(Symbol *symbol) const = 0;
        virtual void dump(std::ostream &out) const = 0;
        virtual ~Expression() {}
    };

    std::ostream &operator<<(std::ostream &os, Expression const &expression);

    class Attributable
    {
    public:
        template <typename T>
        std::optional<T> get_attribute(std::string_view attribute_name) const;

        template <typename T>
        void set_attribute(std::string const &attribute_name, T value);

        std::map<std::string, attribute_value_t, std::less<>> const &get_attributes() const;

    private:
        std::map<std::string, attribute_value_t, std::less<>> attributes;
    };

    class Module;

    class Context
    {
    public:
        Context() {}
        Context(const Context &) = delete;
        Context &operator=(const Context &) = delete;
        std::vector<Module*> const &get_modules() const
        {
            return modules;
        }
        Module *get_module(std::string_view module_name);

        void emplace_module(std::string_view name, std::optional<std::string> lpModuleName);
        void dump(std::ostream &out) const;
        void dump_def(std::ostream &out) const;
        bool interpret(std::istream &input_stream, Language language, std::string input_filename, bool debug = false);
        bool interpret(const char *input, std::size_t size, Language language, std::string input_filename, bool debug = false);
        bool interpret(const std::string& input, Language language, std::string input_filename, bool debug = false);
        void add_module_tag(std::string const& tag);
        void add_symbol_tag(std::string const& tag);
        identifier_set_t const& get_symbol_tags() const;
        ~Context();
    private:
        std::vector<Module*> modules;
        identifier_set_t module_tags;
        identifier_set_t symbol_tags;
    };

    std::ostream &operator<<(std::ostream &os, Context const &context);

    class Symbol : public Attributable
    {
        friend class Module;

    public:
        Symbol(const Symbol &) = delete;
        Symbol &operator=(const Symbol &) = delete;
        Symbol(Symbol &&) = default;
        Symbol &operator=(Symbol &&mE) = default;
        std::string const &get_name() const
        {
            return name;
        }
        template <typename T>
        std::optional<T> calculate_address();

        template <typename T>
        std::optional<T> get_cached_calculated_address() const;

        Module *get_module() const;

        void add_address(identifier_set_t const &variant_set, std::shared_ptr<Expression> expression);
        void dump(std::ostream &out) const;

        void dump_def(std::ostream &out) const;
        void add_tag(std::string const& tag);

    private:
        Symbol(std::string const &name, std::string const &type, Module *module)
            : name(name), type(type), module(module) {}
        std::optional<expression_value_t> cached_calculated_address;
        std::string name;
        std::string type;
        Module *module;
        std::vector<std::pair<identifier_set_t, std::shared_ptr<Expression>>> addresses;
        identifier_set_t tags;
    };

    std::ostream &operator<<(std::ostream &os, Symbol const &symbol);

    class Module : public Attributable
    {
        friend class Context;

    public:
        Module(const Module &) = delete;
        Module &operator=(const Module &) = delete;
        Module(Module &&) = default;
        Module &operator=(Module &&mE) = default;
        std::string const &get_name() const;
        std::string const &get_real_variant() const;
        Symbol *get_symbol(std::string_view symbol_name);

        void emplace_symbol(std::string const &name, std::string const &type);
        void add_variant(std::string const &name, std::string const &hash);
        bool has_variant(std::string_view name) const;
        void dump(std::ostream &out) const;
        void dump_def(std::ostream &out) const;
        std::optional<expression_value_t> get_preferred_base_address() const;
        std::optional<expression_value_t> get_relocated_base_address() const;
        HMODULE get_hModule() const;
        void add_tag(std::string const& tag);
        Context *get_context() const;
        bool concretize();
        bool is_concrete() const;

    private:
        Module(std::string_view name, std::optional<std::string> lpModuleName, Context *context)
            : context(context), name(name), lpModuleName(lpModuleName){};
        Context *context;
        std::string name;
        std::optional<std::string> lpModuleName;
        std::optional<expression_value_t> preferred_base_address;
        std::optional<expression_value_t> relocated_base_address;
        std::vector<Symbol> symbols;
        std::map<std::string, std::string, std::less<>> variants;
        std::string real_variant;
        HMODULE hModule = 0;
        identifier_set_t tags;
    };

    std::ostream &operator<<(std::ostream &os, Module const &module);

#define PROPAGATE_UNRESOLVED(x) \
    do                          \
    {                           \
        if (!x)                 \
            return {};          \
    } while (0)

    class IntegerExpression final : Expression
    {
    public:
        IntegerExpression(expression_value_t value)
            : value(value) {}
        virtual std::optional<expression_value_t> calculate(Symbol *symbol) const override
        {
            return value;
        }
        virtual void dump(std::ostream &out) const override
        {
            out << value;
        }

    private:
        expression_value_t value;
    };

    enum class Type
    {
        None,
        U8,
        U16,
        U32,
        U64,
        I8,
        I16,
        I32,
        I64,
        PTR,
    };

    std::size_t SizeOfType(Type type);
    const char *TypeToString(Type type);

    std::optional<expression_value_t> CheckedDereference(expression_value_t value, Type type);

    enum class UnaryOperator
    {
        PARENTHESES,
        INDIRECTION,
        RELOCATION,
        BITWISE_NOT,
        SIZEOF,
    };

    class UnaryOperatorExpression final : Expression
    {
    public:
        UnaryOperatorExpression(std::shared_ptr<Expression> expression, UnaryOperator unary_operator, Type type)
            : expression(expression), unary_operator(unary_operator), type(type) {}
        virtual std::optional<expression_value_t> calculate(Symbol *symbol) const override
        {
            if (unary_operator == UnaryOperator::SIZEOF)
            {
                return (expression_value_t)SizeOfType(type);
            }

            auto expression_result = expression->calculate(symbol);
            PROPAGATE_UNRESOLVED(expression_result);

            switch (unary_operator)
            {
            case UnaryOperator::PARENTHESES:
                return expression_result.value();
            case UnaryOperator::INDIRECTION:
                return CheckedDereference(expression_result.value(), type);
            case UnaryOperator::RELOCATION:
            {
                auto preferred_base_address_result = symbol->get_module()->get_preferred_base_address();
                PROPAGATE_UNRESOLVED(preferred_base_address_result);
                auto relocated_base_address_result = symbol->get_module()->get_relocated_base_address();
                PROPAGATE_UNRESOLVED(relocated_base_address_result);
                return expression_result.value() - preferred_base_address_result.value() + relocated_base_address_result.value();
            }
            case UnaryOperator::BITWISE_NOT:
                return ~expression_result.value();
            case UnaryOperator::SIZEOF:
                // Handled above
                break;
            }
            assert(!"Unreachable");
            return {};
        }

        virtual void dump(std::ostream &out) const override
        {
            switch (unary_operator)
            {
            case UnaryOperator::PARENTHESES:
                out << "(" << *expression << ")";
                break;
            case UnaryOperator::INDIRECTION:
                out << TypeToString(type) << "*" << *expression;
                break;
            case UnaryOperator::RELOCATION:
                out << "@" << *expression;
                break;
            case UnaryOperator::BITWISE_NOT:
                out << "~" << *expression;
                break;
            }
        }

    private:
        std::shared_ptr<Expression> expression;
        UnaryOperator unary_operator;
        Type type;
    };

    enum class BinaryOperator
    {
        ADDITION,
        SUBTRACTION,
        MULTIPLICATION,
        INTEGER_DIVISION,
        MODULO,
        BITWISE_AND,
        BITWISE_OR,
        BITWISE_XOR,
        BITWISE_SHIFT_LEFT,
        BITWISE_SHIFT_RIGHT,
        ARRAY_SUBSCRIPT,
        POINTER_PATH,
        SHORT_CIRCUIT_AND,
        SHORT_CIRCUIT_OR,
    };

    class BinaryOperatorExpression final : Expression
    {
    public:
        BinaryOperatorExpression(std::shared_ptr<Expression> lhs, std::shared_ptr<Expression> rhs, BinaryOperator binary_operator, Type type)
            : lhs(lhs), rhs(rhs), binary_operator(binary_operator), type(type) {}
        virtual std::optional<expression_value_t> calculate(Symbol *symbol) const override
        {
            auto lhs_result = lhs->calculate(symbol);

            if (binary_operator == BinaryOperator::SHORT_CIRCUIT_OR)
            {
                if (lhs_result)
                {
                    return lhs_result;
                }
            }

            auto rhs_result = rhs->calculate(symbol);

            if (binary_operator == BinaryOperator::SHORT_CIRCUIT_OR) {
                if (rhs_result)
                {
                    return rhs_result;
                }
            }

            PROPAGATE_UNRESOLVED(lhs_result);

            if (binary_operator == BinaryOperator::SHORT_CIRCUIT_AND)
            {
                return rhs_result;
            }

            PROPAGATE_UNRESOLVED(rhs_result);

            switch (binary_operator)
            {
            case BinaryOperator::ADDITION:
                return lhs_result.value() + rhs_result.value();
            case BinaryOperator::SUBTRACTION:
                return lhs_result.value() - rhs_result.value();
            case BinaryOperator::MULTIPLICATION:
                return lhs_result.value() * rhs_result.value();
            case BinaryOperator::INTEGER_DIVISION:
                return lhs_result.value() / rhs_result.value();
            case BinaryOperator::MODULO:
                return lhs_result.value() % rhs_result.value();
            case BinaryOperator::BITWISE_AND:
                return lhs_result.value() & rhs_result.value();
            case BinaryOperator::BITWISE_OR:
                return lhs_result.value() | rhs_result.value();
            case BinaryOperator::BITWISE_XOR:
                return lhs_result.value() ^ rhs_result.value();
            case BinaryOperator::BITWISE_SHIFT_LEFT:
                return lhs_result.value() << rhs_result.value();
            case BinaryOperator::BITWISE_SHIFT_RIGHT:
                return lhs_result.value() >> rhs_result.value();
            case BinaryOperator::ARRAY_SUBSCRIPT:
                return CheckedDereference(lhs_result.value() + rhs_result.value() * SizeOfType(type), type);
            case BinaryOperator::POINTER_PATH:
            {
                auto result = CheckedDereference(lhs_result.value(), Type::PTR);
                PROPAGATE_UNRESOLVED(result);
                return result.value() + rhs_result.value();
            }
            case BinaryOperator::SHORT_CIRCUIT_AND:
            case BinaryOperator::SHORT_CIRCUIT_OR:
                // Handled above
                break;
            }
            assert(!"Unreachable");
            return {};
        }

        virtual void dump(std::ostream &out) const override
        {
            switch (binary_operator)
            {
            case BinaryOperator::ADDITION:
                out << *lhs << " + " << *rhs;
                break;
            case BinaryOperator::SUBTRACTION:
                out << *lhs << " - " << *rhs;
                break;
            case BinaryOperator::MULTIPLICATION:
                out << *lhs << " * " << *rhs;
                break;
            case BinaryOperator::INTEGER_DIVISION:
                out << *lhs << " / " << *rhs;
                break;
            case BinaryOperator::MODULO:
                out << *lhs << " % " << *rhs;
                break;
            case BinaryOperator::BITWISE_AND:
                out << *lhs << " & " << *rhs;
                break;
            case BinaryOperator::BITWISE_OR:
                out << *lhs << " | " << *rhs;
                break;
            case BinaryOperator::BITWISE_XOR:
                out << *lhs << " ^ " << *rhs;
                break;
            case BinaryOperator::BITWISE_SHIFT_LEFT:
                out << *lhs << " << " << *rhs;
                break;
            case BinaryOperator::BITWISE_SHIFT_RIGHT:
                out << *lhs << " >> " << *rhs;
                break;
            case BinaryOperator::ARRAY_SUBSCRIPT:
                out << TypeToString(type) << *lhs << "[" << *rhs << "]";
                break;
            case BinaryOperator::POINTER_PATH:
                out << *lhs << "->" << *rhs;
                break;
            case BinaryOperator::SHORT_CIRCUIT_AND:
                out << *lhs << " && " << *rhs;
                break;
            case BinaryOperator::SHORT_CIRCUIT_OR:
                out << *lhs << " || " << *rhs;
                break;
            }
        }

    private:
        std::shared_ptr<Expression> lhs;
        std::shared_ptr<Expression> rhs;
        BinaryOperator binary_operator;
        Type type;
    };

    class GetProcAddressExpression final : Expression
    {
    public:
        GetProcAddressExpression(Module *module, std::string const &lpProcName)
            : module(module), lpProcName(lpProcName) {}
        virtual std::optional<expression_value_t> calculate(Symbol *symbol) const override
        {
            HMODULE hModule = module->get_hModule();
            if (!hModule)
            {
                return {};
            }

            FARPROC addr = GetProcAddress(hModule, lpProcName.c_str());

            if (addr)
            {
                return (expression_value_t)addr;
            }

            return {};
        }
        virtual void dump(std::ostream &out) const override
        {
            out << "!" << module->get_name() << "::" << lpProcName;
        }

    private:
        Module *module;
        std::string lpProcName;
    };

    class ModuleExpression final : Expression
    {
    public:
        ModuleExpression(Module *module)
            : module(module) {}
        virtual std::optional<expression_value_t> calculate(Symbol *symbol) const override
        {
            return module->get_relocated_base_address();
        }
        virtual void dump(std::ostream &out) const override
        {
            out << module->get_name();
        }

    private:
        Module *module;
    };

    class SymbolExpression final : Expression
    {
    public:
        SymbolExpression(Symbol *symbol)
            : symbol(symbol) {}
        virtual std::optional<expression_value_t> calculate(Symbol *_symbol) const override
        {
            return symbol->get_cached_calculated_address<expression_value_t>();
        }
        virtual void dump(std::ostream &out) const override
        {
            out << symbol->get_module()->get_name() << "::" << symbol->get_name();
        }

    private:
        Symbol *symbol;
    };

    enum class PatternMatchType
    {
        EXACT,
        MASK,
        WILDCARD,
        COUNT,
    };

    class PatternMatchFragment
    {
    public:
        virtual ~PatternMatchFragment() {}
        virtual void *search(void *begin, void *end) const = 0;
        virtual bool begins_with(void *begin, void *end) const = 0;
        virtual bool collision(void *address) const = 0;
        virtual std::size_t size() const = 0;
        virtual PatternMatchType type() const = 0;
    };

    class PatternMatchExact final : PatternMatchFragment
    {
    public:
        PatternMatchExact(const std::vector<std::uint8_t>& value)
            : value(value) {}
        
        virtual void *search(void *begin, void *end) const override
        {
            if (end < begin)
            {
                return end;
            }
            
            return std::search((std::uint8_t*)begin, (std::uint8_t*)end, value.cbegin(), value.cend());
        }

        virtual bool begins_with(void *begin, void *end) const override
        {
            if (end < begin || (std::uint8_t*)begin + size() > end)
            {
                return end;
            }
            
            return std::equal((std::uint8_t*)begin, (std::uint8_t*)begin + size(), value.cbegin(), value.cend());
        }

        virtual std::size_t size() const override
        {
            return value.size();
        }

        virtual PatternMatchType type() const override
        {
            return PatternMatchType::EXACT;
        }

        virtual bool collision(void *address) const
        {
            return address >= value.data() && address < value.data() + value.size();
        }
    private:
        std::vector<std::uint8_t> value;
    };

    class PatternMatchMask final : PatternMatchFragment
    {
    public:
        PatternMatchMask(std::vector<MaskedByte> const& value)
            : value(value) {}

        virtual void *search(void *begin, void *end) const override
        {
            if (end < begin)
            {
                return end;
            }
            
            return std::search((std::uint8_t*)begin, (std::uint8_t*)end, value.cbegin(), value.cend(), [](std::uint8_t a, MaskedByte b) {
                return (a & b.mask) == (b.value & b.mask);
            });
        }

        virtual bool begins_with(void *begin, void *end) const override
        {
            if (end < begin || (std::uint8_t*)begin + size() > end)
            {
                return end;
            }
            
            return std::equal((std::uint8_t*)begin, (std::uint8_t*)begin + size(), value.cbegin(), value.cend(), [](std::uint8_t a, MaskedByte b) {
                return (a & b.mask) == (b.value & b.mask);
            });
        }

        virtual std::size_t size() const override
        {
            return value.size();
        }

        virtual PatternMatchType type() const override
        {
            return PatternMatchType::MASK;
        }

        virtual bool collision(void *address) const
        {
            return address >= value.data() && address < value.data() + value.size() * sizeof(MaskedByte);
        }
    private:
        std::vector<MaskedByte> value;
    };

    class PatternMatchWildcard final : PatternMatchFragment
    {
    public:
        PatternMatchWildcard(std::size_t size)
            : s(size) {}

        virtual void *search(void *begin, void *end) const override
        {
            if (end < begin)
            {
                return end;
            }
            
            if (s > (std::size_t)((char *)end - (char *)begin))
            {
                return end;
            }

            return begin;
        }

        virtual bool begins_with(void *begin, void *end) const override
        {
            if (end < begin)
            {
                return end;
            }

            if (s > (std::size_t)((char *)end - (char *)begin))
            {
                return false;
            }

            return true;
        }

        virtual std::size_t size() const override
        {
            return s;
        }

        virtual PatternMatchType type() const override
        {
            return PatternMatchType::WILDCARD;
        }

        virtual bool collision(void *address) const
        {
            return false;
        }
    private:
        std::size_t s;
    };

    class PatternMatchNeedle final
    {
    public:
        PatternMatchNeedle(std::vector<MaskedByte> const& needle)
            : size(needle.size()) {
            std::size_t i = 0;
            while (i < needle.size())
            {
                if (needle[i].mask == 0xFF)
                {
                    std::size_t j = i + 1;
                    while (j < needle.size() && needle[j].mask == 0xFF)
                    {
                        ++j;
                    }

                    std::vector<std::uint8_t> value;
                    value.reserve(j - i);
                    for (std::size_t k = i; k < j; ++k)
                    {
                        value.push_back(needle[k].value);
                    }
                    fragments.emplace_back((PatternMatchFragment*)new PatternMatchExact(value));
                    i = j;
                }
                else if (needle[i].mask == 0x00)
                {
                    std::size_t j = i + 1;
                    while (j < needle.size() && needle[j].mask == 0x00)
                    {
                        ++j;
                    }
                    fragments.emplace_back((PatternMatchFragment*)new PatternMatchWildcard(j - i));
                    i = j;
                }
                else
                {
                    std::size_t j = i + 1;
                    while (j < needle.size() && needle[j].mask != 0x00 && needle[j].mask != 0xFF)
                    {
                        ++j;
                    }
                    fragments.emplace_back((PatternMatchFragment*)new PatternMatchMask(std::vector<MaskedByte>(needle.begin() + i, needle.begin() + j)));
                    i = j;
                }
            }

            // Keep track of the largest fragment from each type
            struct SizeRecord {
                std::size_t size;
                std::size_t offset;
                std::size_t index;
            } sizes[(std::size_t)PatternMatchType::COUNT] = {};

            // Find the largest fragment from each type
            std::size_t total_size = 0;
            for (std::size_t i = 0; i < fragments.size(); ++i)
            {
                auto& fragment = fragments[i];
                if (fragment->size() > sizes[(std::size_t)fragment->type()].size)
                {
                    sizes[(std::size_t)fragment->type()].size = fragment->size();
                    sizes[(std::size_t)fragment->type()].offset = total_size;
                    sizes[(std::size_t)fragment->type()].index = i;

                }
                total_size += fragment->size();
            }

            // Find the highest priority fragment with the largest size
            for (std::size_t i = 0; i < (std::size_t)PatternMatchType::COUNT; ++i)
            {
                if (sizes[i].size != 0)
                {
                    // Search for the fragment
                    index = sizes[i].index;
                    offset = sizes[i].offset;
                    break;
                }
            }
        }

        void *search(void *begin, void *end) const
        {
            if (end < begin)
            {
                return end;
            }

            if (fragments.empty())
            {
                return begin;
            }

            // If the total size of the needle is larger than the search space, then we can't find a match
            if (size > (std::size_t)((char *)end - (char *)begin))
            {
                return end;
            }

            auto& fragment = fragments[index];
            void *result = fragment->search((char *)begin + offset, end);
            if (result == end)
            {
                return end;
            }

            // Now check that the other fragments match
            void *result_begin = (char *)result - offset;
            void *result_offset = result_begin;
            for (std::size_t j = 0; j < fragments.size(); ++j)
            {
                auto& fragment = fragments[j];
                if (j != index)
                {
                    if (!fragment->begins_with(result_offset, end))
                    {
                        return end;
                    }
                }
                result_offset = (char *)result_offset + fragment->size();
            }

            return result_begin;
        }

        virtual bool collision(void *address) const
        {
            for (auto& fragment : fragments)
            {
                if (fragment->collision(address))
                    return true;
            }
            return false;
        }
    private:
        std::vector<std::unique_ptr<PatternMatchFragment>> fragments = {};
        std::size_t size = 0;
        std::size_t offset = 0;
        std::size_t index = 0;
    };

    class PatternMatchFilter final
    {
    public:
        PatternMatchFilter(const Module *module = nullptr, std::optional<std::string> const& section_name = {})
            : module(module), section_name(section_name) {}
        
        const Module *get_module() const
        {
            return module;
        }

        std::optional<std::string> const& get_section_name() const
        {
            return section_name;
        }
    private:
        const Module *module;
        std::optional<std::string> section_name;
    };

    class PatternMatchExpression final : Expression
    {
    public:
        PatternMatchExpression(std::vector<MaskedByte> const& needle, expression_value_t offset = 0, std::vector<PatternMatchFilter> const& filters = {})
            : filters(filters), needle(needle), offset(offset) {}
        virtual std::optional<expression_value_t> calculate(Symbol *symbol) const override
        {
            PatternMatchNeedle pattern_match_needle(needle);

            if (filters.size())
            {
                for (auto filter : filters)
                {
                    std::uint8_t *hModule = (std::uint8_t *)filter.get_module()->get_hModule();

                    if (!hModule)
                    {
                        continue;
                    }

                    IMAGE_DOS_HEADER* pDOSHeader = (IMAGE_DOS_HEADER*)hModule;
                    IMAGE_NT_HEADERS* pNTHeaders =(IMAGE_NT_HEADERS*)((BYTE*)pDOSHeader + pDOSHeader->e_lfanew);
                    IMAGE_SECTION_HEADER *pSectionHdr = (IMAGE_SECTION_HEADER *) (pNTHeaders + 1);
                    for ( int i = 0 ; i < pNTHeaders->FileHeader.NumberOfSections ; i++ )
                    {
                        char *name = (char*) pSectionHdr->Name;
                        if (!filter.get_section_name() || name == *filter.get_section_name())
                        {
                            void *begin = hModule + pSectionHdr->VirtualAddress;
                            void *end = hModule + pSectionHdr->VirtualAddress + pSectionHdr->Misc.VirtualSize;
                            while (begin < end)
                            {
                                void *result = pattern_match_needle.search(begin, end);
                                if (result != end && !pattern_match_needle.collision(result))
                                {
                                    return (expression_value_t)result + offset;
                                }

                                if (result == end)
                                {
                                    break;
                                }

                                begin = (char *)result + 1;
                            }

                            if (filter.get_section_name())
                                break;
                        }
                        pSectionHdr++;
                    }
                }
            } else {
                std::uint8_t *cur_base_address = nullptr;

                MEMORY_BASIC_INFORMATION mbi;

                while (VirtualQuery (cur_base_address, &mbi, sizeof (mbi)))
                {
                    if (mbi.Protect != 0 && (mbi.Protect & PAGE_GUARD) == 0 && (mbi.Protect & PAGE_NOACCESS) == 0)
                    {
                        void *begin = cur_base_address;
                        void *end = cur_base_address + mbi.RegionSize;
                        void *result = pattern_match_needle.search(begin, end);
                        while (begin < end)
                        {
                            void *result = pattern_match_needle.search(begin, end);
                            if (result != end && !pattern_match_needle.collision(result))
                            {
                                return (expression_value_t)result + offset;
                            }

                            if (result == end)
                            {
                                break;
                            }

                            begin = (char *)result + 1;
                        }
                    }

                    cur_base_address += mbi.RegionSize;
                }
            }

            return {};
        }

        virtual void dump(std::ostream &out) const override
        {
            if (filters.size())
            {
                out << "[";
                
                for (std::size_t i = 0; i < filters.size(); ++i)
                {
                    out << filters[i].get_module()->get_name();

                    if (filters[i].get_section_name())
                    {
                        out << "::\"" << *filters[i].get_section_name() << "\"";
                    }

                    if (i != filters.size() - 1)
                    {
                        out << ", ";
                    }
                }
                
                out << "]";
            }

            out << "{ ";

            std::ios_base::fmtflags f(out.flags());

            for (std::size_t i = 0; i < needle.size(); ++i)
            {
                if (i != 0 && offset == i)
                {
                    out << "&";
                }
                MaskedByte mb = needle[i];
                out << std::hex << std::setfill('0') << std::setw(2) << std::uppercase << (unsigned int)mb.value << " ";
            }

            out << ": ";

            for (MaskedByte mb : needle)
            {
                out << std::hex << std::setfill('0') << std::setw(2) << std::uppercase << (unsigned int)mb.mask << " ";
            }

            out.flags(f);

            out << "}";
        }

    private:
        std::vector<PatternMatchFilter> filters;
        std::vector<MaskedByte> needle;
        expression_value_t offset;
    };

#undef PROPAGATE_UNRESOLVED

    template<std::size_t S = 32, std::uint8_t C = 0xEF, bool D = true>
    class StackCheck {
    public:
        StackCheck();
        bool good() const;
        ~StackCheck();
    private:
        std::uint8_t buffer[S];
    };

    class Installable {
    public:
        virtual void install() = 0;
    };

    class Uninstallable {
    public:
        virtual void uninstall() = 0;
    };

    template<typename T>
    class Detour : public Installable, public Uninstallable {
    public:
        Detour(T& real, T wrap)
            : real(&real), wrap(wrap) {}
        virtual void install() override
        {
            DetourAttach(reinterpret_cast<PVOID*>(real), reinterpret_cast<PVOID>(wrap));
        }

        virtual void uninstall() override
        {
            DetourDetach(reinterpret_cast<PVOID*>(real), reinterpret_cast<PVOID>(wrap));
        }
    private:
        T *real = {};
        T wrap = {};
    };

    template<typename T>
    class Patch : public Installable, public Uninstallable
    {
    public:
        Patch(T *dst, T *src)
            : dst(dst), src(src) {}
        virtual void install() override
        {
            backup = *dst;
            *dst = *src;
        }

        virtual void uninstall() override
        {
            *dst = backup;
        }
    private:
        T *dst = {};
        T *src = {};
        T backup = {};
    };

    template<typename T, std::size_t N>
    class Patch<T[N]> : public Installable, public Uninstallable
    {
    public:
        Patch(T *dst, T *src)
            : dst(dst), src(src) {}
        virtual void install() override
        {
            for (std::size_t i = 0; i < N; ++i)
            {
                backup[i] = dst[i];
                dst[i] = src[i];
            }
        }

        virtual void uninstall() override
        {
            for (std::size_t i = 0; i < N; ++i)
            {
                dst[i] = backup[i];
            }
        }
    private:
        T *dst = {};
        T *src = {};
        T backup[N] = {};
    };

    class Action
    {
    public:
        virtual void act() = 0;
    };

    class ActionInstall : public Action
    {
    public:
        ActionInstall(Installable *installable)
            : installable(installable) {}
        virtual void act() override
        {
            installable->install();
        }
    private:
        Installable *installable = nullptr;
    };

    class ActionUninstall : public Action
    {
    public:
        ActionUninstall(Uninstallable *uninstallable)
            : uninstallable(uninstallable) {}
        virtual void act() override
        {
            uninstallable->uninstall();
        }
    private:
        Uninstallable *uninstallable = nullptr;
    };

    class Transaction
    {
    public:
        Transaction() {}

        void add(Action *action)
        {
            actions.push_back(action);
        }

        long commit()
        {
            DetourTransactionBegin();
            for (auto action : actions)
            {
                action->act();
            }
            return DetourTransactionCommit();
        }
    private:
        std::vector<Action*> actions;
    };

    // class Process {
    // public:
    //     Process(std::string_view path, std::vector<std::string_view> const& argv, std::vector<std::pair<std::string_view, std::string_view>> const& env);
    //     void push_back_dll(std::string_view path);
    //     void execute();
    //     int wait();
    // };
}

#include "sinker.tpp"

#endif // !SINKER_HPP
