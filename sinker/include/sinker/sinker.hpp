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
        bool interpret(const char *input, unsigned int size, Language language, std::string input_filename, bool debug = false);
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

    class ParenthesesExpression final : Expression
    {
    public:
        ParenthesesExpression(std::shared_ptr<Expression> expression)
            : expression(expression) {}
        virtual std::optional<expression_value_t> calculate(Symbol *symbol) const override
        {
            return expression->calculate(symbol);
        }
        virtual void dump(std::ostream &out) const override
        {
            out << "(";
            expression->dump(out);
            out << ")";
        }

    private:
        std::shared_ptr<Expression> expression;
    };

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

    class AdditionExpression final : Expression
    {
    public:
        AdditionExpression(std::shared_ptr<Expression> lhs, std::shared_ptr<Expression> rhs)
            : lhs(lhs), rhs(rhs) {}
        virtual std::optional<expression_value_t> calculate(Symbol *symbol) const override
        {
            auto lhs_result = lhs->calculate(symbol);
            auto rhs_result = rhs->calculate(symbol);
            PROPAGATE_UNRESOLVED(lhs_result);
            PROPAGATE_UNRESOLVED(rhs_result);
            return lhs_result.value() + rhs_result.value();
        }
        virtual void dump(std::ostream &out) const override
        {
            out << *lhs << " + " << *rhs;
        }

    private:
        std::shared_ptr<Expression> lhs;
        std::shared_ptr<Expression> rhs;
    };

    class SubtractionExpression final : Expression
    {
    public:
        SubtractionExpression(std::shared_ptr<Expression> lhs, std::shared_ptr<Expression> rhs)
            : lhs(lhs), rhs(rhs) {}
        virtual std::optional<expression_value_t> calculate(Symbol *symbol) const override
        {
            auto lhs_result = lhs->calculate(symbol);
            auto rhs_result = rhs->calculate(symbol);
            PROPAGATE_UNRESOLVED(lhs_result);
            PROPAGATE_UNRESOLVED(rhs_result);
            return lhs_result.value() - rhs_result.value();
        }
        virtual void dump(std::ostream &out) const override
        {
            out << *lhs << " - " << *rhs;
        }

    private:
        std::shared_ptr<Expression> lhs;
        std::shared_ptr<Expression> rhs;
    };

    class MultiplicationExpression final : Expression
    {
    public:
        MultiplicationExpression(std::shared_ptr<Expression> lhs, std::shared_ptr<Expression> rhs)
            : lhs(lhs), rhs(rhs) {}
        virtual std::optional<expression_value_t> calculate(Symbol *symbol) const override
        {
            auto lhs_result = lhs->calculate(symbol);
            auto rhs_result = rhs->calculate(symbol);
            PROPAGATE_UNRESOLVED(lhs_result);
            PROPAGATE_UNRESOLVED(rhs_result);
            return lhs_result.value() * rhs_result.value();
        }
        virtual void dump(std::ostream &out) const override
        {
            out << *lhs << " * " << *rhs;
        }

    private:
        std::shared_ptr<Expression> lhs;
        std::shared_ptr<Expression> rhs;
    };

    class IntegerDivisionExpression final : Expression
    {
    public:
        IntegerDivisionExpression(std::shared_ptr<Expression> lhs, std::shared_ptr<Expression> rhs)
            : lhs(lhs), rhs(rhs) {}
        virtual std::optional<expression_value_t> calculate(Symbol *symbol) const override
        {
            auto lhs_result = lhs->calculate(symbol);
            auto rhs_result = rhs->calculate(symbol);
            PROPAGATE_UNRESOLVED(lhs_result);
            PROPAGATE_UNRESOLVED(rhs_result);
            return lhs_result.value() / rhs_result.value();
        }
        virtual void dump(std::ostream &out) const override
        {
            out << *lhs << " / " << *rhs;
        }

    private:
        std::shared_ptr<Expression> lhs;
        std::shared_ptr<Expression> rhs;
    };

    class ModuloExpression final : Expression
    {
    public:
        ModuloExpression(std::shared_ptr<Expression> lhs, std::shared_ptr<Expression> rhs)
            : lhs(lhs), rhs(rhs) {}
        virtual std::optional<expression_value_t> calculate(Symbol *symbol) const override
        {
            auto lhs_result = lhs->calculate(symbol);
            auto rhs_result = rhs->calculate(symbol);
            PROPAGATE_UNRESOLVED(lhs_result);
            PROPAGATE_UNRESOLVED(rhs_result);
            return lhs_result.value() % rhs_result.value();
        }
        virtual void dump(std::ostream &out) const override
        {
            out << *lhs << " % " << *rhs;
        }

    private:
        std::shared_ptr<Expression> lhs;
        std::shared_ptr<Expression> rhs;
    };

    inline std::optional<expression_value_t> CheckedDereference(expression_value_t value)
    {
        __try {
            return (expression_value_t) *(void **)(value);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return {};
        }
    }

    class IndirectionExpression final : Expression
    {
    public:
        IndirectionExpression(std::shared_ptr<Expression> expression)
            : expression(expression) {}
        virtual std::optional<expression_value_t> calculate(Symbol *symbol) const override
        {
            auto expression_result = expression->calculate(symbol);
            PROPAGATE_UNRESOLVED(expression_result);
            return CheckedDereference(expression_result.value());
        }
        virtual void dump(std::ostream &out) const override
        {
            out << "*" << *expression;
        }

    private:
        std::shared_ptr<Expression> expression;
    };

    class RelocateExpression final : Expression
    {
    public:
        RelocateExpression(std::shared_ptr<Expression> expression)
            : expression(expression) {}
        virtual std::optional<expression_value_t> calculate(Symbol *symbol) const override
        {
            auto expression_result = expression->calculate(symbol);
            auto relocated_base_address_result = symbol->get_module()->get_relocated_base_address();
            auto preferred_base_address_result = symbol->get_module()->get_preferred_base_address();
            PROPAGATE_UNRESOLVED(expression_result);
            PROPAGATE_UNRESOLVED(relocated_base_address_result);
            PROPAGATE_UNRESOLVED(preferred_base_address_result);
            return expression_result.value() - preferred_base_address_result.value() + relocated_base_address_result.value();
        }
        virtual void dump(std::ostream &out) const override
        {
            out << "@" << *expression;
        }

    private:
        std::shared_ptr<Expression> expression;
    };

    class ArraySubscriptExpression final : Expression
    {
    public:
        ArraySubscriptExpression(std::shared_ptr<Expression> origin, std::shared_ptr<Expression> offset)
            : origin(origin), offset(offset) {}
        virtual std::optional<expression_value_t> calculate(Symbol *symbol) const override
        {
            auto origin_result = origin->calculate(symbol);
            auto offset_result = offset->calculate(symbol);
            PROPAGATE_UNRESOLVED(origin_result);
            PROPAGATE_UNRESOLVED(offset_result);
            return CheckedDereference(origin_result.value() + offset_result.value() * sizeof(void *));
        }
        virtual void dump(std::ostream &out) const override
        {
            out << *origin << "[" << *offset << "]";
        }

    private:
        std::shared_ptr<Expression> origin;
        std::shared_ptr<Expression> offset;
    };

    class PointerPathExpression final : Expression
    {
    public:
        PointerPathExpression(std::shared_ptr<Expression> lhs, std::shared_ptr<Expression> rhs)
            : lhs(lhs), rhs(rhs) {}
        virtual std::optional<expression_value_t> calculate(Symbol *symbol) const override
        {
            auto lhs_result = lhs->calculate(symbol);
            auto rhs_result = rhs->calculate(symbol);
            PROPAGATE_UNRESOLVED(lhs_result);
            PROPAGATE_UNRESOLVED(rhs_result);
            auto result = CheckedDereference(lhs_result.value());
            PROPAGATE_UNRESOLVED(result);
            return result.value() + rhs_result.value();
        }
        virtual void dump(std::ostream &out) const override
        {
            out << *lhs << "->" << *rhs;
        }

    private:
        std::shared_ptr<Expression> lhs;
        std::shared_ptr<Expression> rhs;
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
    private:
        std::size_t s;
    };

    class PatternMatchNeedle final
    {
    public:
        PatternMatchNeedle(std::vector<MaskedByte> const& needle) {
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

            // If the total size of the needle is larger than the search space, then we can't find a match
            if (total_size > (std::size_t)((char *)end - (char *)begin))
            {
                return end;
            }

            // Find the highest priority fragment with the largest size
            for (std::size_t i = 0; i < (std::size_t)PatternMatchType::COUNT; ++i)
            {
                if (sizes[i].size != 0)
                {
                    // Search for the fragment
                    auto& fragment = fragments[sizes[i].index];
                    void *result = fragment->search((char *)begin + sizes[i].offset, end);
                    if (result == end)
                    {
                        return end;
                    }

                    // Now check that the other fragments match
                    void *result_begin = (char *)result - sizes[i].offset;
                    void *result_offset = result_begin;
                    for (std::size_t j = 0; j < fragments.size(); ++j)
                    {
                        auto& fragment = fragments[j];
                        if (j != sizes[i].index)
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
            }

            return end;
        }
    private:
        std::vector<std::unique_ptr<PatternMatchFragment>> fragments = {};
    };

    class PatternMatchExpression final : Expression
    {
    public:
        PatternMatchExpression(std::vector<MaskedByte> const& needle, expression_value_t offset = 0)
            : needle(needle), offset(offset) {}
        virtual std::optional<expression_value_t> calculate(Symbol *symbol) const override
        {
            PatternMatchNeedle pattern_match_needle(needle);
            void *begin = nullptr;
            void *end = nullptr;
            void *result = pattern_match_needle.search(begin, end);
            if (result == end)
            {
                return {};
            }
            return (expression_value_t)result + offset;
        }

        virtual void dump(std::ostream &out) const override
        {
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
