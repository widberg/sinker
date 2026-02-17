%no-lines
%require "3.4.1"
%language "c++"

%skeleton "lalr1.cc"

%define api.token.constructor
%define api.value.type variant
%define api.location.file none
%define parse.assert true
%define parse.error verbose
%define parse.trace true
/* %define api.value.automove true */

%define api.namespace {sinker}
%define api.parser.class {Parser}

%parse-param {Context *ctx}
%param {LexerState *lexer_state}

%locations

%code requires
{
#include <cstdlib>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <filesystem>
#include <istream>
#include <string>
#include <sha256.hpp>

#include <sinker/sinker.hpp>
using namespace sinker;

// Bison generates warnings on MSVC
#ifdef _MSC_VER
#pragma warning( disable : 4065 )
#pragma warning( disable : 4244 )
#endif

struct LexerState
{
    bool first_loop = true;
    bool in_pattern_match_expression = false;
    const char *cur = nullptr;
    const char *mar = nullptr;
    const char *lim = nullptr;
    Language mode = Language::SINKER;
};

struct StringModifiers
{
    bool wide : 1;
    bool ascii : 1;
};

struct PatternByteList : public std::vector<MaskedByte>
{
    std::optional<expression_value_t> offset;
};
}//%code requires

%code
{
namespace sinker { Parser::symbol_type yylex(LexerState *lexer_state); }
static sinker::location loc;

template<typename... Args>
static std::string format_verify_message(char const *format, Args... args) {
    int needed = std::snprintf(nullptr, 0, format, args...);
    if (needed < 0) {
        return "Failed to format parser error message";
    }
    std::string message(static_cast<std::size_t>(needed), '\0');
    std::snprintf(message.data(), message.size() + 1, format, args...);
    return message;
}

static std::string describe_user_op_arity(UserOp const *user_op) {
    std::size_t min_arity = user_op->get_min_arity();
    if (std::optional<std::size_t> max_arity = user_op->get_max_arity()) {
        if (min_arity == max_arity.value()) {
            return format_verify_message("%zu", min_arity);
        }
        return format_verify_message("between %zu and %zu", min_arity,
                                     max_arity.value());
    }
    return format_verify_message("at least %zu", min_arity);
}

#define TOKEN(name) do { return sinker::Parser::make_##name(loc); } while(0)
#define TOKENV(name, ...) do { return sinker::Parser::make_##name(__VA_ARGS__, loc); } while(0)
#define VERIFY(cond, loc, ...) do { if (!(cond)) { sinker::Parser::error(loc, format_verify_message(__VA_ARGS__)); YYERROR; } } while(0)
}//%code

%initial-action
{
lexer_state->first_loop = true;
lexer_state->in_pattern_match_expression = false;
}//%initial-action

%token END_OF_FILE 0

%token IDENTIFIER INTEGER STRING BOOL PATTERN_BYTE TYPE
%token MODULE "module"
%token VARIANT "variant"
%token SYMBOL "symbol"
%token ADDRESS "address"
%token SET "set"
%token TAG "tag"
%token SIZEOF "sizeof"
%token POINTER_PATH "->"
%token SYMBOL_RESOLUTION "::"
%token BITWISE_SHIFT_LEFT "<<"
%token BITWISE_SHIFT_RIGHT ">>"
%token SHORT_CIRCUIT_AND "&&"
%token SHORT_CIRCUIT_OR "||"
%token WIDE "wide"
%token ASCII "ascii"

%type<std::string> IDENTIFIER STRING string
%type<expression_value_t> INTEGER
%type<MaskedByte> PATTERN_BYTE
%type<Type> TYPE type
%type<std::shared_ptr<Expression>> expression
%type<std::variant<sha256_digest_t, std::shared_ptr<Expression>>> variant_condition
%type<bool> BOOL
%type<attribute_value_t> attribute_value
%type<PatternByteList> pattern_match_body pattern_byte_list
%type<identifier_set_t> identifier_set identifier_set_full
%type<expression_list_t> expression_list
%type<std::vector<PatternMatchFilter>> pattern_match_filter pattern_match_filter_list
%type<PatternMatchFilter> pattern_match_filter_atom
%type<StringModifiers> string_modifiers

%left "||"
%left "&&"
%left '|'
%left '^'
%left '&'
%left "<<" ">>"
%left '+' '-'
%left '*' '/' '%'
%right INDIRECTION '@' '!' '~' "sizeof"
%left '[' '{' "->" USEROP_CALL

%start slist

%%

slist
    : slist stmt
    | slist ';'
    | %empty
    ;

type
    : TYPE
    | '(' TYPE ')' { $$ = $2; }
    ;

expression
    : INTEGER                          { $$ = std::shared_ptr<Expression>((Expression*)new IntegerExpression($1));            }
    | '(' expression ')'               { $$ = std::shared_ptr<Expression>((Expression*)new UnaryOperatorExpression($2, UnaryOperator::PARENTHESES, Type::None));        }

    | expression '+' expression        { $$ = std::shared_ptr<Expression>((Expression*)new BinaryOperatorExpression($1, $3, BinaryOperator::ADDITION, Type::None)); }
    | expression '-' expression        { $$ = std::shared_ptr<Expression>((Expression*)new BinaryOperatorExpression($1, $3, BinaryOperator::SUBTRACTION, Type::None)); }
    | expression '*' expression        { $$ = std::shared_ptr<Expression>((Expression*)new BinaryOperatorExpression($1, $3, BinaryOperator::MULTIPLICATION, Type::None)); }
    | expression '/' expression        { $$ = std::shared_ptr<Expression>((Expression*)new BinaryOperatorExpression($1, $3, BinaryOperator::INTEGER_DIVISION, Type::None)); }
    | expression '%' expression        { $$ = std::shared_ptr<Expression>((Expression*)new BinaryOperatorExpression($1, $3, BinaryOperator::MODULO, Type::None)); }

    | expression '&' expression        { $$ = std::shared_ptr<Expression>((Expression*)new BinaryOperatorExpression($1, $3, BinaryOperator::BITWISE_AND, Type::None)); }
    | expression '|' expression        { $$ = std::shared_ptr<Expression>((Expression*)new BinaryOperatorExpression($1, $3, BinaryOperator::BITWISE_OR, Type::None)); }
    | expression '^' expression        { $$ = std::shared_ptr<Expression>((Expression*)new BinaryOperatorExpression($1, $3, BinaryOperator::BITWISE_XOR, Type::None)); }
    | expression "<<" expression       { $$ = std::shared_ptr<Expression>((Expression*)new BinaryOperatorExpression($1, $3, BinaryOperator::BITWISE_SHIFT_LEFT, Type::None)); }
    | expression ">>" expression       { $$ = std::shared_ptr<Expression>((Expression*)new BinaryOperatorExpression($1, $3, BinaryOperator::BITWISE_SHIFT_RIGHT, Type::None)); }
    | expression "&&" expression { $$ = std::shared_ptr<Expression>((Expression*)new BinaryOperatorExpression($1, $3, BinaryOperator::SHORT_CIRCUIT_AND, Type::None)); }
    | expression "||" expression  { $$ = std::shared_ptr<Expression>((Expression*)new BinaryOperatorExpression($1, $3, BinaryOperator::SHORT_CIRCUIT_OR, Type::None)); }

    | expression '~' expression        { $$ = std::shared_ptr<Expression>((Expression*)new UnaryOperatorExpression($1, UnaryOperator::BITWISE_NOT, Type::None)); }

    | type '*' expression %prec INDIRECTION { $$ = std::shared_ptr<Expression>((Expression*)new UnaryOperatorExpression($3, UnaryOperator::INDIRECTION, $1));        }
    | '@' expression                   { $$ = std::shared_ptr<Expression>((Expression*)new UnaryOperatorExpression($2, UnaryOperator::RELOCATION, Type::None));           }
    | "sizeof" type                    { $$ = std::shared_ptr<Expression>((Expression*)new UnaryOperatorExpression(nullptr, UnaryOperator::SIZEOF, $2)); }
    | type expression '[' expression ']' { $$ = std::shared_ptr<Expression>((Expression*)new BinaryOperatorExpression($2, $4, BinaryOperator::ARRAY_SUBSCRIPT, $1)); }
    | expression "->" expression       { $$ = std::shared_ptr<Expression>((Expression*)new BinaryOperatorExpression($1, $3, BinaryOperator::POINTER_PATH, Type::None));    }
    | '!' IDENTIFIER "::" IDENTIFIER
    {
        Module *module = ctx->get_module($2);
        VERIFY(module, @2, "Module does not exist: %s", $2.c_str());
        $$ = std::shared_ptr<Expression>((Expression*)new GetProcAddressExpression(module, $4));
    }
    | IDENTIFIER
    {
        Module *module = ctx->get_module($1);
        VERIFY(module, @1, "Module does not exist: %s", $1.c_str());
        $$ = std::shared_ptr<Expression>((Expression*)new ModuleExpression(module));
    }
    | IDENTIFIER "::" IDENTIFIER
    {
        Module *module = ctx->get_module($1);
        VERIFY(module, @1, "Module does not exist: %s", $1.c_str());
        Symbol *symbol = module->get_symbol($3);
        VERIFY(symbol, @3, "Symbol does not exist: %s::%s", $1.c_str(), $3.c_str());
        $$ = std::shared_ptr<Expression>((Expression*)new SymbolExpression(symbol));
    }
    | pattern_match_filter '{' {lexer_state->in_pattern_match_expression = true;} pattern_match_body {lexer_state->in_pattern_match_expression = false;} '}'
    {
        $$ = std::shared_ptr<Expression>((Expression*)new PatternMatchExpression($4, $4.offset.value_or(0), $1));
    }
    | IDENTIFIER '(' expression_list ')' %prec USEROP_CALL
    {
        UserOp *user_op = ctx->get_user_op($1);
        VERIFY(user_op, @1, "UserOp does not exist: %s", $1.c_str());
        VERIFY(user_op->accepts_arity($3.size()), @3,
               "UserOp '%s' argument count mismatch: got %zu, expected %s",
               $1.c_str(), $3.size(),
               describe_user_op_arity(user_op).c_str());
        $$ = std::shared_ptr<Expression>((Expression*)new UserOpExpression(user_op, $3));
    }
    ;

pattern_match_filter
    : %empty { $$ = {}; }
    | '[' pattern_match_filter_list ']'
    {
        $$ = $2;
    }
    ;

pattern_match_filter_list
    : pattern_match_filter_atom
    {
        $$ = { $1 };
    }
    | pattern_match_filter_list ',' pattern_match_filter_atom
    {
        $$ = $1;
        $$.push_back($3);
    }
    ;

pattern_match_filter_atom
    : IDENTIFIER
    {
        Module *module = ctx->get_module($1);
        VERIFY(module, @1, "Module does not exist: %s", $1.c_str());
        $$ = PatternMatchFilter(module);
    }
    | IDENTIFIER "::" string
    {
        Module *module = ctx->get_module($1);
        VERIFY(module, @1, "Module does not exist: %s", $1.c_str());
        $$ = PatternMatchFilter(module, $3);
    }
    ;

pattern_match_body
    : pattern_byte_list
    | pattern_byte_list ':' pattern_byte_list
    {
        VERIFY($1.size() == $3.size(), @3,
               "Mask size does not match needle size: needle=%zu, mask=%zu",
               $1.size(), $3.size());
        VERIFY(!$3.offset, @3, "Mask cannot have an offset ('&' not allowed in mask)");
        $$ = $1;
        for (unsigned int i = 0; i < $1.size(); i++) {
            VERIFY($1[i].mask == 0xFF, @1,
                   "If a mask is present, the needle must not contain wildcards (index %u)",
                   i);
            VERIFY($3[i].mask == 0xFF, @3,
                   "Masks must not contain wildcards (index %u)",
                   i);
            $$[i].mask = $3[i].value;
        }
        $$.offset = $1.offset;
    }
    ;

string_modifiers
    : %empty { $$ = {}; }
    | string_modifiers "wide" { $$ = $1; $$.wide = true; }
    | string_modifiers "ascii" { $$ = $1; $$.ascii = true; }
    ;

pattern_byte_list
    : pattern_byte_list PATTERN_BYTE
    {
        $1.push_back($2);
        $$ = $1;
    }
    | pattern_byte_list '&'
    {
        VERIFY(!$1.offset, @2, "Offset cannot be set twice in a pattern");
        $1.offset = $1.size();
        $$ = $1;
    }
    | pattern_byte_list STRING string_modifiers
    {
        VERIFY(($3.ascii == false && $3.wide == false) || ($3.ascii != $3.wide), @3,
               "String cannot be both wide and ascii");
        for (char c : $2) {
            if (!$3.wide) {
                $1.push_back({ (std::uint8_t)c, 0xFF });
            } else {
                $1.push_back({ (std::uint8_t)c, 0xFF });
                $1.push_back({ 0, 0xFF });
            }
        }
        $$ = $1;
    }
    | %empty { $$ = PatternByteList(); }
    ;

string
    : STRING        { $$ = $1; }
    | string STRING { $$ = $1 + $2; }
    ;

attribute_value
    : INTEGER { $$ = attribute_value_t {$1}; }
    | string  { $$ = attribute_value_t {$1}; }
    | BOOL    { $$ = attribute_value_t {$1}; }
    ;

identifier_set_full
    : IDENTIFIER                    { $$ = identifier_set_t {$1}; }
    | identifier_set ',' IDENTIFIER { $$ = $1; $$.insert($3); }
    ;

identifier_set
    : identifier_set_full
    | '*' { $$ = identifier_set_t {}; }
    ;

variant_condition
    : string
    {
        sha256_digest_t hash;
        VERIFY(string_to_hash($1.c_str(), hash), @1, "Invalid SHA256 hash: %s", $1.c_str());
        $$ = hash;
    }
    | expression { $$ = $1; }
    ;

expression_list
    : %empty                         { $$ = expression_list_t {}; }
    | expression                     { $$ = expression_list_t {$1}; }
    | expression_list ',' expression { $$ = $1; $$.push_back($3); }
    ;

stmt
    : "module" IDENTIFIER ',' string
    {
        VERIFY(ctx->emplace_module($2, $4), @2, "Module already exists: %s", $2.c_str());
    }
    | "module" IDENTIFIER
    {
        VERIFY(ctx->emplace_module($2, {}), @2, "Module already exists: %s", $2.c_str());
    }
    | "variant" IDENTIFIER ',' IDENTIFIER ',' variant_condition
    {
        Module *module = ctx->get_module($2);
        VERIFY(module, @2, "Module does not exist: %s", $2.c_str());
        VERIFY(!module->has_variant($4), @4,
               "Variant already exists: %s::%s", $2.c_str(), $4.c_str());
        module->add_variant($4, $6);
    }
    | "symbol" IDENTIFIER "::" IDENTIFIER ',' string
    {
        Module *module = ctx->get_module($2);
        VERIFY(module, @2, "Module does not exist: %s", $2.c_str());
        VERIFY(module->emplace_symbol($4, $6), @4,
               "Symbol already exists: %s::%s", $2.c_str(), $4.c_str());
    }
    | "address" IDENTIFIER "::" IDENTIFIER ',' '[' identifier_set ']' ',' expression
    {
        Module *module = ctx->get_module($2);
        VERIFY(module, @2, "Module does not exist: %s", $2.c_str());
        Symbol *symbol = module->get_symbol($4);
        VERIFY(symbol, @4, "Symbol does not exist: %s::%s", $2.c_str(), $4.c_str());
        symbol->add_address($7, $10);
    }
    | "set" IDENTIFIER ',' IDENTIFIER ',' attribute_value
    {
        Module *module = ctx->get_module($2);
        VERIFY(module, @2, "Module does not exist: %s", $2.c_str());
        module->set_attribute($4, $6);
    }
    | "set" IDENTIFIER "::" IDENTIFIER ',' IDENTIFIER ',' attribute_value
    {
        Module *module = ctx->get_module($2);
        VERIFY(module, @2, "Module does not exist: %s", $2.c_str());
        Symbol *symbol = module->get_symbol($4);
        VERIFY(symbol, @4, "Symbol does not exist: %s::%s", $2.c_str(), $4.c_str());
        symbol->set_attribute($6, $8);
    }
    | "tag" IDENTIFIER ',' IDENTIFIER
    {
        Module *module = ctx->get_module($2);
        VERIFY(module, @2, "Module does not exist: %s", $2.c_str());
        module->add_tag($4);
    }
    | "tag" IDENTIFIER "::" IDENTIFIER ',' IDENTIFIER
    {
        Module *module = ctx->get_module($2);
        VERIFY(module, @2, "Module does not exist: %s", $2.c_str());
        Symbol *symbol = module->get_symbol($4);
        VERIFY(symbol, @4, "Symbol does not exist: %s::%s", $2.c_str(), $4.c_str());
        symbol->add_tag($6);
    }
    ;

%%

void sinker::Parser::error(const location_type& l, const std::string& message)
{
    std::cerr << l.begin.filename->c_str() << ':' << l.begin.line << ':' << l.begin.column << '-' <<
                l.end.column << ": " << message << '\n';
}

sinker::Parser::symbol_type parse_integer(const std::string& str, int base)
{
    char *p;
    unsigned long long n = strtoull(str.c_str(), &p, base);
    if (*p != 0) TOKEN(YYerror);
    TOKENV(INTEGER, n);
}

sinker::Parser::symbol_type sinker::yylex(LexerState *lexer_state)
{
    if (lexer_state->first_loop && lexer_state->mode == Language::SOURCE_CODE) { lexer_state->first_loop = false; goto source; }
    const char *s, *e;
    /*!stags:re2c format = 'const char *@@;\n'; */
    for (;;)
    {
        %{
        // Configuration
        re2c:yyfill:enable  = 0;
        re2c:api:style = free-form;
        re2c:define:YYCTYPE = char;
        re2c:define:YYCURSOR = lexer_state->cur;
        re2c:define:YYMARKER = lexer_state->mar;
        re2c:define:YYLIMIT = lexer_state->lim;
        re2c:eof = 0;
        re2c:tags = 1;
        %}
    sinker:
        if (lexer_state->in_pattern_match_expression) goto pattern_match;
        %{
        // Keywords
        'module'       { TOKEN(MODULE); }
        'set'          { TOKEN(SET); }
        'variant'      { TOKEN(VARIANT); }
        'symbol'       { TOKEN(SYMBOL); }
        'address'      { TOKEN(ADDRESS); }
        'tag'          { TOKEN(TAG); }

        'true'         { TOKENV(BOOL, true); }
        'false'        { TOKENV(BOOL, false); }

        '->'           { TOKEN(POINTER_PATH); }
        '::'           { TOKEN(SYMBOL_RESOLUTION); }
        '<<'           { TOKEN(BITWISE_SHIFT_LEFT); }
        '>>'           { TOKEN(BITWISE_SHIFT_RIGHT); }
        '&&'           { TOKEN(SHORT_CIRCUIT_AND); }
        '||'           { TOKEN(SHORT_CIRCUIT_OR); }

        // Type
        'u8'  { TOKENV(TYPE, Type::U8); }
        'u16' { TOKENV(TYPE, Type::U16); }
        'u32' { TOKENV(TYPE, Type::U32); }
        'u64' { TOKENV(TYPE, Type::U64); }
        'i8'  { TOKENV(TYPE, Type::I8); }
        'i16' { TOKENV(TYPE, Type::I16); }
        'i32' { TOKENV(TYPE, Type::I32); }
        'i64' { TOKENV(TYPE, Type::I64); }
        'ptr' { TOKENV(TYPE, Type::PTR); }

        'sizeof' { TOKEN(SIZEOF); }

        // Identifier
        @s [a-zA-Z_][a-zA-Z_0-9]* @e { TOKENV(IDENTIFIER, std::string(s, e - s)); }

        // String
        // \x22 == '\"' I couldn't figure out how to use double quotes without someone complaining
        [\x22] @s [^\x22]* @e [\x22] { TOKENV(STRING, std::string(s, e - s)); }

        // Literal
        '0b' @s [0-1]+ @e       { return parse_integer(std::string(s, e - s).c_str(), 2); }
        '0x' @s [0-9a-fA-F]+ @e { return parse_integer(std::string(s, e - s).c_str(), 16); }
        '0' @s [0-9a-fA-F]+ @e { return parse_integer(std::string(s, e - s).c_str(), 8); }
        @s [0-9]+ @e            { return parse_integer(std::string(s, e - s).c_str(), 10); }

        // Whitespace
        $              { TOKEN(END_OF_FILE); }
        "\r\n"|[\r\n]  { loc.lines(); loc.step(); if (lexer_state->mode == Language::SOURCE_CODE) goto source; continue; }
        [ \t\v\b\f]    { loc.columns(); continue; }

        // Comment
        "//"[^\r\n]*   { continue; }

        *              { return sinker::Parser::symbol_type (lexer_state->cur[-1], loc); }
        %}
    pattern_match:
        %{
        'wide' { TOKEN(WIDE); }
        'ascii' { TOKEN(ASCII); }

        '??' { TOKENV(PATTERN_BYTE, { 0, 0x00 }); }
        @s [0-9a-fA-F][0-9a-fA-F] @e {
            char *p;
            unsigned long long n = strtoull(std::string(s, e - s).c_str(), &p, 16);
            if (*p != 0) TOKEN(YYerror);
            TOKENV(PATTERN_BYTE, { (std::uint8_t)n, 0xFF });
        }
        @s [0-9a-fA-F] @e '?' {
            char *p;
            unsigned long long n = strtoull(std::string(s, e - s).c_str(), &p, 16) << 4;
            if (*p != 0) TOKEN(YYerror);
            TOKENV(PATTERN_BYTE, { (std::uint8_t)n, 0xF0 });
        }
        '?' @s [0-9a-fA-F] @e {
            char *p;
            unsigned long long n = strtoull(std::string(s, e - s).c_str(), &p, 16);
            if (*p != 0) TOKEN(YYerror);
            TOKENV(PATTERN_BYTE, { (std::uint8_t)n, 0x0F });
        }

        // String
        // \x22 == '\"' I couldn't figure out how to use double quotes without someone complaining
        [\x22] @s [^\x22]* @e [\x22] { TOKENV(STRING, std::string(s, e - s)); }

        // Whitespace
        $              { TOKEN(END_OF_FILE); }
        "\r\n"|[\r\n]  { loc.lines(); loc.step(); if (lexer_state->mode == Language::SOURCE_CODE) goto source; continue; }
        [ \t\v\b\f]    { loc.columns(); continue; }

        // Comment
        "//"[^\r\n]*   { continue; }

        *              { return sinker::Parser::symbol_type (lexer_state->cur[-1], loc); }
        %}
    source:
        %{
        $                                  { TOKEN(END_OF_FILE); }
        [ \t\v\b\f]* "//" [ \t\v\b\f]* "$" { goto sinker; }
        *                                  { loc.columns(); goto source_internal; }
        %}
    source_internal:
        %{
        $             { TOKEN(END_OF_FILE); }
        "\r\n"|[\r\n] { loc.lines(); loc.step(); goto source; }
        [ \t\v\b\f]   { loc.columns(); goto source_internal; }
        *             { loc.columns(); goto source_internal; }
        %}
    }
}

bool Context::interpret(const char *input, std::size_t size, Language language, std::string input_filename, bool debug) {
        sinker::location::filename_type filename(input_filename);

        loc = sinker::location(&filename);

        LexerState lexer_state;
        lexer_state.cur = input;
        lexer_state.mar = input;
        lexer_state.lim = input + size;
        lexer_state.mode = language;
        sinker::Parser parser(this, &lexer_state);
        if (debug) {
            parser.set_debug_level(1);
        }
        return !parser.parse();
}

bool Context::interpret(std::istream& input_stream, Language language, std::string input_filename, bool debug) {
        input_stream.seekg(0, std::ios::end);
        std::streamsize size = input_stream.tellg();
        input_stream.seekg(0, std::ios::beg);

        std::vector<char> buffer((unsigned int)size);
        if (!input_stream.read(buffer.data(), size)) return false;
        buffer.push_back('\0');

        return interpret(buffer.data(), (std::size_t)size, language, input_filename, debug);
}

bool Context::interpret(const std::string& input, Language language, std::string input_filename, bool debug) {
        return interpret(input.c_str(), input.length(), language, input_filename, debug);
}
