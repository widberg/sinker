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
#include <fstream>
#include <iostream>
#include <filesystem>
#include <istream>

#include <sinker/sinker.hpp>
using namespace sinker;

// Bison generates weird switch statements
#ifdef _MSC_VER
#pragma warning( disable : 4065 )
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

struct PatternByteList : public std::vector<MaskedByte>
{
    std::optional<expression_value_t> offset;
};
}//%code requires

%code
{
namespace sinker { Parser::symbol_type yylex(LexerState *lexer_state); }
static sinker::location loc;

#define TOKEN(name) do { return sinker::Parser::make_##name(loc); } while(0)
#define TOKENV(name, ...) do { return sinker::Parser::make_##name(__VA_ARGS__, loc); } while(0)
#define VERIFY(cond, loc, msg) do { if (!(cond)) { sinker::Parser::error(loc, msg); YYERROR; } } while(0)
}//%code

%initial-action
{
lexer_state->first_loop = true;
lexer_state->in_pattern_match_expression = false;
}//%initial-action

%token END_OF_FILE 0

%token IDENTIFIER INTEGER STRING BOOL PATTERN_BYTE
%token MODULE "module"
%token VARIANT "variant"
%token SYMBOL "symbol"
%token ADDRESS "address"
%token SET "set"
%token TAG "tag"
%token POINTER_PATH "->"
%token SYMBOL_RESOLUTION "::"
%token BITWISE_SHIFT_LEFT "<<"
%token BITWISE_SHIFT_RIGHT ">>"
%token SHORT_CIRCUIT_AND "&&"
%token SHORT_CIRCUIT_OR "||"

%type<std::string> IDENTIFIER STRING string
%type<expression_value_t> INTEGER
%type<MaskedByte> PATTERN_BYTE
%type<std::shared_ptr<Expression>> expression
%type<bool> BOOL
%type<attribute_value_t> attribute_value
%type<PatternByteList> pattern_match_body pattern_byte_list
%type<identifier_set_t> identifier_set identifier_set_full
%type<std::vector<PatternMatchFilter>> pattern_match_filter pattern_match_filter_list
%type<PatternMatchFilter> pattern_match_filter_atom

%left SHORT_CIRCUIT_OR
%left SHORT_CIRCUIT_AND
%left '|'
%left '^'
%left '&'
%left BITWISE_SHIFT_LEFT BITWISE_SHIFT_RIGHT
%left '+' '-'
%left '*' '/' '%'
%right INDIRECTION '@' '?' '!' '~'
%left '[' '{' "->"

%start slist

%%

slist
    : slist stmt
    | %empty
    ;

expression
    : INTEGER                          { $$ = std::shared_ptr<Expression>((Expression*)new IntegerExpression($1));            }
    | '(' expression ')'               { $$ = std::shared_ptr<Expression>((Expression*)new UnaryOperatorExpression($2, UnaryOperator::PARENTHESES));        }

    | expression '+' expression        { $$ = std::shared_ptr<Expression>((Expression*)new BinaryOperatorExpression($1, $3, BinaryOperator::ADDITION)); }
    | expression '-' expression        { $$ = std::shared_ptr<Expression>((Expression*)new BinaryOperatorExpression($1, $3, BinaryOperator::SUBTRACTION)); }
    | expression '*' expression        { $$ = std::shared_ptr<Expression>((Expression*)new BinaryOperatorExpression($1, $3, BinaryOperator::MULTIPLICATION)); }
    | expression '/' expression        { $$ = std::shared_ptr<Expression>((Expression*)new BinaryOperatorExpression($1, $3, BinaryOperator::INTEGER_DIVISION)); }
    | expression '%' expression        { $$ = std::shared_ptr<Expression>((Expression*)new BinaryOperatorExpression($1, $3, BinaryOperator::MODULO)); }

    | expression '&' expression        { $$ = std::shared_ptr<Expression>((Expression*)new BinaryOperatorExpression($1, $3, BinaryOperator::BITWISE_AND)); }
    | expression '|' expression        { $$ = std::shared_ptr<Expression>((Expression*)new BinaryOperatorExpression($1, $3, BinaryOperator::BITWISE_OR)); }
    | expression '^' expression        { $$ = std::shared_ptr<Expression>((Expression*)new BinaryOperatorExpression($1, $3, BinaryOperator::BITWISE_XOR)); }
    | expression "<<" expression       { $$ = std::shared_ptr<Expression>((Expression*)new BinaryOperatorExpression($1, $3, BinaryOperator::BITWISE_SHIFT_LEFT)); }
    | expression ">>" expression       { $$ = std::shared_ptr<Expression>((Expression*)new BinaryOperatorExpression($1, $3, BinaryOperator::BITWISE_SHIFT_RIGHT)); }
    | expression SHORT_CIRCUIT_AND expression { $$ = std::shared_ptr<Expression>((Expression*)new BinaryOperatorExpression($1, $3, BinaryOperator::SHORT_CIRCUIT_AND)); }
    | expression SHORT_CIRCUIT_OR expression  { $$ = std::shared_ptr<Expression>((Expression*)new BinaryOperatorExpression($1, $3, BinaryOperator::SHORT_CIRCUIT_OR)); }

    | expression '~' expression        { $$ = std::shared_ptr<Expression>((Expression*)new UnaryOperatorExpression($1, UnaryOperator::BITWISE_NOT)); }

    | '*' expression %prec INDIRECTION { $$ = std::shared_ptr<Expression>((Expression*)new UnaryOperatorExpression($2, UnaryOperator::INDIRECTION));        }
    | '@' expression                   { $$ = std::shared_ptr<Expression>((Expression*)new UnaryOperatorExpression($2, UnaryOperator::RELOCATION));           }
    | expression '[' expression ']'    { $$ = std::shared_ptr<Expression>((Expression*)new BinaryOperatorExpression($1, $3, BinaryOperator::ARRAY_SUBSCRIPT)); }
    | expression "->" expression       { $$ = std::shared_ptr<Expression>((Expression*)new BinaryOperatorExpression($1, $3, BinaryOperator::POINTER_PATH));    }
    | '!' IDENTIFIER "::" IDENTIFIER
    {
        VERIFY(ctx->get_module($2), @2, "Module does not exist");
        $$ = std::shared_ptr<Expression>((Expression*)new GetProcAddressExpression(ctx->get_module($2), $4));
    }
    | IDENTIFIER
    {
        VERIFY(ctx->get_module($1), @1, "Module does not exist");
        $$ = std::shared_ptr<Expression>((Expression*)new ModuleExpression(ctx->get_module($1)));
    }
    | IDENTIFIER "::" IDENTIFIER
    {
        VERIFY(ctx->get_module($1), @1, "Module does not exist");
        VERIFY(ctx->get_module($1)->get_symbol($3), @3, "Symbol does not exist");
        $$ = std::shared_ptr<Expression>((Expression*)new SymbolExpression(ctx->get_module($1)->get_symbol($3)));
    }
    | pattern_match_filter '{' {lexer_state->in_pattern_match_expression = true;} pattern_match_body {lexer_state->in_pattern_match_expression = false;} '}'
    {
        $$ = std::shared_ptr<Expression>((Expression*)new PatternMatchExpression($4, $4.offset.value_or(0), $1));
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
        VERIFY(ctx->get_module($1), @1, "Module does not exist");
        $$ = PatternMatchFilter(ctx->get_module($1));
    }
    | IDENTIFIER "::" string
    {
        VERIFY(ctx->get_module($1), @1, "Module does not exist");
        $$ = PatternMatchFilter(ctx->get_module($1), $3);
    }
    ;

pattern_match_body
    : pattern_byte_list
    | pattern_byte_list ':' pattern_byte_list
    {
        VERIFY($1.size() == $3.size(), @3, "Mask size does not match needle size");
        VERIFY(!$3.offset, @3, "Mask cannot have an offset");
        $$ = $1;
        for (unsigned int i = 0; i < $1.size(); i++) {
            VERIFY($1[i].mask == 0xFF, @1, "If a mask is present, the needle must not contain wildcards");
            VERIFY($3[i].mask == 0xFF, @3, "Masks must not contain wildcards");
            $$[i].mask = $3[i].value;
        }
        $$.offset = $1.offset;
    }
    ;

pattern_byte_list
    : pattern_byte_list PATTERN_BYTE
    {
        $1.push_back($2);
        $$ = $1;
    }
    | pattern_byte_list '&'
    {
        VERIFY(!$1.offset, @2, "Offset cannot be set twice");
        $1.offset = $1.size();
        $$ = $1;
    }
    | pattern_byte_list STRING
    {
        for (char c : $2) {
            $1.push_back({ (std::uint8_t)c, 0xFF });
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
    | identifier_set ',' IDENTIFIER { $$.insert($3); }
    ;

identifier_set
    : identifier_set_full
    | '*' { $$ = identifier_set_t {}; }
    ;

stmt
    : "module" IDENTIFIER ',' string ';'
    {
        VERIFY(!ctx->get_module($2), @2, "Module exists");
        ctx->emplace_module($2, $4);
    }
    | "module" IDENTIFIER ';'
    {
        VERIFY(!ctx->get_module($2), @2, "Module exists");
        ctx->emplace_module($2, {});
    }
    | "variant" IDENTIFIER ',' IDENTIFIER ',' string ';'
    {
        VERIFY(ctx->get_module($2), @2, "Module does not exist");
        VERIFY(!ctx->get_module($2)->has_variant($4), @4, "Variant exists");
        ctx->get_module($2)->add_variant($4, $6);
    }
    | "symbol" IDENTIFIER "::" IDENTIFIER ',' string ';'
    {
        VERIFY(ctx->get_module($2), @2, "Module does not exist");
        VERIFY(!ctx->get_module($2)->get_symbol($4), @4, "Symbol exists");
        ctx->get_module($2)->emplace_symbol($4, $6);
    }
    | "address" IDENTIFIER "::" IDENTIFIER ',' '[' identifier_set ']' ',' expression ';'
    {
        VERIFY(ctx->get_module($2), @2, "Module does not exist");
        VERIFY(ctx->get_module($2)->get_symbol($4), @4, "Symbol does not exist");
        ctx->get_module($2)->get_symbol($4)->add_address($7, $10);
    }
    | "set" IDENTIFIER ',' IDENTIFIER ',' attribute_value ';'
    {
        VERIFY(ctx->get_module($2), @2, "Module does not exist");
        ctx->get_module($2)->set_attribute($4, $6);
    }
    | "set" IDENTIFIER "::" IDENTIFIER ',' IDENTIFIER ',' attribute_value ';'
    {
        VERIFY(ctx->get_module($2), @2, "Module does not exist");
        VERIFY(ctx->get_module($2)->get_symbol($4), @4, "Symbol does not exist");
        ctx->get_module($2)->get_symbol($4)->set_attribute($6, $8);
    }
    | "tag" IDENTIFIER ',' IDENTIFIER ';'
    {
        VERIFY(ctx->get_module($2), @2, "Module does not exist");
        ctx->get_module($2)->add_tag($4);
    }
    | "tag" IDENTIFIER "::" IDENTIFIER ',' IDENTIFIER ';'
    {
        VERIFY(ctx->get_module($2), @2, "Module does not exist");
        VERIFY(ctx->get_module($2)->get_symbol($4), @4, "Symbol does not exist");
        ctx->get_module($2)->get_symbol($4)->add_tag($6);
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
