#include <stddef.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <stdexcept>

enum colour {
	DARKBLUE = 1,
	DARKGREEN,
	DARKTEAL,
	DARKRED,
	DARKPINK,
	DARKYELLOW,
	GRAY,
	DARKGRAY,
	BLUE,
	GREEN,
	TEAL,
	RED,
	PINK,
	YELLOW,
	WHITE
};

#if defined(WIN32)
#include <Windows.h>
struct setcolour
{
	colour _c;
	HANDLE _console_handle;


	setcolour(colour c, HANDLE console_handle)
		: _c(c), _console_handle(0)
	{
		_console_handle = console_handle;
	}

	explicit setcolour(colour c)
		: _c(c), _console_handle(GetStdHandle(STD_OUTPUT_HANDLE))
	{

	}
	
};

std::basic_ostream <char>& operator << (std::basic_ostream<char> &s, const setcolour &ref)
{
	SetConsoleTextAttribute(ref._console_handle, ref._c);
	return s;
}

#else
#include <stdio.h>

#define CC_CONSOLE_COLOR_DEFAULT "\033[0m"
#define CC_FORECOLOR(C) "\033[" #C "m"
#define CC_BACKCOLOR(C) "\033[" #C "m"
#define CC_ATTR(A) "\033[" #A "m"

namespace zkr
{
	class cc
	{
	public:

		class fore
		{
		public:
			static const char *black;
			static const char *blue;
			static const char *red;
			static const char *magenta;
			static const char *green;
			static const char *cyan;
			static const char *yellow;
			static const char *white;
			static const char *console;

			static const char *lightblack;
			static const char *lightblue;
			static const char *lightred;
			static const char *lightmagenta;
			static const char *lightgreen;
			static const char *lightcyan;
			static const char *lightyellow;
			static const char *lightwhite;
		};

		class back
		{
		public:
			static const char *black;
			static const char *blue;
			static const char *red;
			static const char *magenta;
			static const char *green;
			static const char *cyan;
			static const char *yellow;
			static const char *white;
			static const char *console;

			static const char *lightblack;
			static const char *lightblue;
			static const char *lightred;
			static const char *lightmagenta;
			static const char *lightgreen;
			static const char *lightcyan;
			static const char *lightyellow;
			static const char *lightwhite;
		};

		static char *color(int attr, int fg, int bg);
		static const char *console;
		static const char *underline;
		static const char *bold;
	};
}
namespace zkr
{
	enum Color
	{
		Black,
		Red,
		Green,
		Yellow,
		Blue,
		Magenta,
		Cyan,
		White,
		Default = 9
	};

	enum Attributes
	{
		Reset,
		Bright,
		Dim,
		Underline,
		Blink,
		Reverse,
		Hidden
	};

	char *cc::color(int attr, int fg, int bg)
	{
		static char command[13];

		/* Command is the control command to the terminal */
		sprintf(command, "%c[%d;%d;%dm", 0x1B, attr, fg + 30, bg + 40);
		return command;
	}


	const char *cc::console = CC_CONSOLE_COLOR_DEFAULT;
	const char *cc::underline = CC_ATTR(4);
	const char *cc::bold = CC_ATTR(1);

	const char *cc::fore::black = CC_FORECOLOR(30);
	const char *cc::fore::blue = CC_FORECOLOR(34);
	const char *cc::fore::red = CC_FORECOLOR(31);
	const char *cc::fore::magenta = CC_FORECOLOR(35);
	const char *cc::fore::green = CC_FORECOLOR(92);
	const char *cc::fore::cyan = CC_FORECOLOR(36);
	const char *cc::fore::yellow = CC_FORECOLOR(33);
	const char *cc::fore::white = CC_FORECOLOR(37);
	const char *cc::fore::console = CC_FORECOLOR(39);

	const char *cc::fore::lightblack = CC_FORECOLOR(90);
	const char *cc::fore::lightblue = CC_FORECOLOR(94);
	const char *cc::fore::lightred = CC_FORECOLOR(91);
	const char *cc::fore::lightmagenta = CC_FORECOLOR(95);
	const char *cc::fore::lightgreen = CC_FORECOLOR(92);
	const char *cc::fore::lightcyan = CC_FORECOLOR(96);
	const char *cc::fore::lightyellow = CC_FORECOLOR(93);
	const char *cc::fore::lightwhite = CC_FORECOLOR(97);

	const char *cc::back::black = CC_BACKCOLOR(40);
	const char *cc::back::blue = CC_BACKCOLOR(44);
	const char *cc::back::red = CC_BACKCOLOR(41);
	const char *cc::back::magenta = CC_BACKCOLOR(45);
	const char *cc::back::green = CC_BACKCOLOR(42);
	const char *cc::back::cyan = CC_BACKCOLOR(46);
	const char *cc::back::yellow = CC_BACKCOLOR(43);
	const char *cc::back::white = CC_BACKCOLOR(47);
	const char *cc::back::console = CC_BACKCOLOR(49);

	const char *cc::back::lightblack = CC_BACKCOLOR(100);
	const char *cc::back::lightblue = CC_BACKCOLOR(104);
	const char *cc::back::lightred = CC_BACKCOLOR(101);
	const char *cc::back::lightmagenta = CC_BACKCOLOR(105);
	const char *cc::back::lightgreen = CC_BACKCOLOR(102);
	const char *cc::back::lightcyan = CC_BACKCOLOR(106);
	const char *cc::back::lightyellow = CC_BACKCOLOR(103);
	const char *cc::back::lightwhite = CC_BACKCOLOR(107);
}

struct setcolour
{
	const char* _code;
	explicit setcolour(colour c)
		: _code (" ")
	{
		switch (c)
		{
		case DARKBLUE:
			_code = zkr::cc::fore::blue;
			break;
		case DARKGREEN:
			_code = zkr::cc::fore::green;
			break;
		case DARKTEAL:
			_code = zkr::cc::fore::cyan;
			break;
		case DARKRED:
			_code = zkr::cc::fore::red;
			break;
		case DARKPINK:
			_code = zkr::cc::fore::magenta;
			break;
		case DARKYELLOW:
			_code = zkr::cc::fore::yellow;
			break;
		case GRAY:
			_code = zkr::cc::fore::lightwhite;
			break;
		case DARKGRAY:
			_code = zkr::cc::fore::white;
			break;
		case BLUE:
			_code = zkr::cc::fore::lightblue;
			break;
		case GREEN:
			_code = zkr::cc::fore::lightgreen;
			break;
		case TEAL:
			_code = zkr::cc::fore::lightcyan;
			break;
		case RED:
			_code = zkr::cc::fore::lightred;
			break;
		case PINK:
			_code = zkr::cc::fore::lightmagenta;
			break;
		case YELLOW:
			_code = zkr::cc::fore::lightyellow;
			break;
		case WHITE:
			_code = zkr::cc::fore::lightwhite;
			break;
		}
	}
};

static std::basic_ostream <char>& operator << (std::basic_ostream<char> &s, const setcolour &ref)
{
	s << ref._code;
	return s;
}


#endif

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-variable-declarations"
#endif

#include "explode/io.hh"
#include "explode/exe_file.hh"
#include "explode/unpklite.hh"
#include "explode/unlzexe.hh"
#include "explode/knowledge_dynamics.hh"

#include "unittest/md5.h"

#include "unittest/pklite_112.cc"  
#include "unittest/pklite_120.cc"  
#include "unittest/pklite_201.cc"    
#include "unittest/pklite_E_115.cc"
#include "unittest/pklite_100.cc"  
#include "unittest/pklite_115.cc"  
#include "unittest/pklite_150.cc"  
#include "unittest/pklite_E_112.cc"  
#include "unittest/pklite_E_120.cc"

#include "unittest/z90.cc"
#include "unittest/z91.cc"
#include "unittest/z91e.cc"

#include "unittest/dot.cc"
#include "unittest/lex.cc"
#include "unittest/tntega.cc"

#if defined(__clang__)
#pragma clang diagnostic pop
#endif

static int total_tests = 0;
static int failed_tests = 0;

static const char* digest_pklite_112   = "e1f98f301ef8bb8710ae14469bcb2cd0";
static const char* digest_pklite_115   = "13482d37794b1106a85712b5e7a1227a";
static const char* digest_pklite_120   = "e1f98f301ef8bb8710ae14469bcb2cd0";
static const char* digest_pklite_150   = "36ce063f2a979acc3ba887f4f3b9f735";
static const char* digest_pklite_201   = "e6cf27d7818c320ce64bcb4caba7f5a4";
static const char* digest_pklite_E_112 = "8a4b841106bae1f32c7ca45e9d41c016";
static const char* digest_pklite_E_115 = "56dccb4b55bdd7c57f09dbb584050a51";
static const char* digest_pklite_E_120 = "8a4b841106bae1f32c7ca45e9d41c016";

static const char* digest_lzexe_91   = "f38e4c688fcd8f3d4f102dc5e2b8bb0f"; 
static const char* digest_lzexe_91_E = "f38e4c688fcd8f3d4f102dc5e2b8bb0f";
static const char* digest_lzexe_90   = "620d7dce66a13ec7be84b9f390078aa6";


static const char* digest_knowledge_dynamics_LEX = "03703e056977944b007eb2ecccf3f1c4";
static const char* digest_knowledge_dynamics_DOT = "3b1429a7224c868b4725228b1a4ffb66";
static const char* digest_knowledge_dynamics_TNT = "d813b5ac3095c24c3eba559bac22a32d";

typedef unsigned char md5_digest[MD5_DIGEST_LENGTH];

template <class DECODER>
struct tester;

template <>
struct tester < explode::unpklite >
{
	static void test(explode::input_exe_file& iexe)
	{
		if (!explode::unpklite::accept (iexe))
		{
			throw std::runtime_error("not a PKLITE");
		}
	}
};

template <>
struct tester < explode::unlzexe >
{
	static void test(explode::input_exe_file& iexe)
	{
		if (!explode::unlzexe::accept (iexe))
		{
			throw std::runtime_error("not a LZEXE");
		}
	}
};

template <>
struct tester < explode::knowledge_dynamics >
{
	static void test(explode::input_exe_file& iexe)
	{
		if (!explode::knowledge_dynamics::accept(iexe))
		{
			throw std::runtime_error("not a Knowledge Dynaimcs");
		}
	}
};


template <typename DECODER>
static void eval_digest(const unsigned char* data, std::size_t length, md5_digest& digest, std::vector<char>& out_buff)
{
	explode::inmem_input input(data, length);
	explode::input_exe_file iexe(input);

	tester <DECODER>::test(iexe);

	DECODER decoder(iexe);
	explode::full_exe_file fo(decoder.decomp_size());
	decoder.unpack(fo);
	
	explode::inmem_output out(out_buff);
	fo.write(out);


	MD5_CTX c;
	MD5_Init(&c);
	MD5_Update(&c, &out_buff[0], static_cast <unsigned long> (out_buff.size ()));
	MD5_Final(digest, &c);
}
template <typename DECODER>
static void do_test(const char* test_name, const unsigned char* data, std::size_t length, const char* expected)
{
	md5_digest dgst = {0};
	bool ok = true;
	try
	{
		std::vector <char> out_buff;
		eval_digest <DECODER>(data, length, dgst, out_buff);

		for (int n = 0; n < MD5_DIGEST_LENGTH; n++)
		{
			std::string h(expected + 2 * n, expected + 2 * (n + 1));
			std::istringstream is(h);
			int x;
			is >> std::hex >> x;
			if (x != dgst[n])
			{
				ok = false;
				break;



			}
		}
	}
	
	catch (...)
	{
		ok = false;
	}
	total_tests++;
	const char* s_ok = "PASSED";
	colour col = GREEN;
	if (!ok)
	{
		failed_tests++;
		s_ok = "FAILED";
		col = RED;
	}
	std::cout << setcolour(GRAY) << "TEST #" << std::dec << total_tests << ": " << test_name << " "
		<< setcolour(col) << s_ok << setcolour(GRAY) << std::endl;
	if (!ok)
	{
		std::cout << "E " << expected << std::endl;

		std::cout << "A ";
		for (int n = 0; n < MD5_DIGEST_LENGTH; n++)
		{
			std::cout << std::setw(2) << std::setfill('0') << std::hex
				  << (static_cast <int> (dgst[n]) & 0xFF);
		}
		std::cout << std::endl;
	}
}

#define CONCATENATE_DIRECT(s1,s2) s1##s2
#define CONCATENATE(s1,s2) CONCATENATE_DIRECT(s1,s2)

#define STRINGIZE_HELPER(exp) #exp
#define STRINGIZE(exp) STRINGIZE_HELPER(exp)

#define PKLITE_TEST(NAME) do_test <explode::unpklite>("PKLITE-" STRINGIZE(NAME), CONCATENATE (data::pklite_, NAME), CONCATENATE(CONCATENATE (data::pklite_, NAME), _len), CONCATENATE(digest_, CONCATENATE (pklite_, NAME)))
#define LZEXE_TEST(NAME) do_test <explode::unlzexe>("LZEXE-" STRINGIZE(NAME), CONCATENATE (data::z, NAME), CONCATENATE(CONCATENATE (data::z, NAME), _len), CONCATENATE(digest_, CONCATENATE (lzexe_, NAME)))
#define KD_TEST(NAME) do_test <explode::knowledge_dynamics>("KD-" STRINGIZE(NAME), CONCATENATE (data::knowledge_dynamics_, NAME), CONCATENATE(CONCATENATE (data::knowledge_dynamics_, NAME), _len), CONCATENATE(digest_, CONCATENATE (knowledge_dynamics_, NAME)))
int main(int argc, char* argv[])
{

	PKLITE_TEST(112);
	PKLITE_TEST(E_112);

	PKLITE_TEST(115);
	PKLITE_TEST(E_115);

	PKLITE_TEST(150);
	PKLITE_TEST(201);

	LZEXE_TEST(90);
	LZEXE_TEST(91);
	LZEXE_TEST(91_E);

	KD_TEST(DOT);
	KD_TEST(TNT);
	KD_TEST(LEX);

	const colour col = (failed_tests == 0) ? GREEN : RED;
	
	std::cout << "Total Tests: " << setcolour(YELLOW) << total_tests << setcolour(GRAY)
		<< " Failed tests: " << setcolour(col) << failed_tests << setcolour(GRAY) << std::endl;

	return failed_tests;
}
