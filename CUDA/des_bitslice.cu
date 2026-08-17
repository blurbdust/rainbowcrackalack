/* des_bitslice.cl -- bitsliced DES for Net-NTLMv1 chain generation.
 *
 * 32 chains per work item: each 32-bit word holds one bit position across 32
 * independent chains.  A scalar DES pays ~2100 instructions per chain step just
 * building the key schedule with DES_PC2, plus 128 S-box loads.  Bitsliced, the
 * key schedule is free -- it is only which bsKey[] index gets XORed -- and there
 * is no memory traffic at all.
 *
 * Rainbow chains normally defeat bitslicing because the reduction has to be
 * done per chain, forcing a transpose in and out of bitslice form every step.
 * This configuration escapes that entirely:
 *   - index -> plaintext for the byte charset is a pure bit relabelling (free);
 *   - the plaintext IS the 56-bit DES key (free);
 *   - the 2^56 keyspace mask is free (just ignore the high words);
 *   - the only real work is adding a per-step constant, a bitsliced ripple-carry
 *     adder at ~2 gates per bit.
 * So there are ZERO transposes per step -- only one per chain, at the end.
 *
 * S-boxes are Roman Rusakov's gate-optimal expressions via Openwall's John the
 * Ripper; the surrounding bitslice DES is Daniel Thornburgh's, both carried over
 * from the des-cbc-crc cracker.
 */
#ifndef _DES_BITSLICE_CU
#define _DES_BITSLICE_CU

/* NVRTC compiles these standalone and does not define the OpenCL spelling of uint. */
#ifndef __CUDA_UINT_DEFINED
#define __CUDA_UINT_DEFINED
typedef unsigned int uint;
#endif

/*
 * Bitslice DES S-boxes for x86 with MMX/SSE2/AVX and for typical RISC
 * architectures.  These use AND, OR, XOR, NOT, and AND-NOT gates.
 *
 * Gate counts: 49 44 46 33 48 46 46 41
 * Average: 44.125
 *
 * Several same-gate-count expressions for each S-box are included (for use on
 * different CPUs/GPUs).
 *
 * These Boolean expressions corresponding to DES S-boxes have been generated
 * by Roman Rusakov <roman_rus at openwall.com> for use in Openwall's
 * John the Ripper password cracker: http://www.openwall.com/john/
 * Being mathematical formulas, they are not copyrighted and are free for reuse
 * by anyone.
 *
 * This file (a specific representation of the S-box expressions, surrounding
 * logic) is Copyright (c) 2011 by Solar Designer <solar at openwall.com>.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.  (This is a heavily cut-down "BSD license".)
 *
 * The effort has been sponsored by Rapid7: http://www.rapid7.com
 */

/* s1-00484, 49 gates, 17 regs, 11 andn, 4/9/39/79/120 stalls, 74 biop */
/* Currently used for MMX/SSE2 and x86-64 SSE2 */
__device__ inline void s1(uint a1, uint a2, uint a3, uint a4, uint a5, uint a6,
        uint *out1, uint *out2, uint *out3, uint *out4)
{
    uint x55005500, x5A0F5A0F, x3333FFFF, x66666666, x22226666, x2D2D6969,
        x25202160;
    uint x00FFFF00, x33CCCC33, x4803120C, x2222FFFF, x6A21EDF3, x4A01CC93;
    uint x5555FFFF, x7F75FFFF, x00D20096, x7FA7FF69;
    uint x0A0A0000, x0AD80096, x00999900, x0AD99996;
    uint x22332233, x257AA5F0, x054885C0, xFAB77A3F, x2221EDF3, xD89697CC;
    uint x05B77AC0, x05F77AD6, x36C48529, x6391D07C, xBB0747B0;
    uint x4C460000, x4EDF9996, x2D4E49EA, xBBFFFFB0, x96B1B65A;
    uint x5AFF5AFF, x52B11215, x4201C010, x10B0D205;
    uint x00, x01, x10, x11, x20, x21, x30, x31;

    x55005500 = a1 & ~a5;
    x5A0F5A0F = a4 ^ x55005500;
    x3333FFFF = a3 | a6;
    x66666666 = a1 ^ a3;
    x22226666 = x3333FFFF & x66666666;
    x2D2D6969 = a4 ^ x22226666;
    x25202160 = x2D2D6969 & ~x5A0F5A0F;

    x00FFFF00 = a5 ^ a6;
    x33CCCC33 = a3 ^ x00FFFF00;
    x4803120C = x5A0F5A0F & ~x33CCCC33;
    x2222FFFF = a6 | x22226666;
    x6A21EDF3 = x4803120C ^ x2222FFFF;
    x4A01CC93 = x6A21EDF3 & ~x25202160;

    x5555FFFF = a1 | a6;
    x7F75FFFF = x6A21EDF3 | x5555FFFF;
    x00D20096 = a5 & ~x2D2D6969;
    x7FA7FF69 = x7F75FFFF ^ x00D20096;

    x0A0A0000 = a4 & ~x5555FFFF;
    x0AD80096 = x00D20096 ^ x0A0A0000;
    x00999900 = x00FFFF00 & ~x66666666;
    x0AD99996 = x0AD80096 | x00999900;

    x22332233 = a3 & ~x55005500;
    x257AA5F0 = x5A0F5A0F ^ x7F75FFFF;
    x054885C0 = x257AA5F0 & ~x22332233;
    xFAB77A3F = ~x054885C0;
    x2221EDF3 = x3333FFFF & x6A21EDF3;
    xD89697CC = xFAB77A3F ^ x2221EDF3;
    x20 = x7FA7FF69 & ~a2;
    x21 = x20 ^ xD89697CC;
    *out3 ^= x21;

    x05B77AC0 = x00FFFF00 ^ x054885C0;
    x05F77AD6 = x00D20096 | x05B77AC0;
    x36C48529 = x3333FFFF ^ x05F77AD6;
    x6391D07C = a1 ^ x36C48529;
    xBB0747B0 = xD89697CC ^ x6391D07C;
    x00 = x25202160 | a2;
    x01 = x00 ^ xBB0747B0;
    *out1 ^= x01;

    x4C460000 = x3333FFFF ^ x7F75FFFF;
    x4EDF9996 = x0AD99996 | x4C460000;
    x2D4E49EA = x6391D07C ^ x4EDF9996;
    xBBFFFFB0 = x00FFFF00 | xBB0747B0;
    x96B1B65A = x2D4E49EA ^ xBBFFFFB0;
    x10 = x4A01CC93 | a2;
    x11 = x10 ^ x96B1B65A;
    *out2 ^= x11;

    x5AFF5AFF = a5 | x5A0F5A0F;
    x52B11215 = x5AFF5AFF & ~x2D4E49EA;
    x4201C010 = x4A01CC93 & x6391D07C;
    x10B0D205 = x52B11215 ^ x4201C010;
    x30 = x10B0D205 | a2;
    x31 = x30 ^ x0AD99996;
    *out4 ^= x31;
}

/* s2-016276, 44 gates, 15 regs, 11 andn, 1/9/24/59/104 stalls, 67 biop */
__device__ inline void s2(uint a1, uint a2, uint a3, uint a4, uint a5, uint a6,
        uint *out1, uint *out2, uint *out3, uint *out4)
{
    uint x33CC33CC;
    uint x55550000, x00AA00FF, x33BB33FF;
    uint x33CC0000, x11441144, x11BB11BB, x003311BB;
    uint x00000F0F, x336600FF, x332200FF, x332200F0;
    uint x0302000F, xAAAAAAAA, xA9A8AAA5, x33CCCC33, x33CCC030, x9A646A95;
    uint x00333303, x118822B8, xA8208805, x3CC3C33C, x94E34B39;
    uint x0331330C, x3FF3F33C, xA9DF596A, xA9DF5F6F, x962CAC53;
    uint xA9466A6A, x3DA52153, x29850143, x33C0330C, x1A45324F;
    uint x0A451047, xBBDFDD7B, xB19ACD3C;
    uint x00, x01, x10, x11, x20, x21, x30, x31;

    x33CC33CC = a2 ^ a5;

    x55550000 = a1 & ~a6;
    x00AA00FF = a5 & ~x55550000;
    x33BB33FF = a2 | x00AA00FF;

    x33CC0000 = x33CC33CC & ~a6;
    x11441144 = a1 & x33CC33CC;
    x11BB11BB = a5 ^ x11441144;
    x003311BB = x11BB11BB & ~x33CC0000;

    x00000F0F = a3 & a6;
    x336600FF = x00AA00FF ^ x33CC0000;
    x332200FF = x33BB33FF & x336600FF;
    x332200F0 = x332200FF & ~x00000F0F;

    x0302000F = a3 & x332200FF;
    xAAAAAAAA = ~a1;
    xA9A8AAA5 = x0302000F ^ xAAAAAAAA;
    x33CCCC33 = a6 ^ x33CC33CC;
    x33CCC030 = x33CCCC33 & ~x00000F0F;
    x9A646A95 = xA9A8AAA5 ^ x33CCC030;
    x10 = a4 & ~x332200F0;
    x11 = x10 ^ x9A646A95;
    *out2 ^= x11;

    x00333303 = a2 & ~x33CCC030;
    x118822B8 = x11BB11BB ^ x00333303;
    xA8208805 = xA9A8AAA5 & ~x118822B8;
    x3CC3C33C = a3 ^ x33CCCC33;
    x94E34B39 = xA8208805 ^ x3CC3C33C;
    x00 = x33BB33FF & ~a4;
    x01 = x00 ^ x94E34B39;
    *out1 ^= x01;

    x0331330C = x0302000F ^ x00333303;
    x3FF3F33C = x3CC3C33C | x0331330C;
    xA9DF596A = x33BB33FF ^ x9A646A95;
    xA9DF5F6F = x00000F0F | xA9DF596A;
    x962CAC53 = x3FF3F33C ^ xA9DF5F6F;

    xA9466A6A = x332200FF ^ x9A646A95;
    x3DA52153 = x94E34B39 ^ xA9466A6A;
    x29850143 = xA9DF5F6F & x3DA52153;
    x33C0330C = x33CC33CC & x3FF3F33C;
    x1A45324F = x29850143 ^ x33C0330C;
    x20 = x1A45324F | a4;
    x21 = x20 ^ x962CAC53;
    *out3 ^= x21;

    x0A451047 = x1A45324F & ~x118822B8;
    xBBDFDD7B = x33CCCC33 | xA9DF596A;
    xB19ACD3C = x0A451047 ^ xBBDFDD7B;
    x30 = x003311BB | a4;
    x31 = x30 ^ xB19ACD3C;
    *out4 ^= x31;
}

/* s3-001283, 46 gates, 16 regs, 14 andn, 2/5/10/30/69 stalls, 69 biop */
__device__ inline void s3(uint a1, uint a2, uint a3, uint a4, uint a5, uint a6,
        uint *out1, uint *out2, uint *out3, uint *out4)
{
    uint x44444444, x0F0FF0F0, x4F4FF4F4, x00FFFF00, x00AAAA00, x4FE55EF4;
    uint x3C3CC3C3, x3C3C0000, x7373F4F4, x0C840A00;
    uint x00005EF4, x00FF5EFF, x00555455, x3C699796;
    uint x000FF000, x55AA55AA, x26D9A15E, x2FDFAF5F, x2FD00F5F;
    uint x55AAFFAA, x28410014, x000000FF, x000000CC, x284100D8;
    uint x204100D0, x3C3CC3FF, x1C3CC32F, x4969967A;
    uint x4CC44CC4, x40C040C0, xC3C33C3C, x9669C396, xD6A98356;
    uint xD6E9C3D6, x4CEEEEC4, x9A072D12, x001A000B, x9A1F2D1B;
    uint x00, x01, x10, x11, x20, x21, x30, x31;

    x44444444 = a1 & ~a2;
    x0F0FF0F0 = a3 ^ a6;
    x4F4FF4F4 = x44444444 | x0F0FF0F0;
    x00FFFF00 = a4 ^ a6;
    x00AAAA00 = x00FFFF00 & ~a1;
    x4FE55EF4 = x4F4FF4F4 ^ x00AAAA00;

    x3C3CC3C3 = a2 ^ x0F0FF0F0;
    x3C3C0000 = x3C3CC3C3 & ~a6;
    x7373F4F4 = x4F4FF4F4 ^ x3C3C0000;
    x0C840A00 = x4FE55EF4 & ~x7373F4F4;

    x00005EF4 = a6 & x4FE55EF4;
    x00FF5EFF = a4 | x00005EF4;
    x00555455 = a1 & x00FF5EFF;
    x3C699796 = x3C3CC3C3 ^ x00555455;
    x30 = x4FE55EF4 & ~a5;
    x31 = x30 ^ x3C699796;
    *out4 ^= x31;

    x000FF000 = x0F0FF0F0 & x00FFFF00;
    x55AA55AA = a1 ^ a4;
    x26D9A15E = x7373F4F4 ^ x55AA55AA;
    x2FDFAF5F = a3 | x26D9A15E;
    x2FD00F5F = x2FDFAF5F & ~x000FF000;

    x55AAFFAA = x00AAAA00 | x55AA55AA;
    x28410014 = x3C699796 & ~x55AAFFAA;
    x000000FF = a4 & a6;
    x000000CC = x000000FF & ~a2;
    x284100D8 = x28410014 ^ x000000CC;

    x204100D0 = x7373F4F4 & x284100D8;
    x3C3CC3FF = x3C3CC3C3 | x000000FF;
    x1C3CC32F = x3C3CC3FF & ~x204100D0;
    x4969967A = a1 ^ x1C3CC32F;
    x10 = x2FD00F5F & a5;
    x11 = x10 ^ x4969967A;
    *out2 ^= x11;

    x4CC44CC4 = x4FE55EF4 & ~a2;
    x40C040C0 = x4CC44CC4 & ~a3;
    xC3C33C3C = ~x3C3CC3C3;
    x9669C396 = x55AAFFAA ^ xC3C33C3C;
    xD6A98356 = x40C040C0 ^ x9669C396;
    x00 = a5 & ~x0C840A00;
    x01 = x00 ^ xD6A98356;
    *out1 ^= x01;

    xD6E9C3D6 = x40C040C0 | x9669C396;
    x4CEEEEC4 = x00AAAA00 | x4CC44CC4;
    x9A072D12 = xD6E9C3D6 ^ x4CEEEEC4;
    x001A000B = a4 & ~x4FE55EF4;
    x9A1F2D1B = x9A072D12 | x001A000B;
    x20 = a5 & ~x284100D8;
    x21 = x20 ^ x9A1F2D1B;
    *out3 ^= x21;
}

/* s4, 33 gates, 11/12 regs, 9 andn, 2/21/53/86/119 stalls, 52 biop */
__device__ inline void s4(uint a1, uint a2, uint a3, uint a4, uint a5, uint a6,
        uint *out1, uint *out2, uint *out3, uint *out4)
{
    uint x5A5A5A5A, x0F0FF0F0;
    uint x33FF33FF, x33FFCC00, x0C0030F0, x0C0CC0C0, x0CF3C03F, x5EFBDA7F,
        x52FBCA0F, x61C8F93C;
    uint x00C0C03C, x0F0F30C0, x3B92A366, x30908326, x3C90B3D6;
    uint x33CC33CC, x0C0CFFFF, x379E5C99, x04124C11, x56E9861E, xA91679E1;
    uint x9586CA37, x8402C833, x84C2C83F, xB35C94A6;
    uint x00, x01, x10, x11, x20, x21, x30, x31;

    x5A5A5A5A = a1 ^ a3;
    x0F0FF0F0 = a3 ^ a5;
    x33FF33FF = a2 | a4;
    x33FFCC00 = a5 ^ x33FF33FF;
    x0C0030F0 = x0F0FF0F0 & ~x33FFCC00;
    x0C0CC0C0 = x0F0FF0F0 & ~a2;
    x0CF3C03F = a4 ^ x0C0CC0C0;
    x5EFBDA7F = x5A5A5A5A | x0CF3C03F;
    x52FBCA0F = x5EFBDA7F & ~x0C0030F0;
    x61C8F93C = a2 ^ x52FBCA0F;

    x00C0C03C = x0CF3C03F & x61C8F93C;
    x0F0F30C0 = x0F0FF0F0 & ~x00C0C03C;
    x3B92A366 = x5A5A5A5A ^ x61C8F93C;
    x30908326 = x3B92A366 & ~x0F0F30C0;
    x3C90B3D6 = x0C0030F0 ^ x30908326;

    x33CC33CC = a2 ^ a4;
    x0C0CFFFF = a5 | x0C0CC0C0;
    x379E5C99 = x3B92A366 ^ x0C0CFFFF;
    x04124C11 = x379E5C99 & ~x33CC33CC;
    x56E9861E = x52FBCA0F ^ x04124C11;
    x00 = a6 & ~x3C90B3D6;
    x01 = x00 ^ x56E9861E;
    *out1 ^= x01;

    xA91679E1 = ~x56E9861E;
    x10 = x3C90B3D6 & ~a6;
    x11 = x10 ^ xA91679E1;
    *out2 ^= x11;

    x9586CA37 = x3C90B3D6 ^ xA91679E1;
    x8402C833 = x9586CA37 & ~x33CC33CC;
    x84C2C83F = x00C0C03C | x8402C833;
    xB35C94A6 = x379E5C99 ^ x84C2C83F;
    x20 = x61C8F93C | a6;
    x21 = x20 ^ xB35C94A6;
    *out3 ^= x21;

    x30 = a6 & x61C8F93C;
    x31 = x30 ^ xB35C94A6;
    *out4 ^= x31;
}

/* s5-04829, 48 gates, 15/16 regs, 9 andn, 4/24/65/113/163 stalls, 72 biop */
/* Currently used for x86-64 SSE2 */
__device__ inline void s5(uint a1, uint a2, uint a3, uint a4, uint a5, uint a6,
        uint *out1, uint *out2, uint *out3, uint *out4)
{
    uint x77777777, x77770000, x22225555, x11116666, x1F1F6F6F;
    uint x70700000, x43433333, x00430033, x55557777, x55167744, x5A19784B;
    uint x5A1987B4, x7A3BD7F5, x003B00F5, x221955A0, x05050707, x271C52A7;
    uint x2A2A82A0, x6969B193, x1FE06F90, x16804E00, xE97FB1FF;
    uint x43403302, x35CAED30, x37DEFFB7, x349ECCB5, x0B01234A;
    uint x101884B4, x0FF8EB24, x41413333, x4FF9FB37, x4FC2FBC2;
    uint x22222222, x16BCEE97, x0F080B04, x19B4E593;
    uint x5C5C5C5C, x4448184C, x2DDABE71, x6992A63D;
    uint x00, x01, x10, x11, x20, x21, x30, x31;

    x77777777 = a1 | a3;
    x77770000 = x77777777 & ~a6;
    x22225555 = a1 ^ x77770000;
    x11116666 = a3 ^ x22225555;
    x1F1F6F6F = a4 | x11116666;

    x70700000 = x77770000 & ~a4;
    x43433333 = a3 ^ x70700000;
    x00430033 = a5 & x43433333;
    x55557777 = a1 | x11116666;
    x55167744 = x00430033 ^ x55557777;
    x5A19784B = a4 ^ x55167744;

    x5A1987B4 = a6 ^ x5A19784B;
    x7A3BD7F5 = x22225555 | x5A1987B4;
    x003B00F5 = a5 & x7A3BD7F5;
    x221955A0 = x22225555 ^ x003B00F5;
    x05050707 = a4 & x55557777;
    x271C52A7 = x221955A0 ^ x05050707;

    x2A2A82A0 = x7A3BD7F5 & ~a1;
    x6969B193 = x43433333 ^ x2A2A82A0;
    x1FE06F90 = a5 ^ x1F1F6F6F;
    x16804E00 = x1FE06F90 & ~x6969B193;
    xE97FB1FF = ~x16804E00;
    x20 = xE97FB1FF & ~a2;
    x21 = x20 ^ x5A19784B;
    *out3 ^= x21;

    x43403302 = x43433333 & ~x003B00F5;
    x35CAED30 = x2A2A82A0 ^ x1FE06F90;
    x37DEFFB7 = x271C52A7 | x35CAED30;
    x349ECCB5 = x37DEFFB7 & ~x43403302;
    x0B01234A = x1F1F6F6F & ~x349ECCB5;

    x101884B4 = x5A1987B4 & x349ECCB5;
    x0FF8EB24 = x1FE06F90 ^ x101884B4;
    x41413333 = x43433333 & x55557777;
    x4FF9FB37 = x0FF8EB24 | x41413333;
    x4FC2FBC2 = x003B00F5 ^ x4FF9FB37;
    x30 = x4FC2FBC2 & a2;
    x31 = x30 ^ x271C52A7;
    *out4 ^= x31;

    x22222222 = a1 ^ x77777777;
    x16BCEE97 = x349ECCB5 ^ x22222222;
    x0F080B04 = a4 & x0FF8EB24;
    x19B4E593 = x16BCEE97 ^ x0F080B04;
    x00 = x0B01234A | a2;
    x01 = x00 ^ x19B4E593;
    *out1 ^= x01;

    x5C5C5C5C = x1F1F6F6F ^ x43433333;
    x4448184C = x5C5C5C5C & ~x19B4E593;
    x2DDABE71 = x22225555 ^ x0FF8EB24;
    x6992A63D = x4448184C ^ x2DDABE71;
    x10 = x1F1F6F6F & a2;
    x11 = x10 ^ x6992A63D;
    *out2 ^= x11;
}

/* s6-000007, 46 gates, 19 regs, 8 andn, 3/19/39/66/101 stalls, 69 biop */
/* Currently used for x86-64 SSE2 */
__device__ inline void s6(uint a1, uint a2, uint a3, uint a4, uint a5, uint a6,
        uint *out1, uint *out2, uint *out3, uint *out4)
{
    uint x33CC33CC;
    uint x3333FFFF, x11115555, x22DD6699, x22DD9966, x00220099;
    uint x00551144, x33662277, x5A5A5A5A, x7B7E7A7F, x59A31CE6;
    uint x09030C06, x09030000, x336622FF, x3A6522FF;
    uint x484D494C, x0000B6B3, x0F0FB9BC, x00FC00F9, x0FFFB9FD;
    uint x5DF75DF7, x116600F7, x1E69B94B, x1668B94B;
    uint x7B7B7B7B, x411E5984, x1FFFFDFD, x5EE1A479;
    uint x3CB4DFD2, x004B002D, xB7B2B6B3, xCCC9CDC8, xCC82CDE5;
    uint x0055EEBB, x5A5AECE9, x0050ECA9, xC5CAC1CE, xC59A2D67;
    uint x00, x01, x10, x11, x20, x21, x30, x31;

    x33CC33CC = a2 ^ a5;

    x3333FFFF = a2 | a6;
    x11115555 = a1 & x3333FFFF;
    x22DD6699 = x33CC33CC ^ x11115555;
    x22DD9966 = a6 ^ x22DD6699;
    x00220099 = a5 & ~x22DD9966;

    x00551144 = a1 & x22DD9966;
    x33662277 = a2 ^ x00551144;
    x5A5A5A5A = a1 ^ a3;
    x7B7E7A7F = x33662277 | x5A5A5A5A;
    x59A31CE6 = x22DD6699 ^ x7B7E7A7F;

    x09030C06 = a3 & x59A31CE6;
    x09030000 = x09030C06 & ~a6;
    x336622FF = x00220099 | x33662277;
    x3A6522FF = x09030000 ^ x336622FF;
    x30 = x3A6522FF & a4;
    x31 = x30 ^ x59A31CE6;
    *out4 ^= x31;

    x484D494C = a2 ^ x7B7E7A7F;
    x0000B6B3 = a6 & ~x484D494C;
    x0F0FB9BC = a3 ^ x0000B6B3;
    x00FC00F9 = a5 & ~x09030C06;
    x0FFFB9FD = x0F0FB9BC | x00FC00F9;

    x5DF75DF7 = a1 | x59A31CE6;
    x116600F7 = x336622FF & x5DF75DF7;
    x1E69B94B = x0F0FB9BC ^ x116600F7;
    x1668B94B = x1E69B94B & ~x09030000;
    x20 = x00220099 | a4;
    x21 = x20 ^ x1668B94B;
    *out3 ^= x21;

    x7B7B7B7B = a2 | x5A5A5A5A;
    x411E5984 = x3A6522FF ^ x7B7B7B7B;
    x1FFFFDFD = x11115555 | x0FFFB9FD;
    x5EE1A479 = x411E5984 ^ x1FFFFDFD;

    x3CB4DFD2 = x22DD6699 ^ x1E69B94B;
    x004B002D = a5 & ~x3CB4DFD2;
    xB7B2B6B3 = ~x484D494C;
    xCCC9CDC8 = x7B7B7B7B ^ xB7B2B6B3;
    xCC82CDE5 = x004B002D ^ xCCC9CDC8;
    x10 = xCC82CDE5 & ~a4;
    x11 = x10 ^ x5EE1A479;
    *out2 ^= x11;

    x0055EEBB = a6 ^ x00551144;
    x5A5AECE9 = a1 ^ x0F0FB9BC;
    x0050ECA9 = x0055EEBB & x5A5AECE9;
    xC5CAC1CE = x09030C06 ^ xCCC9CDC8;
    xC59A2D67 = x0050ECA9 ^ xC5CAC1CE;
    x00 = x0FFFB9FD & ~a4;
    x01 = x00 ^ xC59A2D67;
    *out1 ^= x01;
}

/* s7-056945, 46 gates, 16 regs, 7 andn, 10/31/62/107/156 stalls, 67 biop */
/* Currently used for MMX/SSE2 */
__device__ inline void s7(uint a1, uint a2, uint a3, uint a4, uint a5, uint a6,
        uint *out1, uint *out2, uint *out3, uint *out4)
{
    uint x0FF00FF0, x3CC33CC3, x00003CC3, x0F000F00, x5A555A55, x00001841;
    uint x00000F00, x33333C33, x7B777E77, x0FF0F00F, x74878E78;
    uint x003C003C, x5A7D5A7D, x333300F0, x694E5A8D;
    uint x0FF0CCCC, x000F0303, x5A505854, x33CC000F, x699C585B;
    uint x7F878F78, x21101013, x7F979F7B, x30030CC0, x4F9493BB;
    uint x6F9CDBFB, x0000DBFB, x00005151, x26DAC936, x26DA9867;
    uint x27DA9877, x27DA438C, x2625C9C9, x27FFCBCD;
    uint x27FF1036, x27FF103E, xB06B6C44, x97947C7A;
    uint x00, x01, x10, x11, x20, x21, x30, x31;

    x0FF00FF0 = a4 ^ a5;
    x3CC33CC3 = a3 ^ x0FF00FF0;
    x00003CC3 = a6 & x3CC33CC3;
    x0F000F00 = a4 & x0FF00FF0;
    x5A555A55 = a2 ^ x0F000F00;
    x00001841 = x00003CC3 & x5A555A55;

    x00000F00 = a6 & x0F000F00;
    x33333C33 = a3 ^ x00000F00;
    x7B777E77 = x5A555A55 | x33333C33;
    x0FF0F00F = a6 ^ x0FF00FF0;
    x74878E78 = x7B777E77 ^ x0FF0F00F;
    x30 = a1 & ~x00001841;
    x31 = x30 ^ x74878E78;
    *out4 ^= x31;

    x003C003C = a5 & ~x3CC33CC3;
    x5A7D5A7D = x5A555A55 | x003C003C;
    x333300F0 = x00003CC3 ^ x33333C33;
    x694E5A8D = x5A7D5A7D ^ x333300F0;

    x0FF0CCCC = x00003CC3 ^ x0FF0F00F;
    x000F0303 = a4 & ~x0FF0CCCC;
    x5A505854 = x5A555A55 & ~x000F0303;
    x33CC000F = a5 ^ x333300F0;
    x699C585B = x5A505854 ^ x33CC000F;

    x7F878F78 = x0F000F00 | x74878E78;
    x21101013 = a3 & x699C585B;
    x7F979F7B = x7F878F78 | x21101013;
    x30030CC0 = x3CC33CC3 & ~x0FF0F00F;
    x4F9493BB = x7F979F7B ^ x30030CC0;
    x00 = x4F9493BB & ~a1;
    x01 = x00 ^ x694E5A8D;
    *out1 ^= x01;

    x6F9CDBFB = x699C585B | x4F9493BB;
    x0000DBFB = a6 & x6F9CDBFB;
    x00005151 = a2 & x0000DBFB;
    x26DAC936 = x694E5A8D ^ x4F9493BB;
    x26DA9867 = x00005151 ^ x26DAC936;

    x27DA9877 = x21101013 | x26DA9867;
    x27DA438C = x0000DBFB ^ x27DA9877;
    x2625C9C9 = a5 ^ x26DAC936;
    x27FFCBCD = x27DA438C | x2625C9C9;
    x20 = x27FFCBCD & a1;
    x21 = x20 ^ x699C585B;
    *out3 ^= x21;

    x27FF1036 = x0000DBFB ^ x27FFCBCD;
    x27FF103E = x003C003C | x27FF1036;
    xB06B6C44 = ~x4F9493BB;
    x97947C7A = x27FF103E ^ xB06B6C44;
    x10 = x97947C7A & ~a1;
    x11 = x10 ^ x26DA9867;
    *out2 ^= x11;
}

/* s8-019374, 41 gates, 14 regs, 7 andn, 4/25/61/103/145 stalls, 59 biop */
/* Currently used for x86-64 SSE2 */
__device__ inline void s8(uint a1, uint a2, uint a3, uint a4, uint a5, uint a6,
        uint *out1, uint *out2, uint *out3, uint *out4)
{
    uint x0C0C0C0C, x0000F0F0, x00FFF00F, x00555005, x00515001;
    uint x33000330, x77555775, x30303030, x3030CFCF, x30104745, x30555745;
    uint xFF000FF0, xCF1048B5, x080A080A, xC71A40BF, xCB164CB3;
    uint x9E4319E6, x000019E6, xF429738C, xF4296A6A, xC729695A;
    uint xC47C3D2F, xF77F3F3F, x9E43E619, x693CD926;
    uint xF719A695, xF4FF73FF, x03E6D56A, x56B3803F;
    uint xF700A600, x61008000, x03B7856B, x62B7056B;
    uint x00, x01, x10, x11, x20, x21, x30, x31;

    x0C0C0C0C = a3 & ~a2;
    x0000F0F0 = a5 & ~a3;
    x00FFF00F = a4 ^ x0000F0F0;
    x00555005 = a1 & x00FFF00F;
    x00515001 = x00555005 & ~x0C0C0C0C;

    x33000330 = a2 & ~x00FFF00F;
    x77555775 = a1 | x33000330;
    x30303030 = a2 & ~a3;
    x3030CFCF = a5 ^ x30303030;
    x30104745 = x77555775 & x3030CFCF;
    x30555745 = x00555005 | x30104745;

    xFF000FF0 = ~x00FFF00F;
    xCF1048B5 = x30104745 ^ xFF000FF0;
    x080A080A = a3 & ~x77555775;
    xC71A40BF = xCF1048B5 ^ x080A080A;
    xCB164CB3 = x0C0C0C0C ^ xC71A40BF;
    x10 = x00515001 | a6;
    x11 = x10 ^ xCB164CB3;
    *out2 ^= x11;

    x9E4319E6 = a1 ^ xCB164CB3;
    x000019E6 = a5 & x9E4319E6;
    xF429738C = a2 ^ xC71A40BF;
    xF4296A6A = x000019E6 ^ xF429738C;
    xC729695A = x33000330 ^ xF4296A6A;

    xC47C3D2F = x30555745 ^ xF4296A6A;
    xF77F3F3F = a2 | xC47C3D2F;
    x9E43E619 = a5 ^ x9E4319E6;
    x693CD926 = xF77F3F3F ^ x9E43E619;
    x20 = x30555745 & a6;
    x21 = x20 ^ x693CD926;
    *out3 ^= x21;

    xF719A695 = x3030CFCF ^ xC729695A;
    xF4FF73FF = a4 | xF429738C;
    x03E6D56A = xF719A695 ^ xF4FF73FF;
    x56B3803F = a1 ^ x03E6D56A;
    x30 = x56B3803F & a6;
    x31 = x30 ^ xC729695A;
    *out4 ^= x31;

    xF700A600 = xF719A695 & ~a4;
    x61008000 = x693CD926 & xF700A600;
    x03B7856B = x00515001 ^ x03E6D56A;
    x62B7056B = x61008000 ^ x03B7856B;
    x00 = x62B7056B | a6;
    x01 = x00 ^ xC729695A;
    *out1 ^= x01;
}

__device__ inline void f1(uint in[], uint key[], uint out[])
{
    s1(in[31] ^ key[8],
       in[0] ^ key[44],
       in[1] ^ key[29],
       in[2] ^ key[52],
       in[3] ^ key[42],
       in[4] ^ key[14],
       &out[8],
       &out[16],
       &out[22],
       &out[30]
    );
    s2(in[3] ^ key[28],
       in[4] ^ key[49],
       in[5] ^ key[1],
       in[6] ^ key[7],
       in[7] ^ key[16],
       in[8] ^ key[36],
       &out[12],
       &out[27],
       &out[1],
       &out[17]
    );
    s3(in[7] ^ key[2],
       in[8] ^ key[30],
       in[9] ^ key[22],
       in[10] ^ key[21],
       in[11] ^ key[38],
       in[12] ^ key[50],
       &out[23],
       &out[15],
       &out[29],
       &out[5]
    );
    s4(in[11] ^ key[51],
       in[12] ^ key[0],
       in[13] ^ key[31],
       in[14] ^ key[23],
       in[15] ^ key[15],
       in[16] ^ key[35],
       &out[25],
       &out[19],
       &out[9],
       &out[0]
    );
    s5(in[15] ^ key[19],
       in[16] ^ key[24],
       in[17] ^ key[34],
       in[18] ^ key[47],
       in[19] ^ key[32],
       in[20] ^ key[3],
       &out[7],
       &out[13],
       &out[24],
       &out[2]
    );
    s6(in[19] ^ key[41],
       in[20] ^ key[26],
       in[21] ^ key[4],
       in[22] ^ key[46],
       in[23] ^ key[20],
       in[24] ^ key[25],
       &out[3],
       &out[28],
       &out[10],
       &out[18]
    );
    s7(in[23] ^ key[53],
       in[24] ^ key[18],
       in[25] ^ key[33],
       in[26] ^ key[55],
       in[27] ^ key[13],
       in[28] ^ key[17],
       &out[31],
       &out[11],
       &out[21],
       &out[6]
    );
    s8(in[27] ^ key[39],
       in[28] ^ key[12],
       in[29] ^ key[11],
       in[30] ^ key[54],
       in[31] ^ key[48],
       in[0] ^ key[27],
       &out[4],
       &out[26],
       &out[14],
       &out[20]
    );
}

__device__ inline void f2(uint in[], uint key[], uint out[])
{
    s1(in[31] ^ key[1],
       in[0] ^ key[37],
       in[1] ^ key[22],
       in[2] ^ key[45],
       in[3] ^ key[35],
       in[4] ^ key[7],
       &out[8],
       &out[16],
       &out[22],
       &out[30]
    );
    s2(in[3] ^ key[21],
       in[4] ^ key[42],
       in[5] ^ key[51],
       in[6] ^ key[0],
       in[7] ^ key[9],
       in[8] ^ key[29],
       &out[12],
       &out[27],
       &out[1],
       &out[17]
    );
    s3(in[7] ^ key[52],
       in[8] ^ key[23],
       in[9] ^ key[15],
       in[10] ^ key[14],
       in[11] ^ key[31],
       in[12] ^ key[43],
       &out[23],
       &out[15],
       &out[29],
       &out[5]
    );
    s4(in[11] ^ key[44],
       in[12] ^ key[50],
       in[13] ^ key[49],
       in[14] ^ key[16],
       in[15] ^ key[8],
       in[16] ^ key[28],
       &out[25],
       &out[19],
       &out[9],
       &out[0]
    );
    s5(in[15] ^ key[12],
       in[16] ^ key[17],
       in[17] ^ key[27],
       in[18] ^ key[40],
       in[19] ^ key[25],
       in[20] ^ key[55],
       &out[7],
       &out[13],
       &out[24],
       &out[2]
    );
    s6(in[19] ^ key[34],
       in[20] ^ key[19],
       in[21] ^ key[24],
       in[22] ^ key[39],
       in[23] ^ key[13],
       in[24] ^ key[18],
       &out[3],
       &out[28],
       &out[10],
       &out[18]
    );
    s7(in[23] ^ key[46],
       in[24] ^ key[11],
       in[25] ^ key[26],
       in[26] ^ key[48],
       in[27] ^ key[6],
       in[28] ^ key[10],
       &out[31],
       &out[11],
       &out[21],
       &out[6]
    );
    s8(in[27] ^ key[32],
       in[28] ^ key[5],
       in[29] ^ key[4],
       in[30] ^ key[47],
       in[31] ^ key[41],
       in[0] ^ key[20],
       &out[4],
       &out[26],
       &out[14],
       &out[20]
    );
}

__device__ inline void f3(uint in[], uint key[], uint out[])
{
    s1(in[31] ^ key[44],
       in[0] ^ key[23],
       in[1] ^ key[8],
       in[2] ^ key[31],
       in[3] ^ key[21],
       in[4] ^ key[50],
       &out[8],
       &out[16],
       &out[22],
       &out[30]
    );
    s2(in[3] ^ key[7],
       in[4] ^ key[28],
       in[5] ^ key[37],
       in[6] ^ key[43],
       in[7] ^ key[52],
       in[8] ^ key[15],
       &out[12],
       &out[27],
       &out[1],
       &out[17]
    );
    s3(in[7] ^ key[38],
       in[8] ^ key[9],
       in[9] ^ key[1],
       in[10] ^ key[0],
       in[11] ^ key[42],
       in[12] ^ key[29],
       &out[23],
       &out[15],
       &out[29],
       &out[5]
    );
    s4(in[11] ^ key[30],
       in[12] ^ key[36],
       in[13] ^ key[35],
       in[14] ^ key[2],
       in[15] ^ key[51],
       in[16] ^ key[14],
       &out[25],
       &out[19],
       &out[9],
       &out[0]
    );
    s5(in[15] ^ key[53],
       in[16] ^ key[3],
       in[17] ^ key[13],
       in[18] ^ key[26],
       in[19] ^ key[11],
       in[20] ^ key[41],
       &out[7],
       &out[13],
       &out[24],
       &out[2]
    );
    s6(in[19] ^ key[20],
       in[20] ^ key[5],
       in[21] ^ key[10],
       in[22] ^ key[25],
       in[23] ^ key[54],
       in[24] ^ key[4],
       &out[3],
       &out[28],
       &out[10],
       &out[18]
    );
    s7(in[23] ^ key[32],
       in[24] ^ key[24],
       in[25] ^ key[12],
       in[26] ^ key[34],
       in[27] ^ key[47],
       in[28] ^ key[55],
       &out[31],
       &out[11],
       &out[21],
       &out[6]
    );
    s8(in[27] ^ key[18],
       in[28] ^ key[46],
       in[29] ^ key[17],
       in[30] ^ key[33],
       in[31] ^ key[27],
       in[0] ^ key[6],
       &out[4],
       &out[26],
       &out[14],
       &out[20]
    );
}

__device__ inline void f4(uint in[], uint key[], uint out[])
{
    s1(in[31] ^ key[30],
       in[0] ^ key[9],
       in[1] ^ key[51],
       in[2] ^ key[42],
       in[3] ^ key[7],
       in[4] ^ key[36],
       &out[8],
       &out[16],
       &out[22],
       &out[30]
    );
    s2(in[3] ^ key[50],
       in[4] ^ key[14],
       in[5] ^ key[23],
       in[6] ^ key[29],
       in[7] ^ key[38],
       in[8] ^ key[1],
       &out[12],
       &out[27],
       &out[1],
       &out[17]
    );
    s3(in[7] ^ key[49],
       in[8] ^ key[52],
       in[9] ^ key[44],
       in[10] ^ key[43],
       in[11] ^ key[28],
       in[12] ^ key[15],
       &out[23],
       &out[15],
       &out[29],
       &out[5]
    );
    s4(in[11] ^ key[16],
       in[12] ^ key[22],
       in[13] ^ key[21],
       in[14] ^ key[45],
       in[15] ^ key[37],
       in[16] ^ key[0],
       &out[25],
       &out[19],
       &out[9],
       &out[0]
    );
    s5(in[15] ^ key[39],
       in[16] ^ key[48],
       in[17] ^ key[54],
       in[18] ^ key[12],
       in[19] ^ key[24],
       in[20] ^ key[27],
       &out[7],
       &out[13],
       &out[24],
       &out[2]
    );
    s6(in[19] ^ key[6],
       in[20] ^ key[46],
       in[21] ^ key[55],
       in[22] ^ key[11],
       in[23] ^ key[40],
       in[24] ^ key[17],
       &out[3],
       &out[28],
       &out[10],
       &out[18]
    );
    s7(in[23] ^ key[18],
       in[24] ^ key[10],
       in[25] ^ key[53],
       in[26] ^ key[20],
       in[27] ^ key[33],
       in[28] ^ key[41],
       &out[31],
       &out[11],
       &out[21],
       &out[6]
    );
    s8(in[27] ^ key[4],
       in[28] ^ key[32],
       in[29] ^ key[3],
       in[30] ^ key[19],
       in[31] ^ key[13],
       in[0] ^ key[47],
       &out[4],
       &out[26],
       &out[14],
       &out[20]
    );
}

__device__ inline void f5(uint in[], uint key[], uint out[])
{
    s1(in[31] ^ key[16],
       in[0] ^ key[52],
       in[1] ^ key[37],
       in[2] ^ key[28],
       in[3] ^ key[50],
       in[4] ^ key[22],
       &out[8],
       &out[16],
       &out[22],
       &out[30]
    );
    s2(in[3] ^ key[36],
       in[4] ^ key[0],
       in[5] ^ key[9],
       in[6] ^ key[15],
       in[7] ^ key[49],
       in[8] ^ key[44],
       &out[12],
       &out[27],
       &out[1],
       &out[17]
    );
    s3(in[7] ^ key[35],
       in[8] ^ key[38],
       in[9] ^ key[30],
       in[10] ^ key[29],
       in[11] ^ key[14],
       in[12] ^ key[1],
       &out[23],
       &out[15],
       &out[29],
       &out[5]
    );
    s4(in[11] ^ key[2],
       in[12] ^ key[8],
       in[13] ^ key[7],
       in[14] ^ key[31],
       in[15] ^ key[23],
       in[16] ^ key[43],
       &out[25],
       &out[19],
       &out[9],
       &out[0]
    );
    s5(in[15] ^ key[25],
       in[16] ^ key[34],
       in[17] ^ key[40],
       in[18] ^ key[53],
       in[19] ^ key[10],
       in[20] ^ key[13],
       &out[7],
       &out[13],
       &out[24],
       &out[2]
    );
    s6(in[19] ^ key[47],
       in[20] ^ key[32],
       in[21] ^ key[41],
       in[22] ^ key[24],
       in[23] ^ key[26],
       in[24] ^ key[3],
       &out[3],
       &out[28],
       &out[10],
       &out[18]
    );
    s7(in[23] ^ key[4],
       in[24] ^ key[55],
       in[25] ^ key[39],
       in[26] ^ key[6],
       in[27] ^ key[19],
       in[28] ^ key[27],
       &out[31],
       &out[11],
       &out[21],
       &out[6]
    );
    s8(in[27] ^ key[17],
       in[28] ^ key[18],
       in[29] ^ key[48],
       in[30] ^ key[5],
       in[31] ^ key[54],
       in[0] ^ key[33],
       &out[4],
       &out[26],
       &out[14],
       &out[20]
    );
}

__device__ inline void f6(uint in[], uint key[], uint out[])
{
    s1(in[31] ^ key[2],
       in[0] ^ key[38],
       in[1] ^ key[23],
       in[2] ^ key[14],
       in[3] ^ key[36],
       in[4] ^ key[8],
       &out[8],
       &out[16],
       &out[22],
       &out[30]
    );
    s2(in[3] ^ key[22],
       in[4] ^ key[43],
       in[5] ^ key[52],
       in[6] ^ key[1],
       in[7] ^ key[35],
       in[8] ^ key[30],
       &out[12],
       &out[27],
       &out[1],
       &out[17]
    );
    s3(in[7] ^ key[21],
       in[8] ^ key[49],
       in[9] ^ key[16],
       in[10] ^ key[15],
       in[11] ^ key[0],
       in[12] ^ key[44],
       &out[23],
       &out[15],
       &out[29],
       &out[5]
    );
    s4(in[11] ^ key[45],
       in[12] ^ key[51],
       in[13] ^ key[50],
       in[14] ^ key[42],
       in[15] ^ key[9],
       in[16] ^ key[29],
       &out[25],
       &out[19],
       &out[9],
       &out[0]
    );
    s5(in[15] ^ key[11],
       in[16] ^ key[20],
       in[17] ^ key[26],
       in[18] ^ key[39],
       in[19] ^ key[55],
       in[20] ^ key[54],
       &out[7],
       &out[13],
       &out[24],
       &out[2]
    );
    s6(in[19] ^ key[33],
       in[20] ^ key[18],
       in[21] ^ key[27],
       in[22] ^ key[10],
       in[23] ^ key[12],
       in[24] ^ key[48],
       &out[3],
       &out[28],
       &out[10],
       &out[18]
    );
    s7(in[23] ^ key[17],
       in[24] ^ key[41],
       in[25] ^ key[25],
       in[26] ^ key[47],
       in[27] ^ key[5],
       in[28] ^ key[13],
       &out[31],
       &out[11],
       &out[21],
       &out[6]
    );
    s8(in[27] ^ key[3],
       in[28] ^ key[4],
       in[29] ^ key[34],
       in[30] ^ key[46],
       in[31] ^ key[40],
       in[0] ^ key[19],
       &out[4],
       &out[26],
       &out[14],
       &out[20]
    );
}

__device__ inline void f7(uint in[], uint key[], uint out[])
{
    s1(in[31] ^ key[45],
       in[0] ^ key[49],
       in[1] ^ key[9],
       in[2] ^ key[0],
       in[3] ^ key[22],
       in[4] ^ key[51],
       &out[8],
       &out[16],
       &out[22],
       &out[30]
    );
    s2(in[3] ^ key[8],
       in[4] ^ key[29],
       in[5] ^ key[38],
       in[6] ^ key[44],
       in[7] ^ key[21],
       in[8] ^ key[16],
       &out[12],
       &out[27],
       &out[1],
       &out[17]
    );
    s3(in[7] ^ key[7],
       in[8] ^ key[35],
       in[9] ^ key[2],
       in[10] ^ key[1],
       in[11] ^ key[43],
       in[12] ^ key[30],
       &out[23],
       &out[15],
       &out[29],
       &out[5]
    );
    s4(in[11] ^ key[31],
       in[12] ^ key[37],
       in[13] ^ key[36],
       in[14] ^ key[28],
       in[15] ^ key[52],
       in[16] ^ key[15],
       &out[25],
       &out[19],
       &out[9],
       &out[0]
    );
    s5(in[15] ^ key[24],
       in[16] ^ key[6],
       in[17] ^ key[12],
       in[18] ^ key[25],
       in[19] ^ key[41],
       in[20] ^ key[40],
       &out[7],
       &out[13],
       &out[24],
       &out[2]
    );
    s6(in[19] ^ key[19],
       in[20] ^ key[4],
       in[21] ^ key[13],
       in[22] ^ key[55],
       in[23] ^ key[53],
       in[24] ^ key[34],
       &out[3],
       &out[28],
       &out[10],
       &out[18]
    );
    s7(in[23] ^ key[3],
       in[24] ^ key[27],
       in[25] ^ key[11],
       in[26] ^ key[33],
       in[27] ^ key[46],
       in[28] ^ key[54],
       &out[31],
       &out[11],
       &out[21],
       &out[6]
    );
    s8(in[27] ^ key[48],
       in[28] ^ key[17],
       in[29] ^ key[20],
       in[30] ^ key[32],
       in[31] ^ key[26],
       in[0] ^ key[5],
       &out[4],
       &out[26],
       &out[14],
       &out[20]
    );
}

__device__ inline void f8(uint in[], uint key[], uint out[])
{
    s1(in[31] ^ key[31],
       in[0] ^ key[35],
       in[1] ^ key[52],
       in[2] ^ key[43],
       in[3] ^ key[8],
       in[4] ^ key[37],
       &out[8],
       &out[16],
       &out[22],
       &out[30]
    );
    s2(in[3] ^ key[51],
       in[4] ^ key[15],
       in[5] ^ key[49],
       in[6] ^ key[30],
       in[7] ^ key[7],
       in[8] ^ key[2],
       &out[12],
       &out[27],
       &out[1],
       &out[17]
    );
    s3(in[7] ^ key[50],
       in[8] ^ key[21],
       in[9] ^ key[45],
       in[10] ^ key[44],
       in[11] ^ key[29],
       in[12] ^ key[16],
       &out[23],
       &out[15],
       &out[29],
       &out[5]
    );
    s4(in[11] ^ key[42],
       in[12] ^ key[23],
       in[13] ^ key[22],
       in[14] ^ key[14],
       in[15] ^ key[38],
       in[16] ^ key[1],
       &out[25],
       &out[19],
       &out[9],
       &out[0]
    );
    s5(in[15] ^ key[10],
       in[16] ^ key[47],
       in[17] ^ key[53],
       in[18] ^ key[11],
       in[19] ^ key[27],
       in[20] ^ key[26],
       &out[7],
       &out[13],
       &out[24],
       &out[2]
    );
    s6(in[19] ^ key[5],
       in[20] ^ key[17],
       in[21] ^ key[54],
       in[22] ^ key[41],
       in[23] ^ key[39],
       in[24] ^ key[20],
       &out[3],
       &out[28],
       &out[10],
       &out[18]
    );
    s7(in[23] ^ key[48],
       in[24] ^ key[13],
       in[25] ^ key[24],
       in[26] ^ key[19],
       in[27] ^ key[32],
       in[28] ^ key[40],
       &out[31],
       &out[11],
       &out[21],
       &out[6]
    );
    s8(in[27] ^ key[34],
       in[28] ^ key[3],
       in[29] ^ key[6],
       in[30] ^ key[18],
       in[31] ^ key[12],
       in[0] ^ key[46],
       &out[4],
       &out[26],
       &out[14],
       &out[20]
    );
}

__device__ inline void f9(uint in[], uint key[], uint out[])
{
    s1(in[31] ^ key[49],
       in[0] ^ key[28],
       in[1] ^ key[45],
       in[2] ^ key[36],
       in[3] ^ key[1],
       in[4] ^ key[30],
       &out[8],
       &out[16],
       &out[22],
       &out[30]
    );
    s2(in[3] ^ key[44],
       in[4] ^ key[8],
       in[5] ^ key[42],
       in[6] ^ key[23],
       in[7] ^ key[0],
       in[8] ^ key[52],
       &out[12],
       &out[27],
       &out[1],
       &out[17]
    );
    s3(in[7] ^ key[43],
       in[8] ^ key[14],
       in[9] ^ key[38],
       in[10] ^ key[37],
       in[11] ^ key[22],
       in[12] ^ key[9],
       &out[23],
       &out[15],
       &out[29],
       &out[5]
    );
    s4(in[11] ^ key[35],
       in[12] ^ key[16],
       in[13] ^ key[15],
       in[14] ^ key[7],
       in[15] ^ key[31],
       in[16] ^ key[51],
       &out[25],
       &out[19],
       &out[9],
       &out[0]
    );
    s5(in[15] ^ key[3],
       in[16] ^ key[40],
       in[17] ^ key[46],
       in[18] ^ key[4],
       in[19] ^ key[20],
       in[20] ^ key[19],
       &out[7],
       &out[13],
       &out[24],
       &out[2]
    );
    s6(in[19] ^ key[53],
       in[20] ^ key[10],
       in[21] ^ key[47],
       in[22] ^ key[34],
       in[23] ^ key[32],
       in[24] ^ key[13],
       &out[3],
       &out[28],
       &out[10],
       &out[18]
    );
    s7(in[23] ^ key[41],
       in[24] ^ key[6],
       in[25] ^ key[17],
       in[26] ^ key[12],
       in[27] ^ key[25],
       in[28] ^ key[33],
       &out[31],
       &out[11],
       &out[21],
       &out[6]
    );
    s8(in[27] ^ key[27],
       in[28] ^ key[55],
       in[29] ^ key[54],
       in[30] ^ key[11],
       in[31] ^ key[5],
       in[0] ^ key[39],
       &out[4],
       &out[26],
       &out[14],
       &out[20]
    );
}

__device__ inline void f10(uint in[], uint key[], uint out[])
{
    s1(in[31] ^ key[35],
       in[0] ^ key[14],
       in[1] ^ key[31],
       in[2] ^ key[22],
       in[3] ^ key[44],
       in[4] ^ key[16],
       &out[8],
       &out[16],
       &out[22],
       &out[30]
    );
    s2(in[3] ^ key[30],
       in[4] ^ key[51],
       in[5] ^ key[28],
       in[6] ^ key[9],
       in[7] ^ key[43],
       in[8] ^ key[38],
       &out[12],
       &out[27],
       &out[1],
       &out[17]
    );
    s3(in[7] ^ key[29],
       in[8] ^ key[0],
       in[9] ^ key[49],
       in[10] ^ key[23],
       in[11] ^ key[8],
       in[12] ^ key[52],
       &out[23],
       &out[15],
       &out[29],
       &out[5]
    );
    s4(in[11] ^ key[21],
       in[12] ^ key[2],
       in[13] ^ key[1],
       in[14] ^ key[50],
       in[15] ^ key[42],
       in[16] ^ key[37],
       &out[25],
       &out[19],
       &out[9],
       &out[0]
    );
    s5(in[15] ^ key[48],
       in[16] ^ key[26],
       in[17] ^ key[32],
       in[18] ^ key[17],
       in[19] ^ key[6],
       in[20] ^ key[5],
       &out[7],
       &out[13],
       &out[24],
       &out[2]
    );
    s6(in[19] ^ key[39],
       in[20] ^ key[55],
       in[21] ^ key[33],
       in[22] ^ key[20],
       in[23] ^ key[18],
       in[24] ^ key[54],
       &out[3],
       &out[28],
       &out[10],
       &out[18]
    );
    s7(in[23] ^ key[27],
       in[24] ^ key[47],
       in[25] ^ key[3],
       in[26] ^ key[53],
       in[27] ^ key[11],
       in[28] ^ key[19],
       &out[31],
       &out[11],
       &out[21],
       &out[6]
    );
    s8(in[27] ^ key[13],
       in[28] ^ key[41],
       in[29] ^ key[40],
       in[30] ^ key[24],
       in[31] ^ key[46],
       in[0] ^ key[25],
       &out[4],
       &out[26],
       &out[14],
       &out[20]
    );
}

__device__ inline void f11(uint in[], uint key[], uint out[])
{
    s1(in[31] ^ key[21],
       in[0] ^ key[0],
       in[1] ^ key[42],
       in[2] ^ key[8],
       in[3] ^ key[30],
       in[4] ^ key[2],
       &out[8],
       &out[16],
       &out[22],
       &out[30]
    );
    s2(in[3] ^ key[16],
       in[4] ^ key[37],
       in[5] ^ key[14],
       in[6] ^ key[52],
       in[7] ^ key[29],
       in[8] ^ key[49],
       &out[12],
       &out[27],
       &out[1],
       &out[17]
    );
    s3(in[7] ^ key[15],
       in[8] ^ key[43],
       in[9] ^ key[35],
       in[10] ^ key[9],
       in[11] ^ key[51],
       in[12] ^ key[38],
       &out[23],
       &out[15],
       &out[29],
       &out[5]
    );
    s4(in[11] ^ key[7],
       in[12] ^ key[45],
       in[13] ^ key[44],
       in[14] ^ key[36],
       in[15] ^ key[28],
       in[16] ^ key[23],
       &out[25],
       &out[19],
       &out[9],
       &out[0]
    );
    s5(in[15] ^ key[34],
       in[16] ^ key[12],
       in[17] ^ key[18],
       in[18] ^ key[3],
       in[19] ^ key[47],
       in[20] ^ key[46],
       &out[7],
       &out[13],
       &out[24],
       &out[2]
    );
    s6(in[19] ^ key[25],
       in[20] ^ key[41],
       in[21] ^ key[19],
       in[22] ^ key[6],
       in[23] ^ key[4],
       in[24] ^ key[40],
       &out[3],
       &out[28],
       &out[10],
       &out[18]
    );
    s7(in[23] ^ key[13],
       in[24] ^ key[33],
       in[25] ^ key[48],
       in[26] ^ key[39],
       in[27] ^ key[24],
       in[28] ^ key[5],
       &out[31],
       &out[11],
       &out[21],
       &out[6]
    );
    s8(in[27] ^ key[54],
       in[28] ^ key[27],
       in[29] ^ key[26],
       in[30] ^ key[10],
       in[31] ^ key[32],
       in[0] ^ key[11],
       &out[4],
       &out[26],
       &out[14],
       &out[20]
    );
}

__device__ inline void f12(uint in[], uint key[], uint out[])
{
    s1(in[31] ^ key[7],
       in[0] ^ key[43],
       in[1] ^ key[28],
       in[2] ^ key[51],
       in[3] ^ key[16],
       in[4] ^ key[45],
       &out[8],
       &out[16],
       &out[22],
       &out[30]
    );
    s2(in[3] ^ key[2],
       in[4] ^ key[23],
       in[5] ^ key[0],
       in[6] ^ key[38],
       in[7] ^ key[15],
       in[8] ^ key[35],
       &out[12],
       &out[27],
       &out[1],
       &out[17]
    );
    s3(in[7] ^ key[1],
       in[8] ^ key[29],
       in[9] ^ key[21],
       in[10] ^ key[52],
       in[11] ^ key[37],
       in[12] ^ key[49],
       &out[23],
       &out[15],
       &out[29],
       &out[5]
    );
    s4(in[11] ^ key[50],
       in[12] ^ key[31],
       in[13] ^ key[30],
       in[14] ^ key[22],
       in[15] ^ key[14],
       in[16] ^ key[9],
       &out[25],
       &out[19],
       &out[9],
       &out[0]
    );
    s5(in[15] ^ key[20],
       in[16] ^ key[53],
       in[17] ^ key[4],
       in[18] ^ key[48],
       in[19] ^ key[33],
       in[20] ^ key[32],
       &out[7],
       &out[13],
       &out[24],
       &out[2]
    );
    s6(in[19] ^ key[11],
       in[20] ^ key[27],
       in[21] ^ key[5],
       in[22] ^ key[47],
       in[23] ^ key[17],
       in[24] ^ key[26],
       &out[3],
       &out[28],
       &out[10],
       &out[18]
    );
    s7(in[23] ^ key[54],
       in[24] ^ key[19],
       in[25] ^ key[34],
       in[26] ^ key[25],
       in[27] ^ key[10],
       in[28] ^ key[46],
       &out[31],
       &out[11],
       &out[21],
       &out[6]
    );
    s8(in[27] ^ key[40],
       in[28] ^ key[13],
       in[29] ^ key[12],
       in[30] ^ key[55],
       in[31] ^ key[18],
       in[0] ^ key[24],
       &out[4],
       &out[26],
       &out[14],
       &out[20]
    );
}

__device__ inline void f13(uint in[], uint key[], uint out[])
{
    s1(in[31] ^ key[50],
       in[0] ^ key[29],
       in[1] ^ key[14],
       in[2] ^ key[37],
       in[3] ^ key[2],
       in[4] ^ key[31],
       &out[8],
       &out[16],
       &out[22],
       &out[30]
    );
    s2(in[3] ^ key[45],
       in[4] ^ key[9],
       in[5] ^ key[43],
       in[6] ^ key[49],
       in[7] ^ key[1],
       in[8] ^ key[21],
       &out[12],
       &out[27],
       &out[1],
       &out[17]
    );
    s3(in[7] ^ key[44],
       in[8] ^ key[15],
       in[9] ^ key[7],
       in[10] ^ key[38],
       in[11] ^ key[23],
       in[12] ^ key[35],
       &out[23],
       &out[15],
       &out[29],
       &out[5]
    );
    s4(in[11] ^ key[36],
       in[12] ^ key[42],
       in[13] ^ key[16],
       in[14] ^ key[8],
       in[15] ^ key[0],
       in[16] ^ key[52],
       &out[25],
       &out[19],
       &out[9],
       &out[0]
    );
    s5(in[15] ^ key[6],
       in[16] ^ key[39],
       in[17] ^ key[17],
       in[18] ^ key[34],
       in[19] ^ key[19],
       in[20] ^ key[18],
       &out[7],
       &out[13],
       &out[24],
       &out[2]
    );
    s6(in[19] ^ key[24],
       in[20] ^ key[13],
       in[21] ^ key[46],
       in[22] ^ key[33],
       in[23] ^ key[3],
       in[24] ^ key[12],
       &out[3],
       &out[28],
       &out[10],
       &out[18]
    );
    s7(in[23] ^ key[40],
       in[24] ^ key[5],
       in[25] ^ key[20],
       in[26] ^ key[11],
       in[27] ^ key[55],
       in[28] ^ key[32],
       &out[31],
       &out[11],
       &out[21],
       &out[6]
    );
    s8(in[27] ^ key[26],
       in[28] ^ key[54],
       in[29] ^ key[53],
       in[30] ^ key[41],
       in[31] ^ key[4],
       in[0] ^ key[10],
       &out[4],
       &out[26],
       &out[14],
       &out[20]
    );
}

__device__ inline void f14(uint in[], uint key[], uint out[])
{
    s1(in[31] ^ key[36],
       in[0] ^ key[15],
       in[1] ^ key[0],
       in[2] ^ key[23],
       in[3] ^ key[45],
       in[4] ^ key[42],
       &out[8],
       &out[16],
       &out[22],
       &out[30]
    );
    s2(in[3] ^ key[31],
       in[4] ^ key[52],
       in[5] ^ key[29],
       in[6] ^ key[35],
       in[7] ^ key[44],
       in[8] ^ key[7],
       &out[12],
       &out[27],
       &out[1],
       &out[17]
    );
    s3(in[7] ^ key[30],
       in[8] ^ key[1],
       in[9] ^ key[50],
       in[10] ^ key[49],
       in[11] ^ key[9],
       in[12] ^ key[21],
       &out[23],
       &out[15],
       &out[29],
       &out[5]
    );
    s4(in[11] ^ key[22],
       in[12] ^ key[28],
       in[13] ^ key[2],
       in[14] ^ key[51],
       in[15] ^ key[43],
       in[16] ^ key[38],
       &out[25],
       &out[19],
       &out[9],
       &out[0]
    );
    s5(in[15] ^ key[47],
       in[16] ^ key[25],
       in[17] ^ key[3],
       in[18] ^ key[20],
       in[19] ^ key[5],
       in[20] ^ key[4],
       &out[7],
       &out[13],
       &out[24],
       &out[2]
    );
    s6(in[19] ^ key[10],
       in[20] ^ key[54],
       in[21] ^ key[32],
       in[22] ^ key[19],
       in[23] ^ key[48],
       in[24] ^ key[53],
       &out[3],
       &out[28],
       &out[10],
       &out[18]
    );
    s7(in[23] ^ key[26],
       in[24] ^ key[46],
       in[25] ^ key[6],
       in[26] ^ key[24],
       in[27] ^ key[41],
       in[28] ^ key[18],
       &out[31],
       &out[11],
       &out[21],
       &out[6]
    );
    s8(in[27] ^ key[12],
       in[28] ^ key[40],
       in[29] ^ key[39],
       in[30] ^ key[27],
       in[31] ^ key[17],
       in[0] ^ key[55],
       &out[4],
       &out[26],
       &out[14],
       &out[20]
    );
}

__device__ inline void f15(uint in[], uint key[], uint out[])
{
    s1(in[31] ^ key[22],
       in[0] ^ key[1],
       in[1] ^ key[43],
       in[2] ^ key[9],
       in[3] ^ key[31],
       in[4] ^ key[28],
       &out[8],
       &out[16],
       &out[22],
       &out[30]
    );
    s2(in[3] ^ key[42],
       in[4] ^ key[38],
       in[5] ^ key[15],
       in[6] ^ key[21],
       in[7] ^ key[30],
       in[8] ^ key[50],
       &out[12],
       &out[27],
       &out[1],
       &out[17]
    );
    s3(in[7] ^ key[16],
       in[8] ^ key[44],
       in[9] ^ key[36],
       in[10] ^ key[35],
       in[11] ^ key[52],
       in[12] ^ key[7],
       &out[23],
       &out[15],
       &out[29],
       &out[5]
    );
    s4(in[11] ^ key[8],
       in[12] ^ key[14],
       in[13] ^ key[45],
       in[14] ^ key[37],
       in[15] ^ key[29],
       in[16] ^ key[49],
       &out[25],
       &out[19],
       &out[9],
       &out[0]
    );
    s5(in[15] ^ key[33],
       in[16] ^ key[11],
       in[17] ^ key[48],
       in[18] ^ key[6],
       in[19] ^ key[46],
       in[20] ^ key[17],
       &out[7],
       &out[13],
       &out[24],
       &out[2]
    );
    s6(in[19] ^ key[55],
       in[20] ^ key[40],
       in[21] ^ key[18],
       in[22] ^ key[5],
       in[23] ^ key[34],
       in[24] ^ key[39],
       &out[3],
       &out[28],
       &out[10],
       &out[18]
    );
    s7(in[23] ^ key[12],
       in[24] ^ key[32],
       in[25] ^ key[47],
       in[26] ^ key[10],
       in[27] ^ key[27],
       in[28] ^ key[4],
       &out[31],
       &out[11],
       &out[21],
       &out[6]
    );
    s8(in[27] ^ key[53],
       in[28] ^ key[26],
       in[29] ^ key[25],
       in[30] ^ key[13],
       in[31] ^ key[3],
       in[0] ^ key[41],
       &out[4],
       &out[26],
       &out[14],
       &out[20]
    );
}

__device__ inline void f16(uint in[], uint key[], uint out[])
{
    s1(in[31] ^ key[15],
       in[0] ^ key[51],
       in[1] ^ key[36],
       in[2] ^ key[2],
       in[3] ^ key[49],
       in[4] ^ key[21],
       &out[8],
       &out[16],
       &out[22],
       &out[30]
    );
    s2(in[3] ^ key[35],
       in[4] ^ key[31],
       in[5] ^ key[8],
       in[6] ^ key[14],
       in[7] ^ key[23],
       in[8] ^ key[43],
       &out[12],
       &out[27],
       &out[1],
       &out[17]
    );
    s3(in[7] ^ key[9],
       in[8] ^ key[37],
       in[9] ^ key[29],
       in[10] ^ key[28],
       in[11] ^ key[45],
       in[12] ^ key[0],
       &out[23],
       &out[15],
       &out[29],
       &out[5]
    );
    s4(in[11] ^ key[1],
       in[12] ^ key[7],
       in[13] ^ key[38],
       in[14] ^ key[30],
       in[15] ^ key[22],
       in[16] ^ key[42],
       &out[25],
       &out[19],
       &out[9],
       &out[0]
    );
    s5(in[15] ^ key[26],
       in[16] ^ key[4],
       in[17] ^ key[41],
       in[18] ^ key[54],
       in[19] ^ key[39],
       in[20] ^ key[10],
       &out[7],
       &out[13],
       &out[24],
       &out[2]
    );
    s6(in[19] ^ key[48],
       in[20] ^ key[33],
       in[21] ^ key[11],
       in[22] ^ key[53],
       in[23] ^ key[27],
       in[24] ^ key[32],
       &out[3],
       &out[28],
       &out[10],
       &out[18]
    );
    s7(in[23] ^ key[5],
       in[24] ^ key[25],
       in[25] ^ key[40],
       in[26] ^ key[3],
       in[27] ^ key[20],
       in[28] ^ key[24],
       &out[31],
       &out[11],
       &out[21],
       &out[6]
    );
    s8(in[27] ^ key[46],
       in[28] ^ key[19],
       in[29] ^ key[18],
       in[30] ^ key[6],
       in[31] ^ key[55],
       in[0] ^ key[34],
       &out[4],
       &out[26],
       &out[14],
       &out[20]
    );
}

__device__ inline void encrypt(const uint *in, uint * key, uint *out)
{
    uint i;
    for (i = 0; i < 64; i++) {
        out[i] = in[i];
    }

    // Round 1
    f1(&out[32], key, out);
    // Round 2
    f2(out, key, &out[32]);
    // Round 3
    f3(&out[32], key, out);
    // Round 4
    f4(out, key, &out[32]);
    // Round 5
    f5(&out[32], key, out);
    // Round 6
    f6(out, key, &out[32]);
    // Round 7
    f7(&out[32], key, out);
    // Round 8
    f8(out, key, &out[32]);
    // Round 9
    f9(&out[32], key, out);
    // Round 10 
    f10(out, key, &out[32]);
    // Round 11 
    f11(&out[32], key, out);
    // Round 12 
    f12(out, key, &out[32]);
    // Round 13 
    f13(&out[32], key, out);
    // Round 14 
    f14(out, key, &out[32]);
    // Round 15 
    f15(&out[32], key, out);
    // Round 16 
    f16(out, key, &out[32]);
}

#endif
