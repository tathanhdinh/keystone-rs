#![allow(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case
)]

use keystone_sys as kss;

use crate::kss::{Arch::*, Error::*, Mode::*, OptionType::*, OptionValue::*};
use std::{convert, ops};

macro_rules! enum_association_wrapper {
    ([
        $reexport_enum:ty
        ]
    $(
        -> $asso_reexport_variant:ident = $existed_reexport_variant:ident;
        )*
    ) => {
        impl $reexport_enum {
            $(
                pub const $asso_reexport_variant: $reexport_enum = $existed_reexport_variant;
            )*
        }
    };
}

// ref: cs_enum_wrapper of capstone-rs
macro_rules! enum_wrapper {
    ([
        => $reexport_enum:ident = $ks_enum:ty
        ]
    $(
        => $reexport_variant:ident = $ks_variant:ident;
        )*
    $(
        -> $asso_reexport_variant:ident = $existed_reexport_variant:ident;
    )*) => {
        #[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
        pub enum $reexport_enum {
            $(
                $reexport_variant,
            )*
        }

        impl $reexport_enum {
            $(
                pub const $asso_reexport_variant: $reexport_enum = $existed_reexport_variant;
            )*
        }

        impl convert::From<$ks_enum> for $reexport_enum {
            fn from(other: $ks_enum) -> Self {
                match other {
                    $(
                        $ks_variant => $reexport_enum::$reexport_variant,
                    )*
                }
            }
        }

        impl convert::From<$reexport_enum> for $ks_enum {
            fn from(other: $reexport_enum) -> Self {
                match other {
                    $(
                        $reexport_enum::$reexport_variant => $ks_variant,
                    )*
                }
            }
        }
    };
}

// wrapping Error
enum_wrapper!(
    [
        => Error = kss::Error
    ]
    => Oki = KS_ERR_OK; // Sorry -\0/-
    => NoMem = KS_ERR_NOMEM;
    => Arch = KS_ERR_ARCH;
    => Handle = KS_ERR_HANDLE;
    => Mode = KS_ERR_MODE;
    => Version = KS_ERR_VERSION;
    => OptInvalid = KS_ERR_OPT_INVALID;
    => AsmExprToken = KS_ERR_ASM_EXPR_TOKEN;
    => AsmDirectiveValueRange = KS_ERR_ASM_DIRECTIVE_VALUE_RANGE;
    => AsmDirectiveId = KS_ERR_ASM_DIRECTIVE_ID;
    => AsmDirectiveToken = KS_ERR_ASM_DIRECTIVE_TOKEN;
    => AsmDirectiveStr = KS_ERR_ASM_DIRECTIVE_STR;
    => AsmDirectiveComma = KS_ERR_ASM_DIRECTIVE_COMMA;
    => AsmDirectiveRelocName = KS_ERR_ASM_DIRECTIVE_RELOC_NAME;
    => AsmDirectiveRelocToken = KS_ERR_ASM_DIRECTIVE_RELOC_TOKEN;
    => AsmDirectiveFPoint = KS_ERR_ASM_DIRECTIVE_FPOINT;
    => AsmDirectiveUnknown = KS_ERR_ASM_DIRECTIVE_UNKNOWN;
    => AsmDirectiveEqu = KS_ERR_ASM_DIRECTIVE_EQU;
    => AsmDirectiveInvalid = KS_ERR_ASM_DIRECTIVE_INVALID;
    => AsmVariantInvalid = KS_ERR_ASM_VARIANT_INVALID;
    => AsmExprBracket = KS_ERR_ASM_EXPR_BRACKET;
    => AsmSymbolModifier = KS_ERR_ASM_SYMBOL_MODIFIER;
    => AsmSymbolRedefined = KS_ERR_ASM_SYMBOL_REDEFINED;
    => AsmSymbolMissing = KS_ERR_ASM_SYMBOL_MISSING;
    => AsmRParen = KS_ERR_ASM_RPAREN;
    => AsmStatToken = KS_ERR_ASM_STAT_TOKEN;
    => AsmUnsupported = KS_ERR_ASM_UNSUPPORTED;
    => AsmMacroToken = KS_ERR_ASM_MACRO_TOKEN;
    => AsmMacroParen = KS_ERR_ASM_MACRO_PAREN;
    => AsmMacroEqu = KS_ERR_ASM_MACRO_EQU;
    => AsmMacroArgs = KS_ERR_ASM_MACRO_ARGS;
    => AsmMacroLevelsExceed = KS_ERR_ASM_MACRO_LEVELS_EXCEED;
    => AsmMacroStr = KS_ERR_ASM_MACRO_STR;
    => AsmMacroInvalid = KS_ERR_ASM_MACRO_INVALID;
    => AsmEscBackslash = KS_ERR_ASM_ESC_BACKSLASH;
    => AsmEscOctal = KS_ERR_ASM_ESC_OCTAL;
    => AsmEscSequence = KS_ERR_ASM_ESC_SEQUENCE;
    => AsmEscStr = KS_ERR_ASM_ESC_STR;
    => AsmTokenInvalid = KS_ERR_ASM_TOKEN_INVALID;
    => AsmInsnUnsupported = KS_ERR_ASM_INSN_UNSUPPORTED;
    => AsmFixupInvalid = KS_ERR_ASM_FIXUP_INVALID;
    => AsmLabelInvalid = KS_ERR_ASM_LABEL_INVALID;
    => AsmFragmentInvalid = KS_ERR_ASM_FRAGMENT_INVALID;
    => AsmInvalidOperand = KS_ERR_ASM_INVALIDOPERAND;
    => AsmMissingFeature = KS_ERR_ASM_MISSINGFEATURE;
    => AsmMnemonicFail = KS_ERR_ASM_MNEMONICFAIL;
);

// wrapping OptionType
enum_wrapper!(
    [
        => OptionType = kss::OptionType
    ]
    => Syntax = KS_OPT_SYNTAX;
    => SymbolResolver = KS_OPT_SYM_RESOLVER;
);

enum_wrapper!(
    [
        => OptionValue = kss::OptionValue
    ]
    => SyntaxIntel = KS_OPT_SYNTAX_INTEL;
    => SyntaxAtt = KS_OPT_SYNTAX_ATT;
    => SyntaxNasm = KS_OPT_SYNTAX_NASM;
    => SyntaxMasm = KS_OPT_SYNTAX_MASM;
    => SyntaxGas = KS_OPT_SYNTAX_GAS;
    => SyntaxRadix16 = KS_OPT_SYNTAX_RADIX16;
);

// wrapping Arch
enum_wrapper!(
    [
        => Arch = kss::Arch
    ]
    => Arm = KS_ARCH_ARM;
    => Arm64 = KS_ARCH_ARM64;
    => Mips = KS_ARCH_MIPS;
    => X86 = KS_ARCH_X86;
    => Ppc= KS_ARCH_PPC;
    => Sparc = KS_ARCH_SPARC;
    => SystemZ = KS_ARCH_SYSTEMZ;
    => Hexagon = KS_ARCH_HEXAGON;
    => Evm = KS_ARCH_EVM;
    => Max = KS_ARCH_MAX;
);

// wrapping Mode
enum_wrapper!(
    [
        => Mode = kss::Mode
    ]
    => LittleEndian = KS_MODE_LITTLE_ENDIAN;
    => BigEndian = KS_MODE_BIG_ENDIAN;
    => Arm = KS_MODE_ARM;
    => Thumb = KS_MODE_THUMB;
    => V8 = KS_MODE_V8;
    => Mips3 = KS_MODE_MIPS3;
    => Mips32 = KS_MODE_MIPS32;
    => Mips64 = KS_MODE_MIPS64;
    => Bit16 = KS_MODE_16;
);

use self::Mode::{Mips32, Mips64, Thumb, V8};
enum_association_wrapper!(
    [
        Mode
    ]
    -> Micro = Thumb;
    -> Mips32R6 = V8;
    -> Bit32 = Mips32;
    -> Bit64 = Mips64;
    -> Ppc64 = Mips64;
    -> Qpx = Thumb;
    -> Sparc32 = Mips32;
    -> Sparc64 = Mips64;
    -> V8 = Thumb;
);

macro_rules! implement_bit_operators {
    ($reexported_enum:ty, $sys_enum:tt) => {
        impl ops::BitOr<$reexported_enum> for $reexported_enum {
            type Output = Self;
            #[inline]
            fn bitor(self, other: Self) -> Self {
                let s: u32 = From::from(kss::$sys_enum::from(self));
                let o: u32 = From::from(kss::$sys_enum::from(other));
                From::from(kss::$sys_enum::from(s | o))
            }
        }

        impl ops::BitOrAssign<$reexported_enum> for $reexported_enum {
            #[inline]
            fn bitor_assign(&mut self, other: Self) {
                let s: u32 = From::from(kss::$sys_enum::from(*self));
                let o: u32 = From::from(kss::$sys_enum::from(other));
                *self = From::from(kss::$sys_enum::from(s | o));
            }
        }

        impl ops::BitAnd<$reexported_enum> for $reexported_enum {
            type Output = Self;
            #[inline]
            fn bitand(self, other: Self) -> Self {
                let s: u32 = From::from(kss::$sys_enum::from(self));
                let o: u32 = From::from(kss::$sys_enum::from(other));
                From::from(kss::$sys_enum::from(s & o))
            }
        }

        impl ops::BitAndAssign<$reexported_enum> for $reexported_enum {
            #[inline]
            fn bitand_assign(&mut self, other: Self) {
                let s: u32 = From::from(kss::$sys_enum::from(*self));
                let o: u32 = From::from(kss::$sys_enum::from(other));
                *self = From::from(kss::$sys_enum::from(s & o));
            }
        }
    };
}

implement_bit_operators!(Mode, Mode);
implement_bit_operators!(OptionValue, OptionValue);
