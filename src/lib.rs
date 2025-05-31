#![feature(portable_simd)]
#![warn(unsafe_op_in_unsafe_fn)]

use std::alloc::{alloc, dealloc, Layout};
use std::arch::asm;
use std::convert::TryFrom;
use std::fmt::Display;
use std::ops::{Index, IndexMut};
use std::simd;
use std::num::{ParseFloatError, ParseIntError};
use std::simd::num::SimdInt;
use std::str::{self, Utf8Error};
use std::string::FromUtf8Error;
use std::{usize, fmt};
use std::fmt::Debug;
use std::hash::Hash;

use std::arch::x86_64;

use ezcbor::cbor::{byteslice_from_cbor, byteslice_to_cbor, Cbor, CborError};
// use eznoise::CipherState;
use fnv::{FnvBuildHasher, FnvHashMap, FnvHashSet};
// use aes_gcm::aead;
// use sha2::{Sha256, Digest};

// use crate::auth::AuthenticationError;
// use crate::db_structure::Value;
// use crate::server_networking::Database;


pub const INSTRUCTION_BUFFER: usize = 1024;
pub const DATA_BUFFER: usize = 1_048;//_576; // 1 mb
pub const MAX_DATA_LEN: usize = u32::MAX as usize;
pub const NULLPTR: Pointer = Pointer{pointer: usize::MAX};


#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Eq, Ord)]
pub enum ErrorTag {
    Utf8,
    Io,
    Instruction,
    Confirmation,
    Authentication,
    Crypto,
    ParseInt,
    ParseFloat,
    ParseResponse,
    ParseUser,
    OversizedData,
    Decompression,
    Query,
    Debug,
    NoMoreBufferSpace,
    Unimplemented,
    Serialization,
    Deserialization,
    Structure,
}

#[derive(Clone, Debug, PartialEq, PartialOrd, Eq, Ord)]
pub struct EzError {
    pub tag: ErrorTag,
    pub text: String,
}

impl EzError {
    pub fn to_binary(&self) -> Vec<u8> {
        let mut binary = Vec::new();
        match self.tag {
            ErrorTag::Utf8 => binary.extend_from_slice(ksf("Utf8").raw()),
            ErrorTag::Io => binary.extend_from_slice(ksf("Io").raw()),
            ErrorTag::Instruction => binary.extend_from_slice(ksf("Instruction").raw()),
            ErrorTag::Confirmation => binary.extend_from_slice(ksf("Confirmation").raw()),
            ErrorTag::Authentication => binary.extend_from_slice(ksf("Authentication").raw()),
            ErrorTag::Crypto => binary.extend_from_slice(ksf("Crypto").raw()),
            ErrorTag::ParseInt => binary.extend_from_slice(ksf("ParseInt").raw()),
            ErrorTag::ParseFloat => binary.extend_from_slice(ksf("ParseFloat").raw()),
            ErrorTag::ParseResponse => binary.extend_from_slice(ksf("ParseResponse").raw()),
            ErrorTag::ParseUser => binary.extend_from_slice(ksf("ParseUser").raw()),
            ErrorTag::OversizedData => binary.extend_from_slice(ksf("OversizedData").raw()),
            ErrorTag::Decompression => binary.extend_from_slice(ksf("Decompression").raw()),
            ErrorTag::Query => binary.extend_from_slice(ksf("Query").raw()),
            ErrorTag::Debug => binary.extend_from_slice(ksf("Debug").raw()),
            ErrorTag::NoMoreBufferSpace => binary.extend_from_slice(ksf("NoMoreBufferSpace").raw()),
            ErrorTag::Unimplemented => binary.extend_from_slice(ksf("Unimplemented").raw()),
            ErrorTag::Serialization => binary.extend_from_slice(ksf("Serialization").raw()),
            ErrorTag::Deserialization => binary.extend_from_slice(ksf("Deserialization").raw()),
            ErrorTag::Structure => binary.extend_from_slice(ksf("Structure").raw()),
        };

        binary.extend_from_slice(&self.text.len().to_le_bytes());
        binary.extend_from_slice(self.text.as_bytes());

        binary
    }

    pub fn from_binary(binary: &[u8]) -> Result<EzError, EzError> {
        let tag = KeyString::try_from(&binary[0..64])?;
        let tag = match tag.as_str() {
            "Utf8" => ErrorTag::Utf8,
            "Io" => ErrorTag::Io,
            "Instruction" => ErrorTag::Instruction,
            "Confirmation" => ErrorTag::Confirmation,
            "Authentication" => ErrorTag::Authentication,
            "Crypto" => ErrorTag::Crypto,
            "ParseInt" => ErrorTag::ParseInt,
            "ParseFloat" => ErrorTag::ParseFloat,
            "ParseResponse" => ErrorTag::ParseResponse,
            "ParseUser" => ErrorTag::ParseUser,
            "OversizedData" => ErrorTag::OversizedData,
            "Decompression" => ErrorTag::Decompression,
            "Query" => ErrorTag::Query,
            "Debug" => ErrorTag::Debug,
            "NoMoreBufferSpace" => ErrorTag::NoMoreBufferSpace,
            "Unimplemented" => ErrorTag::Unimplemented,
            "Serialization" => ErrorTag::Serialization,
            "Deserialization" => ErrorTag::Deserialization,
            "Structure" => ErrorTag::Structure,
            other => return Err(EzError{tag: ErrorTag::Unimplemented, text: format!("No error type called '{}'", other)})
        };
        let len = u64_from_le_slice(&binary[64..72]) as usize;
        let text = String::from_utf8(binary[72..72+len].to_vec())?;

        Ok(EzError{tag, text})
    }
}

impl Display for EzError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut disp = "Tag: ".to_owned();
        match self.tag {
            ErrorTag::Utf8 => disp.push_str("Utf8"),
            ErrorTag::Io => disp.push_str("Io"),
            ErrorTag::Instruction => disp.push_str("Instruction"),
            ErrorTag::Confirmation => disp.push_str("Confirmation"),
            ErrorTag::Authentication => disp.push_str("Authentication"),
            ErrorTag::Crypto => disp.push_str("Crypto"),
            ErrorTag::ParseInt => disp.push_str("ParseInt"),
            ErrorTag::ParseFloat => disp.push_str("ParseFloat"),
            ErrorTag::ParseResponse => disp.push_str("ParseResponse"),
            ErrorTag::ParseUser => disp.push_str("ParseUser"),
            ErrorTag::OversizedData => disp.push_str("OversizedData"),
            ErrorTag::Decompression => disp.push_str("Decompression"),
            ErrorTag::Query => disp.push_str("Query"),
            ErrorTag::Debug => disp.push_str("Debug"),
            ErrorTag::NoMoreBufferSpace => disp.push_str("NoMoreBufferSpace"),
            ErrorTag::Unimplemented => disp.push_str("Unimplemented"),
            ErrorTag::Serialization => disp.push_str("Serialization"),
            ErrorTag::Deserialization => disp.push_str("Deserialization"),
            ErrorTag::Structure => disp.push_str("Structure"),
        };
        disp.push_str("\nError text:\n");
        disp.push_str(&self.text);
        disp.push('\n');
        write!(f, "{}", disp)
    }
}

impl From<std::io::Error> for EzError {
    fn from(e: std::io::Error) -> Self {
        let tag = ErrorTag::Io;
        let text = e.to_string();
        EzError { tag, text }
    }
}

impl From<Utf8Error> for EzError {
    fn from(e: Utf8Error) -> Self {
        let tag = ErrorTag::Utf8;
        let text = e.to_string();
        EzError { tag, text }
    }
}

impl From<ParseIntError> for EzError {
    fn from(e: ParseIntError) -> Self {
        let tag = ErrorTag::ParseInt;
        let text = e.to_string();
        EzError { tag, text }
    }
}

impl From<ParseFloatError> for EzError {
    fn from(e: ParseFloatError) -> Self {
        let tag = ErrorTag::ParseFloat;
        let text = e.to_string();
        EzError { tag, text }
    }
}

impl From<CborError> for EzError {
    fn from(e: CborError) -> Self {
        let tag = ErrorTag::Deserialization;
        let text = match e {
            CborError::IllFormed(x) => x,
            CborError::Unexpected(x) => x,
        };
        EzError{tag, text}
    }
}

impl From<FromUtf8Error> for EzError {
    fn from(e: FromUtf8Error) -> Self {
        let tag = ErrorTag::Utf8;
        let text = e.to_string();
        EzError { tag, text }
    }
}


#[repr(align(8))]
#[derive(Clone, Copy, Hash, PartialEq)]
pub struct KeyString {
    inner: [u8;64],
}


impl fmt::Debug for KeyString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        
        f.debug_struct("KeyString").field("inner", &self.as_str()).finish()
    }
}

impl fmt::Display for KeyString {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let text = std::str::from_utf8(&self.inner).expect(&format!("A KeyString should always be valid utf8.\nThe KeyString that was just attempted to Display was:\n{:x?}", self.inner));
        write!(f, "{}", text)
    }   
}

impl Default for KeyString {
    fn default() -> Self {
        Self { inner: [0;64] }
    }
}

/// Turns a &str into a KeyString. If the &str has more than 64 bytes, the last bytes will be cut.
impl From<&str> for KeyString {
    fn from(s: &str) -> Self {

        let mut inner = [0u8;64];

        let mut min = std::cmp::min(s.len(), 64);
        inner[0..min].copy_from_slice(&s.as_bytes()[0..min]);

        loop {
            if min == 0 {break}
            match std::str::from_utf8(&inner[0..min]) {
                Ok(_) => break,
                Err(_) => min -= 1,
            }
        }

        KeyString {
            inner
        }
    }
}

impl TryFrom<&[u8]> for KeyString {
    type Error = EzError;

    fn try_from(s: &[u8]) -> Result<Self, Self::Error> {
        let mut inner = [0u8;64];

        let min = std::cmp::min(s.len(), 64);
        inner[0..min].copy_from_slice(&s[0..min]);

        match std::str::from_utf8(&inner) {
            Ok(_) => {
                Ok(KeyString {inner})
            },
            Err(e) => Err(EzError{tag: ErrorTag::Utf8, text: e.to_string()})
        }
    }
}

impl Eq for KeyString {}

impl Ord for KeyString {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_str().cmp(other.as_str())
    }
}

impl PartialOrd for KeyString {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.as_str().cmp(other.as_str()))
    }
}

impl Cbor for KeyString {
    fn to_cbor_bytes(&self) -> Vec<u8> {
        byteslice_to_cbor(self.as_bytes())
    }

    fn from_cbor_bytes(bytes: &[u8]) -> Result<(Self, usize), ezcbor::cbor::CborError>
        where 
            Self: Sized 
    {
        let (bytes, bytes_read) = byteslice_from_cbor(bytes)?;
        let text = match String::from_utf8(bytes) {
            Ok(t) => t,
            Err(_) => return Err(CborError::Unexpected(format!("Error originated in KeyString implementation")))
        };
        Ok((KeyString::from(text.as_str()), bytes_read))
    }
}

impl KeyString {

    pub fn new() -> Self {
        KeyString {
            inner: [0u8; 64]
        }
    }

    pub fn len(&self) -> usize {
        let mut output = 0;
        for byte in self.inner {
            match byte {
                0 => break,
                _ => output += 1,
            }
        }
        output
    }

    pub fn push(&mut self, s: &str) -> usize {

        let start = self.as_str().len();
        let len = std::cmp::min(s.len(), 64-start);

        self.inner[start..start+len].copy_from_slice(&s.as_bytes()[0..len]);

        len
    }

    pub fn as_str(&self) -> &str {
        // This is safe since an enforced invariant of KeyString is that it is utf8
        unsafe { std::str::from_utf8_unchecked(&self.inner[0..self.len()]) }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.inner[0..self.len()]
    }

    pub fn raw(&self) -> &[u8] {
        &self.inner
    }

    /// These functions may panic and should only be called if you are certain that the KeyString contains a valid number
    pub fn to_i32(&self) -> i32 {
        self.as_str().parse::<i32>().unwrap()
    }

    /// These functions may panic and should only be called if you are certain that the KeyString contains a valid number
    pub fn to_f32(&self) -> f32 {
        self.as_str().parse::<f32>().unwrap()
    }

    pub fn to_i32_checked(&self) -> Result<i32, ParseIntError> {
        self.as_str().parse::<i32>()
    }

    pub fn to_f32_checked(&self) -> Result<f32, ParseFloatError> {
        self.as_str().parse::<f32>()
    }

}

#[inline]
pub fn ksf(s: &str) -> KeyString {
    KeyString::from(s)
}

/// Gets the current time as seconds since UNIX_EPOCH. Used for logging, mostly.
#[inline]
pub fn get_current_time() -> u64 {
    
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Gets the current time as seconds since UNIX_EPOCH. Used for logging, mostly.
#[inline]
pub fn get_precise_time() -> u128 {

    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_micros()
}

/// Count cycles for benchmarking
#[inline(always)]
pub fn rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        asm!("rdtsc", out("eax") lo, out("edx") hi, options(nostack, preserves_flags));
    }
    ((hi as u64) << 32) | (lo as u64)
}

/// Incredibly convoluted way to print the current date. Copied from StackOverflow
pub fn time_print(s: &str, cycles: u64) {
    
    let num = cycles.to_string()
    .as_bytes()
    .rchunks(3)
    .rev()
    .map(std::str::from_utf8)
    .collect::<Result<Vec<&str>, _>>()
    .unwrap()
    .join(".");  // separator

    let millis = (cycles/1_700_000).to_string()
    .as_bytes()
    .rchunks(3)
    .rev()
    .map(std::str::from_utf8)
    .collect::<Result<Vec<&str>, _>>()
    .unwrap()
    .join(".");  // separator

    println!("{}: {}\n\tApproximately {} milliseconds", s, num, millis);
}


/// Removes the trailing 0 bytes from a str created from a byte buffer
pub fn bytes_to_str(bytes: &[u8]) -> Result<&str, Utf8Error> {
    
    if bytes.is_empty() {
        return Ok("")
    }

    let mut index: usize = 0;
    let len = bytes.len();
    let mut start: usize = 0;
    
    while index < len {
        if bytes[index] != 0 {
            break
        }
        index += 1;
        start += 1;
    }


    if start >= bytes.len()-1 {
        return Ok("")
    }

    let mut stop: usize = start;
    while index < len {
        if bytes[index] == 0 {
            break
        }
        index += 1;
        stop += 1;
    }

    str::from_utf8(&bytes[start..stop])
}

/// Encodes a byte slice as a hexadecimal String
pub fn encode_hex(bytes: &[u8]) -> String {
    
    let mut s = String::new();
    for &b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Decodes a hexadecimal String as a byte slice.
pub fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {

    // println!("s.len(): {}", s.len());
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}



/// Creates a i32 from a &[u8] of length 4. Panics if len is different than 4. 
#[inline]
pub fn i32_from_le_slice(slice: &[u8]) -> i32 {

    assert!(slice.len() == 4);
    let l: [u8;4] = [slice[0], slice[1], slice[2], slice[3]];
    i32::from_le_bytes(l)
}

/// Creates a u32 from a &[u8] of length 4. Panics if len is different than 4.
#[inline]
pub fn u32_from_le_slice(slice: &[u8]) -> u32 {

    assert!(slice.len() == 4);
    let l: [u8;4] = [slice[0], slice[1], slice[2], slice[3]];
    u32::from_le_bytes(l)
}

/// Creates a u64 from a &[u8] of length 8. Panics if len is different than 8.
#[inline]
pub fn u64_from_le_slice(slice: &[u8]) -> u64 {

    assert!(slice.len() == 8);
    let l: [u8;8] = [ slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7] ];
    u64::from_le_bytes(l)
}

/// Creates a u32 from a &[u8] of length 4. Panics if len is different than 4.
#[inline]
pub fn f32_from_le_slice(slice: &[u8]) -> f32 {   

    assert!(slice.len() == 4);
    let l: [u8;4] = [slice[0], slice[1], slice[2], slice[3]];
    f32::from_le_bytes(l)
}

/// Creates a usize from a &[u8] of length 8. Panics if len is different than 8.
#[inline]
pub fn usize_from_le_slice(slice: &[u8]) -> usize {   

    assert!(slice.len() == 8);
    let l: [u8;8] = [slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7]];
    usize::from_le_bytes(l)
}



#[inline]
pub fn read_i32(slice: &[u8], offset: usize) -> i32 {
    if offset > slice.len() - 4 {
        panic!("Trying to read out of bounds memory")
    }
    unsafe { *(slice[offset..offset+4].as_ptr() as *const i32) }
}

#[inline]
pub fn read_u64(slice: &[u8], offset: usize) -> u64 {
    if offset > slice.len() - 8 {
        panic!("Trying to read out of bounds memory")
    }
    unsafe { *(slice[offset..offset+8].as_ptr() as *const u64) }
}

#[inline]
pub fn read_f32(slice: &[u8], offset: usize) -> f32 {
    if offset > slice.len() - 4 {
        panic!("Trying to read out of bounds memory")
    }
    unsafe { *(slice[offset..offset+4].as_ptr() as *const f32) }
}

#[inline]
pub fn read_keystring(slice: &[u8], offset: usize) -> KeyString {
    if offset > slice.len() - 64 {
        panic!("Trying to read out of bounds memory")
    }
    unsafe { *(slice[offset..offset+64].as_ptr() as *const KeyString) }
}

#[inline]
pub fn write_i32(slice: &mut [u8], offset: usize, value: i32) {
    if offset > slice.len() - 4 {
        panic!("Trying to write out of bounds memory")
    }
    unsafe { ((slice[offset..offset+4]).as_mut_ptr() as *mut i32).write(value) }
}

#[inline]
pub fn write_u64(slice: &mut [u8], offset: usize, value: u64) {
    if offset > slice.len() - 8 {
        panic!("Trying to write out of bounds memory")
    }
    unsafe { ((slice[offset..offset+8]).as_mut_ptr() as *mut u64).write(value) }
}

#[inline]
pub fn write_f32(slice: &mut [u8], offset: usize, value: f32) {
    if offset > slice.len() - 4 {
        panic!("Trying to write out of bounds memory")
    }
    unsafe { ((slice[offset..offset+4]).as_mut_ptr() as *mut f32).write(value) }
}

#[inline]
pub fn write_keystring(slice: &mut [u8], offset: usize, value: KeyString) {
    if offset > slice.len() - 64 {
        panic!("Trying to write out of bounds memory")
    }
    unsafe { ((slice[offset..offset+64]).as_mut_ptr() as *mut KeyString).write(value) }

}


#[inline]
pub fn print_sep_list<T>(list: &[T], sep: &str) -> String 
where T: Display  {

    let mut printer = String::with_capacity(64*list.len());
    for item in list {
        printer.push_str(&item.to_string());
        printer.push_str(sep);
    }
    for _ in 0..sep.len() {
        printer.pop();
    }

    printer
}

#[inline]
pub fn sum_i32_slice(slice: &[i32]) -> i32 {


    let mut suma = simd::i32x4::splat(0);
    let mut sumb = simd::i32x4::splat(0);
    let mut sumc = simd::i32x4::splat(0);
    let mut sumd = simd::i32x4::splat(0);
    let mut i = 0;
    while i + 15 < slice.len() {
        suma = suma.saturating_add(simd::i32x4::from_slice(&slice[i..i+4]));
        sumb = sumb.saturating_add(simd::i32x4::from_slice(&slice[i+4..i+8]));
        sumc = sumc.saturating_add(simd::i32x4::from_slice(&slice[i+8..i+12]));
        sumd = sumd.saturating_add(simd::i32x4::from_slice(&slice[i+12..i+16]));
        i += 16;
    }

    let suma = suma.as_array().iter().fold(0, |acc: i32, x| acc.saturating_add(*x));
    let sumb = sumb.as_array().iter().fold(0, |acc: i32, x| acc.saturating_add(*x));
    let sumc = sumc.as_array().iter().fold(0, |acc: i32, x| acc.saturating_add(*x));
    let sumd = sumd.as_array().iter().fold(0, |acc: i32, x| acc.saturating_add(*x));

    let mut sum = suma.saturating_add(sumb).saturating_add(sumc).saturating_add(sumd);
    while i < slice.len() {
        sum = sum.saturating_add(slice[i]);
        i += 1;
    }

    sum
}

#[inline]
pub fn sum_f32_slice(slice: &[f32]) -> f32 {

    let mut suma = simd::f32x4::splat(0.0);
    let mut sumb = simd::f32x4::splat(0.0);
    let mut sumc = simd::f32x4::splat(0.0);
    let mut sumd = simd::f32x4::splat(0.0);
    let mut i = 0;
    while i + 15 < slice.len() {
        suma = suma + simd::f32x4::from_slice(&slice[i..i+4]);
        sumb = sumb + simd::f32x4::from_slice(&slice[i+4..i+8]);
        sumc = sumc + simd::f32x4::from_slice(&slice[i+8..i+12]);
        sumd = sumd + simd::f32x4::from_slice(&slice[i+12..i+16]);
        i += 16;
    }

    // let suma = suma.as_array().iter().fold(0.0, |acc: f32, x| acc + *x);
    // let sumb = sumb.as_array().iter().fold(0.0, |acc: f32, x| acc + *x);
    // let sumc = sumc.as_array().iter().fold(0.0, |acc: f32, x| acc + *x);
    // let sumd = sumd.as_array().iter().fold(0.0, |acc: f32, x| acc + *x);
    let suma = suma[0] + suma[1] + suma[2] + suma[3];
    let sumb = sumb[0] + sumb[1] + sumb[2] + sumb[3];
    let sumc = sumc[0] + sumc[1] + sumc[2] + sumc[3];
    let sumd = sumd[0] + sumd[1] + sumd[2] + sumd[3];

    let mut sum = suma + sumb + sumc + sumd;
    while i < slice.len() {
        sum = sum + slice[i];
        i += 1;
    }

    sum
}

pub unsafe fn raw_sum_f32_slice(slice: &[f32]) -> f32 {

    unsafe {
        let mut suma = x86_64::_mm_setzero_ps();
        let mut sumb = x86_64::_mm_setzero_ps();
        let mut sumc = x86_64::_mm_setzero_ps();
        let mut sumd = x86_64::_mm_setzero_ps();
        let mut i = 0;
        while i + 15 < slice.len() {
            suma = x86_64::_mm_add_ps(suma, x86_64::_mm_load_ps(slice[i..i+4].as_ptr()));
            sumb = x86_64::_mm_add_ps(sumb, x86_64::_mm_load_ps(slice[i+4..i+8].as_ptr()));
            sumc = x86_64::_mm_add_ps(sumc, x86_64::_mm_load_ps(slice[i+8..i+12].as_ptr()));
            sumd = x86_64::_mm_add_ps(sumd, x86_64::_mm_load_ps(slice[i+12..i+16].as_ptr()));
            i += 16;
        }

        let mut pa = [0f32;4];
        let mut pb = [0f32;4];
        let mut pc = [0f32;4];
        let mut pd = [0f32;4];

        x86_64::_mm_store_ps(pa.as_mut_ptr(), suma);
        x86_64::_mm_store_ps(pb.as_mut_ptr(), sumb);
        x86_64::_mm_store_ps(pc.as_mut_ptr(), sumc);
        x86_64::_mm_store_ps(pd.as_mut_ptr(), sumd);
        let suma = pa.iter().fold(0.0, |acc: f32, x| acc + *x);
        let sumb = pb.iter().fold(0.0, |acc: f32, x| acc + *x);
        let sumc = pc.iter().fold(0.0, |acc: f32, x| acc + *x);
        let sumd = pd.iter().fold(0.0, |acc: f32, x| acc + *x);
        
        
        let mut sum = suma + sumb + sumc + sumd;
        while i < slice.len() {
            sum = sum + slice[i];
            i += 1;
        }
        
        sum 
    }
}

#[inline]
pub fn mean_i32_slice(slice: &[i32]) -> f32 {

    let mut suma = simd::f32x4::splat(0.0);
    let mut sumb = simd::f32x4::splat(0.0);
    let mut sumc = simd::f32x4::splat(0.0);
    let mut sumd = simd::f32x4::splat(0.0);
    let mut i = 0;
    while i + 15 < slice.len() {
        suma = suma + simd::i32x4::from_slice(&slice[i..i+4]).cast();
        sumb = sumb + simd::i32x4::from_slice(&slice[i+4..i+8]).cast();
        sumc = sumc + simd::i32x4::from_slice(&slice[i+8..i+12]).cast();
        sumd = sumd + simd::i32x4::from_slice(&slice[i+12..i+16]).cast();
        i += 16;
    }

    let suma = suma.as_array().iter().fold(0.0, |acc: f32, x| acc + *x);
    let sumb = sumb.as_array().iter().fold(0.0, |acc: f32, x| acc + *x);
    let sumc = sumc.as_array().iter().fold(0.0, |acc: f32, x| acc + *x);
    let sumd = sumd.as_array().iter().fold(0.0, |acc: f32, x| acc + *x);

    let mut sum = suma + sumb + sumc + sumd;
    while i < slice.len() {
        sum = sum + slice[i] as f32;
        i += 1;
    }

    sum / slice.len() as f32
}

#[inline]
pub fn mean_f32_slice(slice: &[f32]) -> f32 {

    sum_f32_slice(slice) / (slice.len() as f32)
}

#[inline]
pub fn mode_i32_slice(slice: &[i32]) -> i32 {


    let mut map = FnvHashMap::default();
    for item in slice {
        map
        .entry(item)
        .and_modify(|n| *n += 1)
        .or_insert(1);
    }

    let mut max = 0;
    let mut result = 0;
    for (key, value) in map {
        if value > max {
            max = value;
            result = key.clone();
        }
    }
    result
}


#[inline]
pub fn mode_string_slice(slice: &[KeyString]) -> KeyString {


    let mut map = FnvHashMap::default();
    for item in slice {
        map
        .entry(item)
        .and_modify(|n| *n += 1)
        .or_insert(1);
    }

    let mut max = 0;
    let mut result = KeyString::new();
    for (key, value) in map {
        if value > max {
            max = value;
            result = *key;
        }
    }
    result
}


#[inline]
pub fn stdev_i32_slice(slice: &[i32]) -> f32 {

    let mean = mean_i32_slice(slice);

    let mut variancea = simd::f32x4::splat(0.0);
    let mut varianceb = simd::f32x4::splat(0.0);
    let mut variancec = simd::f32x4::splat(0.0);
    let mut varianced = simd::f32x4::splat(0.0);

    let mut i = 0;
    while i+15 < slice.len() {
        let mut updatea: simd::f32x4 = simd::i32x4::from_slice(&slice[i..i+4]).cast();
        let mut updateb: simd::f32x4 = simd::i32x4::from_slice(&slice[i+4..i+8]).cast();
        let mut updatec: simd::f32x4 = simd::i32x4::from_slice(&slice[i+8..i+12]).cast();
        let mut updated: simd::f32x4 = simd::i32x4::from_slice(&slice[i+12..i+16]).cast();

        updatea = updatea - simd::f32x4::splat(mean);
        updateb = updateb - simd::f32x4::splat(mean);
        updatec = updatec - simd::f32x4::splat(mean);
        updated = updated - simd::f32x4::splat(mean);

        variancea = updatea * updatea;
        varianceb = updateb * updateb;
        variancec = updatec * updatec;
        varianced = updated * updated;

        i += 16;
    }

    let mut variance = variancea.as_array().iter().fold(0.0, |acc, x| acc + x);
    variance += varianceb.as_array().iter().fold(0.0, |acc, x| acc + x);
    variance += variancec.as_array().iter().fold(0.0, |acc, x| acc + x);
    variance += varianced.as_array().iter().fold(0.0, |acc, x| acc + x);

    while i < slice.len() {
        variance += (slice[i] as f32 - mean) * (slice[i] as f32 - mean);
        i += 1;
    }

    (variance/slice.len() as f32).sqrt()

}

#[inline]
pub fn stdev_f32_slice(slice: &[f32]) -> f32 {

    let mean = mean_f32_slice(slice);

    let mut variancea = simd::f32x4::splat(0.0);
    let mut varianceb = simd::f32x4::splat(0.0);
    let mut variancec = simd::f32x4::splat(0.0);
    let mut varianced = simd::f32x4::splat(0.0);

    let mut i = 0;
    while i+15 < slice.len() {
        let mut updatea: simd::f32x4 = simd::f32x4::from_slice(&slice[i..i+4]);
        let mut updateb: simd::f32x4 = simd::f32x4::from_slice(&slice[i+4..i+8]);
        let mut updatec: simd::f32x4 = simd::f32x4::from_slice(&slice[i+8..i+12]);
        let mut updated: simd::f32x4 = simd::f32x4::from_slice(&slice[i+12..i+16]);

        updatea = updatea - simd::f32x4::splat(mean);
        updateb = updateb - simd::f32x4::splat(mean);
        updatec = updatec - simd::f32x4::splat(mean);
        updated = updated - simd::f32x4::splat(mean);

        variancea = updatea * updatea;
        varianceb = updateb * updateb;
        variancec = updatec * updatec;
        varianced = updated * updated;

        i += 16;
    }

    let mut variance = variancea.as_array().iter().fold(0.0, |acc, x| acc + x);
    variance += varianceb.as_array().iter().fold(0.0, |acc, x| acc + x);
    variance += variancec.as_array().iter().fold(0.0, |acc, x| acc + x);
    variance += varianced.as_array().iter().fold(0.0, |acc, x| acc + x);

    while i < slice.len() {
        variance += (slice[i] - mean) * (slice[i] - mean);
        i += 1;
    }

    (variance/slice.len() as f32).sqrt()
}



#[inline]
fn partition<T: Copy + PartialOrd>(data: &[T]) -> (Vec<T>, T, Vec<T>) {

    let (pivot_slice, tail) = data.split_at(1);
    let pivot = pivot_slice[0];

    let mut left = Vec::new();
    let mut right = Vec::new();
    for item in tail.iter() {
        if *item < pivot {
            left.push(*item);
        } else {
            right.push(*item);
        }
    }

    (left, pivot, right)
}

#[inline]
fn select<T: Copy + PartialOrd>(data: &[T], k: usize) -> T {


    let (left, pivot, right) = partition(data);

    let pivot_idx = left.len();

    match pivot_idx.cmp(&k) {
        std::cmp::Ordering::Equal => pivot,
        std::cmp::Ordering::Greater => select(&left, k),
        std::cmp::Ordering::Less => select(&right, k - (pivot_idx + 1)),
    }
}

#[inline]
pub fn median_i32_slice(data: &[i32]) -> f32 {

    match data.len() {
        even if even % 2 == 0 => {
            let fst_med = select(data, (even / 2) - 1);
            let snd_med = select(data, even / 2);

            (fst_med + snd_med) as f32 / 2.0
        },
        odd => select(data, odd / 2) as f32
    }
}

#[inline]
pub fn median_f32_slice(data: &[f32]) -> f32 {


    match data.len() {
        even if even % 2 == 0 => {
            let fst_med = select(data, (even / 2) - 1);
            let snd_med = select(data, even / 2);

            (fst_med + snd_med) / 2.0
        },
        odd => select(data, odd / 2)
    }
}

#[inline]
pub fn bytes_from_strings(strings: &[&str]) -> Vec<u8> {

    let mut v = Vec::with_capacity(strings.len()*64);
    for string in strings {
        v.extend_from_slice(KeyString::from(*string).raw());
    }

    v
}


#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Pointer {
    pub pointer: usize,
}

impl Null for Pointer {
    fn null() -> Self {
        NULLPTR
    }
}

impl Display for Pointer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_null() {
            write!(f, "NULL")
        } else {
            write!(f, "ptr({})", self.pointer)
        }
    }
}

#[inline]
pub fn ptr(u: usize) -> Pointer {
    Pointer{pointer: u}
}


pub trait Null: PartialEq + Sized {
    fn null() -> Self;

    fn is_null(&self) -> bool {
        self == &Self::null()
    }
}


impl Null for i32 {
    fn null() -> i32 {
        0
    }
}

impl Null for f32 {
    fn null() -> f32 {
        0.0
    }
}

impl Null for KeyString {
    fn null() -> KeyString {
        ksf("")
    }
}

impl Null for usize {
    fn null() -> usize {
        0
    }
}


pub struct FreeListVec<T: Null> {
    list: Vec<T>,
    free_list: FnvHashSet<usize>,
}

impl<T: Null + Clone> FreeListVec<T> {

    pub fn new() -> FreeListVec<T> {
        FreeListVec {
            list: Vec::new(),
            free_list: FnvHashSet::default(),
        }
    }

    pub fn add(&mut self, t: T) -> Pointer {
        match pop_from_hashset(&mut self.free_list) {
            Some(index) => {self.list[index] = t; return ptr(index)},
            None => {self.list.push(t); return ptr(self.list.len() - 1)},
        }
    }

    pub fn remove(&mut self, index: Pointer) -> T {
        if self.free_list.contains(&index.pointer) {
            panic!()
        } else  {
            let res = self.list[index.pointer].clone();
            self.list[index.pointer] = T::null();
            self.free_list.insert(index.pointer);
            return res
        }
    }
}

impl<T: Null + Clone> Index<Pointer> for FreeListVec<T> {
    type Output = T;

    fn index(&self, index: Pointer) -> &Self::Output {
        if self.free_list.contains(&index.pointer) {
            panic!("Tried to access a freed value with index: {}", index.pointer)
        }
        &self.list[index.pointer]
    }
}

impl<T: Null + Clone> IndexMut<Pointer> for FreeListVec<T> {

    fn index_mut(&mut self, index: Pointer) -> &mut Self::Output {
        if self.free_list.contains(&index.pointer) {
            panic!("Tried to access a freed value with index: {}", index.pointer)
        }
        &mut self.list[index.pointer]
    }
}

impl<'a, T: Null> IntoIterator for &'a FreeListVec<T> {
    type Item = &'a T;
    type IntoIter = FreeListIter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        FreeListIter {
            items: &self.list,
            index: 0,
        }
    }
}


pub struct FreeListIter<'a, T: Null> {
    items: &'a [T],
    index: usize,
}

impl<'a, T: Null> Iterator for FreeListIter<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        while self.index < self.items.len() {
            let item = &self.items[self.index];
            self.index += 1;

            if !item.is_null() {
                return Some(item);
            }
        }
        None
    }
}



pub struct Hallocator {
    pub buffer: Vec<u8>,
    block_size: usize,
    tail: usize,
    free_list: FnvHashSet<usize>,
}

impl Hallocator {
    pub fn new(block_size: usize) -> Hallocator {
        Hallocator {
            buffer: Vec::with_capacity(block_size * 64),
            block_size,
            tail: 0,
            free_list: FnvHashSet::default(),
        }
    }

    pub fn alloc(&mut self) -> Pointer {
        
        match pop_from_hashset(&mut self.free_list) {
            Some(pointer) => {
                Pointer{pointer}
            },
            None => {
                let result = self.tail;
                extend_zeroes(&mut self.buffer, self.block_size);
                self.tail += self.block_size;
                Pointer{pointer: result}
            },
        }
    }

    pub fn free(&mut self, pointer: usize) -> Result<(), EzError> {
        match self.free_list.insert(pointer) {
            true => (),
            false => return Err(EzError { tag: ErrorTag::Structure, text: format!("Attempting to double free a pointer. Pointer address: {}", pointer as usize) }),
        }
        let row_pointer = &self.buffer[pointer..pointer + self.block_size].as_mut_ptr();
        unsafe { row_pointer.write_bytes(0, self.block_size) };

        Ok(())
    }

    pub fn block_size(&self) -> usize {
        self.block_size
    }

    #[inline]
    pub fn get_block(&self, pointer: Pointer) -> &[u8] {
        let pointer = pointer.pointer;
        &self.buffer[pointer..pointer+self.block_size]
    }

    #[inline]
    pub fn get_block_mut(&mut self, pointer: Pointer) -> &mut [u8] {
        let pointer = pointer.pointer;

        &mut self.buffer[pointer..pointer+self.block_size]
    }

    #[inline]
    pub fn read_i32(&self, pointer: Pointer, offset: usize) -> i32 {
        let pointer = pointer.pointer;

        if offset > self.block_size - 4 {
            panic!("Trying to read out of bounds memory")
        }
        unsafe { *(self.get_block(ptr(pointer+offset)).as_ptr() as *const i32) }
    }

    #[inline]
    pub fn read_u64(&self, pointer: Pointer, offset: usize) -> u64 {
        let pointer = pointer.pointer;
        
        if offset > self.block_size - 8 {
            panic!("Trying to read out of bounds memory")
        }
        unsafe { *(self.get_block(ptr(pointer+offset)).as_ptr() as *const u64) }
    }

    #[inline]
    pub fn read_f32(&self, pointer: Pointer, offset: usize) -> f32 {
        let pointer = pointer.pointer;
        
        if offset > self.block_size - 4 {
            panic!("Trying to read out of bounds memory")
        }
        unsafe { *(self.get_block(ptr(pointer+offset)).as_ptr() as *const f32) }
    }

    #[inline]
    pub fn read_keystring(&self, pointer: Pointer, offset: usize) -> KeyString {
        let pointer = pointer.pointer;
        
        if offset > self.block_size - 64 {
            panic!("Trying to read out of bounds memory")
        }
        unsafe { *(self.get_block(ptr(pointer+offset)).as_ptr() as *const KeyString) }
    }

    #[inline]
    pub fn write_i32(&mut self, pointer: Pointer, offset: usize, value: i32) {
        let pointer = pointer.pointer;
        
        if offset > self.block_size - 4 {
            panic!("Trying to write out of bounds memory")
        }
        unsafe { (self.get_block_mut(ptr(pointer+offset)).as_mut_ptr() as *mut i32).write(value) }
    }

    #[inline]
    pub fn write_u64(&mut self, pointer: Pointer, offset: usize, value: u64) {
        let pointer = pointer.pointer;
        
        if offset > self.block_size - 8 {
            panic!("Trying to write out of bounds memory")
        }
        unsafe { (self.get_block_mut(ptr(pointer+offset)).as_mut_ptr() as *mut u64).write(value) }
    }

    #[inline]
    pub fn write_f32(&mut self, pointer: Pointer, offset: usize, value: f32) {
        let pointer = pointer.pointer;
        
        if offset > self.block_size - 4 {
            panic!("Trying to write out of bounds memory")
        }
        unsafe { (self.get_block_mut(ptr(pointer+offset)).as_mut_ptr() as *mut f32).write(value) }
    }

    #[inline]
    pub fn write_keystring(&mut self, pointer: Pointer, offset: usize, value: KeyString) {
        let pointer = pointer.pointer;
        
        if offset > self.block_size - 64 {
            panic!("Trying to write out of bounds memory")
        }
        unsafe { (self.get_block_mut(ptr(pointer+offset)).as_mut_ptr() as *mut KeyString).write(value) }

    }
    
}





pub fn extend_zeroes(vec: &mut Vec<u8>, n: usize) {
    vec.resize(vec.len() + n, 0);
}


pub fn pop_from_hashset<T: Eq + Hash + Clone>(set: &mut FnvHashSet<T>) -> Option<T> {
    let result = match set.iter().next() {
        Some(item) => item,
        None => return None,
    };
    let key = result.clone();

    set.take(&key)
}

pub fn pointer_add(pointer: *mut u8, offset: usize) -> *mut u8 {
    let result = pointer.clone();
    unsafe { result.add(offset) }
}

pub fn check_pointer_safety(pointer: *mut u8) {
    if pointer.is_null() {
        panic!("Got a NULL pointer from the OS. Either out of memory or some other unrecoverable error");
    } else if usize::MAX - (pointer as usize) < 4096 {
        panic!("Pointer from OS is only a page away from overflowing");
    } else {
        ()
    }
}



pub struct Slice {
    pub pointer: *mut u8,
    pub len: usize,
}

impl Slice {
    pub fn offset(&self, offset: usize) -> Result<*mut u8, EzError> {
        if offset >= self.len {
            return Err(EzError { tag: ErrorTag::Structure, text: format!("Attempting out of bounds access. Base pointer - offest: {} - {}", self.pointer as usize, offset) })
        }

        return unsafe { Ok(self.pointer.add(offset)) }
    }
}

pub struct BlockAllocator {
    pub chunks: Vec<*mut u8>,
    pub current_chunk: usize,
    pub current_offset: usize,
    pub block_size: usize,
    pub free_list: FnvHashSet<*mut u8>,
    alloc_count: usize,
}

impl BlockAllocator {
    pub fn new(block_size: usize) -> Result<BlockAllocator, EzError> {

        if block_size % 64 != 0 {
            return Err(EzError { tag: ErrorTag::Structure, text: format!("Improper block size. Must be multiple of 64. Received: {}", block_size) })
        }

        let layout = Layout::from_size_align(block_size * 64, 64)
            .expect(&format!("Must have passed a monstrous block_size.\nBlock_size passed: {}", block_size));

        let start = unsafe { alloc(layout) };
        check_pointer_safety(start);

        Ok(
            BlockAllocator {
                chunks: vec!(start),
                current_chunk: 0,
                current_offset: 0,
                block_size,
                free_list: FnvHashSet::with_hasher(FnvBuildHasher::new()),
                alloc_count: 0,
            }
        )
    }

    pub fn alloc(&mut self) -> Slice {

        self.alloc_count += 1;
        let result: Slice;
        match pop_from_hashset(&mut self.free_list) {
            Some(pointer) => return Slice{pointer, len: self.block_size},
            None => {
                if self.current_chunk == self.chunks.len()-1 && self.block_size + self.current_offset == 64*self.block_size {
                    let l = self.chunks.len();
                    for _ in 0..l {
                        let layout = Layout::from_size_align(self.block_size * 64, 64)
                        .expect(&format!("Must have passed a monstrous block_size.\nBlock_size passed: {}", self.block_size));
    
                        let new_chunk = unsafe { alloc(layout) };
                        check_pointer_safety(new_chunk);
                        self.chunks.push(new_chunk);
                    }
                    let tail = pointer_add(self.chunks[self.current_chunk], self.current_offset);
                    self.current_offset = 0;
                    self.current_chunk += 1;
                    result = Slice{pointer: tail, len: self.block_size};
                } else if self.current_offset + self.block_size == 64*self.block_size {
                    let tail = pointer_add(self.chunks[self.current_chunk], self.current_offset);
                    self.current_chunk += 1;
                    self.current_offset = 0;
                    result = Slice{pointer: tail, len: self.block_size};
                } else {
                    let tail = pointer_add(self.chunks[self.current_chunk], self.current_offset);
                    self.current_offset += self.block_size;
                    result = Slice{pointer: tail, len: self.block_size}
                }
                result
            },
        }
    }

    pub fn free(&mut self, slice: Slice) -> Result<(), EzError> {

        match self.free_list.insert(slice.pointer) {
            true => (),
            false => return Err(EzError { tag: ErrorTag::Structure, text: format!("Attempting to double free a pointer. Pointer address: {}", slice.pointer as usize) }),
        }
        unsafe { slice.pointer.write_bytes(0, self.block_size) };

        Ok(())
    }

}

impl Drop for BlockAllocator {
    fn drop(&mut self) {
        let layout = Layout::from_size_align(self.block_size * 64, 64).unwrap();
        for pointer in &self.chunks {
            unsafe { dealloc(*pointer, layout) };
        }
    }
}



#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct FixedList<T: Null + Clone + Debug + Ord + Eq + Sized, const N: usize> {
    list: [T ; N],
    len: usize,
}

impl<T: Null + Clone + Debug + Ord + Eq + Sized, const N: usize> FixedList<T, N> {
    pub fn new() -> FixedList<T, N> {
        FixedList {
            list: std::array::from_fn(|_| T::null()),
            len: 0,
        }
    }

    pub fn push(&mut self, t: T) -> bool {
        if self.len > self.list.len() {
            return false
        } else {
            self.list[self.len] = t;
            self.len += 1;
            return true
        }
    }

    pub fn pop(&mut self) -> Option<T> {
        if self.len == 0 {
            None
        } else {
            let result = self.list[self.len].clone();
            self.list[self.len] = T::null();
            self.len -= 1;
            Some(result)
        }
    }

    pub fn full(&self) -> bool {
        self.len == N
    }

    pub fn insert_at(&mut self, index: usize, value: &T) -> Result<(), EzError> {
        if self.full() || index > self.len {
            return Err(EzError { tag: ErrorTag::Query, text: format!("Tried to insert {:?} past the bounds of a FixedList", value) })
        }

        let temp = self.list[index..].to_vec();

        self.list[index] = value.clone();
        self.len += 1;
        for i in 0..temp.len()-1 {
            self.list[index+1+i] = temp[i].clone();
        }

        Ok(())
    }

    pub fn remove(&mut self, index: usize) -> T {
        let t = self.list[index].clone();
        for i in index .. self.len()-1 {
            self.list[i] = self.list[i+1].clone();
            self.list[i+1] = T::null();
        }
        self.len -= 1;

        t
    }

    pub fn sort(&mut self) {
        self.list.sort()
    }

    pub fn iter(&self) ->  std::slice::Iter<'_, T> {
        self.list[0..self.len].iter()
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn search(&self, t: &T) -> usize {
        let mut i = 0;
        while i < self.len() {
            if &self.list[i] > t  {
                break
            }
            i += 1;
        }
        return i
    }

    pub fn find(&self, t: &T) -> Option<usize> {
        for i in 0..self.len() {
            if &self.list[i] == t {
                return Some(i)
            }
        }

        None
    }

    pub fn get(&self, index: usize) -> Option<&T> {
        self.list.get(index)
    }

    pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        self.list.get_mut(index)
    }
}

impl<T: Null + Clone + Debug + Display + Ord + Eq + Sized, const N: usize> Display for FixedList<T, N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut printer = String::from("[");
        for item in &self.list[0..self.len()] {
            printer.push_str(&format!("{}, ", item));
        }
        printer.push(']');

        write!(f, "{}",printer)
    }
}


#[cfg(test)]
mod tests {

    use rand::Rng;

    use super::*;

    #[test]
    fn test_tests() {
        println!("Test!");
    }


    #[test]
    fn test_bytes_to_str() {
        let bytes = [0,0,0,0,0,49,50,51,0,0,0,0,0];
        let x = bytes_to_str(&bytes).unwrap();
        assert_eq!("123", x);
    }

    #[test]
    fn test_encode_hex() {
        let byte = [0u8];
        let x = encode_hex(&byte);
        println!("{}", x);
    }

    #[test]
    fn test_median() {
        let data = [3, 1, 6, 1, 5, 8, 1, 8, 10, 11];
    
        let med = median_i32_slice(&data);
        assert_eq!(med, 5.5);
    }

    #[test]
    fn test_mode() {
        let data = [3, 1, 6, 1, 5, 8, 1, 8, 10, 11];
    
        let mode = mode_i32_slice(&data);
        assert_eq!(mode, 1);

        let text_data = [KeyString::from("3"), KeyString::from("1"), KeyString::from("6"), KeyString::from("1"), KeyString::from("5"), KeyString::from("8"), KeyString::from("1"), KeyString::from("8"), KeyString::from("10"), KeyString::from("11")];
        let text_mode = mode_string_slice(&text_data);
        assert_eq!(text_mode, KeyString::from("1"));
    }

    #[test]
    fn test_mean() {
        let data = [3, 1, 6, 1, 5, 8, 1, 8, 10, 11];
    
        let mean = mean_i32_slice(&data);
        assert_eq!(mean, 5.4);
    }

    #[test]
    fn test_stdev() {
        let data = [3, 1, 6, 1, 5, 8, 1, 8, 10, 11, 3, 1, 6, 1, 5, 8, 1, 8, 10, 11];
        let stdev = stdev_i32_slice(&data);
        println!("stdev: {}", stdev);
        assert!(stdev > 3.611 && stdev < 3.612);
    }

    #[test]
    fn test_sum_i32_slice() {
        let data = [3, 6, 9];
        let sum = sum_i32_slice(&data);
        println!("sum: {}", sum);
        assert!(sum == 18);
    }

    #[test]
    fn test_sum_f32_slice() {
        let data = [3.0, 6.0, 9.0];
        let sum = sum_f32_slice(&data);
        println!("sum: {}", sum);
        assert!(sum == 18.0);
    }

    #[test]
    fn test_free_list_vec() {
        let mut list = FreeListVec {
            list: Vec::new(),
            free_list: FnvHashSet::default(),
        };

        for i in 0..2000 {
            list.add(ptr(i));
        }

        for i in 0..2000 {
            let index = list.remove(ptr(i));
            let new_index = list.add(ptr(999));

            assert_eq!(index, new_index);
        }
    }

    #[test]
    fn test_fixed_list() {
        let mut list1: FixedList<Pointer, 100> = FixedList::new();
        let mut list2: FixedList<Pointer, 100> = FixedList::new();

        let mut removes: Vec<usize> = Vec::new();
        let mut rng = rand::thread_rng();
        
        let upper_bound: usize = rng.gen_range(1..100);
        println!("upper_bounds: {}", upper_bound);
        for _ in 0..upper_bound {
            let num = rng.gen_range(0..100);
            if removes.contains(&num) {
                continue
            } else {
                removes.push(num);
            }
        }

        // removes = vec![6,4,2];
        println!("removes: {:?}", removes);
        removes.sort();
        removes = removes.into_iter().rev().collect();

        for i in 0..100 {
            let num = rand::random::<usize>();
            list1.push(ptr(num));
            if removes.contains(&i) {
                continue
            } else {
                list2.push(ptr(num));
            }
        }

        for i in removes {
            list1.remove(i);
        }

        println!("list1.len(): {}\nlist2.len(): {}", list1.len(), list2.len());

        assert_eq!(list1, list2);
    }
}