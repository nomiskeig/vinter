use std::io::{BufRead, Read, Seek, Write};

use anyhow::{bail, Context, Result};
use bincode::{Decode, Encode};
use std::cell::RefCell;
use std::sync::Mutex;

const BINCODE_CONFIG: bincode::config::Configuration = bincode::config::standard();

#[repr(C)]
pub struct MPKTraceEntry {
    pub entry_type: u32,
    pub mnemonic: u32,
    pub id: u32,
    pub non_temporal: u32,
    pub value_size_and_location: u64,
    pub value: u64,
    pub address: u64,
}
#[derive(Debug, Default, Clone, Encode, Decode)]
pub struct Metadata {
    /// current program counter
    pub pc: u64,
    /// currently in kernel mode?
    pub in_kernel: bool,
    /// kernel stack trace (frame pointer walk)
    pub kernel_stacktrace: Vec<u64>,
}

#[derive(Debug)]
pub enum TracerType {
    MPK,
    PANDA,
}
#[derive(Debug, Encode)]
pub enum TraceEntryMPK {
    Write {
        id: usize,
        address: usize,
        size: usize,
        content: Vec<u8>,
        non_temporal: bool,
        metadata: Metadata,
    },
    Fence {
        id: usize,
        mnemonic: String,
        metadata: Metadata,
    },
    Flush {
        id: usize,
        mnemonic: String,
        address: usize,
        metadata: Metadata,
    },
    Read {
        id: usize,
        address: usize,
        size: usize,
        content: Vec<u8>,
    },
    Hypercall {
        id: usize,
        action: String,
        value: String,
    },
}
#[derive(Debug, Encode, Decode)]
pub enum TraceEntry {
    Write {
        id: usize,
        address: usize,
        size: usize,
        content: Vec<u8>,
        non_temporal: bool,
        metadata: Metadata,
    },
    Fence {
        id: usize,
        mnemonic: String,
        metadata: Metadata,
    },
    Flush {
        id: usize,
        mnemonic: String,
        address: usize,
        metadata: Metadata,
    },
    Read {
        id: usize,
        address: usize,
        size: usize,
        content: Vec<u8>,
    },
    Hypercall {
        id: usize,
        action: String,
        value: String,
    },
}
struct DecodeState {
    total_offset: usize,
    remaining: usize,
    base_address: u64,
    rep_size: u32,
    count: usize,
    offset: usize,
    value: u64,
    last_id: u32,
}
struct TotalState {
    total_expectd: i64,
}
fn create_rep_write(mut state: std::sync::MutexGuard<'_, DecodeState>) -> TraceEntryMPK {
    state.remaining -= 1;
    state.total_offset += 1;
    state.offset += 1;
    state.count += 1;

    TraceEntryMPK::Write {
        id: (state.last_id + (state.offset - 1) as u32) as usize,
        address: (state.base_address + ((state.count -1) as u32 * state.rep_size) as u64) as usize,
        size: state.rep_size as usize,
        content: state
            .value
            .to_le_bytes()
            .into_iter()
            .take(state.rep_size as usize)
            .collect(),
        non_temporal: true,
        metadata: Metadata {
            pc: 0,
            in_kernel: false,
            kernel_stacktrace: vec![],
        },
    }
}

static decode_state: Mutex<DecodeState> = Mutex::new(DecodeState {
    remaining: 0,
    count: 0,
    offset: 0,
    total_offset: 0,
    rep_size: 0,
    base_address: 0,
    last_id: 0,
    value: 0,
});
static total_expected: Mutex<TotalState> = Mutex::new(TotalState { total_expectd: 0 });
impl ::bincode::Decode for TraceEntryMPK {
    fn decode<D: ::bincode::de::Decoder>(
        decoder: &mut D,
    ) -> core::result::Result<Self, ::bincode::error::DecodeError> {
        //println!("trying to decode an mpk entry");
        let mut state = decode_state.lock().unwrap();
        if state.remaining > 0 {
            return Ok(create_rep_write(state));
        }
        let variant_index = <u32 as ::bincode::Decode>::decode(decoder)?;
        let mnemonic = <u32 as ::bincode::Decode>::decode(decoder)?;
        let decoded_id = <u32 as ::bincode::Decode>::decode(decoder)?;
        let non_temporal = <u32 as ::bincode::Decode>::decode(decoder)?;
        let value_size_and_location = <u64 as ::bincode::Decode>::decode(decoder)?;
        let value = <u64 as ::bincode::Decode>::decode(decoder)?;
        let address = <u64 as ::bincode::Decode>::decode(decoder)?;
        let flags = <u64 as ::bincode::Decode>::decode(decoder)?;
        let size = value_size_and_location >> 1;
        let mut id = decoded_id + state.total_offset as u32;
        //println!("next id is {}", id);

        // TODO: this is missing multiple thingies, like external values
        // // this creates multiple entries from a rep isntruction
        if flags & (0x1 << 2) != 0x0 {
            println!("found flag with size {}", size);
            state.remaining = size as usize;
            total_expected.lock().unwrap().total_expectd += size as i64 - 1 as i64;
            state.last_id = id;
            state.count = 0;
            state.offset = 0;
            state.value = value;
            state.base_address = address;
            state.rep_size = match flags & 0x3 {
                0 => 1,
                1 => 2,
                2 => 4,
                3 => 8,
                _ => 0, // Err(::bincode::error::DecodeError::OtherString("found unhandled rep_size".to_string());
            };
          //  println!("rep_siz is {:?}", state.rep_size);
        }
        if state.remaining > 0 {
            return Ok(create_rep_write(state));
        }
        match variant_index {
            0u32 => Ok(Self::Write {
                id: id as usize,
                address: address as usize,
                size: size as usize,
                content: value
                    .to_le_bytes()
                    .into_iter()
                    .take(size as usize)
                    .collect(),
                non_temporal: false,
                metadata: Metadata {
                    pc: 0,
                    in_kernel: false,
                    kernel_stacktrace: vec![],
                },
            }),
            1u32 => Ok(Self::Fence {
                id: id as usize,
                mnemonic: match mnemonic {
                    1 => "sfence".to_string(),
                    _ => "not implemented".to_string(),
                },
                metadata: Metadata {
                    pc: 0,
                    in_kernel: false,
                    kernel_stacktrace: vec![],
                },
            }),
            2u32 => Ok(Self::Flush {
                id: id as usize,
                mnemonic: match mnemonic {
                    1 => "clwb".to_string(),
                    _ => "not implemented".to_string(),
                },
                address: address as usize,
                metadata: Metadata {
                    pc: 0,
                    in_kernel: false,
                    kernel_stacktrace: vec![],
                },
            }),
            3u32 => Ok(Self::Read {
                id: id as usize,
                address: address as usize,
                size: size as usize,
                content: value
                    .to_le_bytes()
                    .into_iter()
                    .take(size as usize)
                    .collect(),
            }),
            4u32 => Ok(Self::Hypercall {
                id: id as usize,
                action: "checkpoint".to_string(),
                value: value.to_string(),
            }),
            variant => Err(::bincode::error::DecodeError::UnexpectedVariant {
                found: variant,
                type_name: "TraceEntrySelf",
                allowed: ::bincode::error::AllowedEnumVariants::Range { min: 0, max: 4 },
            }),
        }
    }
}

pub fn get_trace_entry(entry: TraceEntryMPK) -> TraceEntry {
    match entry {
        TraceEntryMPK::Write {
            id,
            address,
            size,
            content,
            non_temporal,
            metadata,
        } => TraceEntry::Write {
            id,
            address,
            size,
            content,
            non_temporal,
            metadata,
        },
        TraceEntryMPK::Fence {
            id,
            mnemonic,
            metadata,
        } => TraceEntry::Fence {
            id,
            mnemonic,
            metadata,
        },
        TraceEntryMPK::Flush {
            id,
            mnemonic,
            address,
            metadata,
        } => TraceEntry::Flush {
            id,
            mnemonic,
            address,
            metadata,
        },
        TraceEntryMPK::Read {
            id,
            address,
            size,
            content,
        } => TraceEntry::Read {
            id,
            address,
            size,
            content,
        },
        TraceEntryMPK::Hypercall { id, action, value } => {
            TraceEntry::Hypercall { id, action, value }
        }
    }
}

impl TraceEntry {
    pub fn decode_from_std_read_panda<R: std::io::Read>(
        src: &mut R,
    ) -> std::result::Result<TraceEntry, bincode::error::DecodeError> {
        bincode::decode_from_std_read(src, BINCODE_CONFIG)
    }
    pub fn decode_from_std_read_mpk<R: std::io::Read>(
        src: &mut R,
    ) -> std::result::Result<TraceEntry, bincode::error::DecodeError> {
        //return decode_mpk_entry(src);
        let res: Result<TraceEntryMPK, bincode::error::DecodeError> = bincode::decode_from_std_read(
            src,
            bincode::config::standard()
                .with_little_endian()
                .with_fixed_int_encoding(),
        );
        match res {
            Ok(entry) => Ok(get_trace_entry(entry)),
            Err(e) => Err(e),
        }
    }

    pub fn encode_into_std_write<W: std::io::Write>(
        &self,
        dst: &mut W,
    ) -> std::result::Result<usize, bincode::error::EncodeError> {
        bincode::encode_into_std_write(self, dst, BINCODE_CONFIG)
    }
}

/// Helper to make filter_map() work with error handling.
fn lift_option<T>(r: Result<Option<T>>) -> Option<Result<T>> {
    match r {
        Ok(None) => None,
        Ok(Some(o)) => Some(Ok(o)),
        Err(e) => Some(Err(e)),
    }
}

pub struct BinTraceIterator<R: Read> {
    file: R,
    tipe: TracerType,
}

impl<R: Read> Iterator for BinTraceIterator<R> {
    type Item = Result<TraceEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        use bincode::error::DecodeError;
        match total_expected.lock().unwrap().total_expectd > 0
            || total_expected.lock().unwrap().total_expectd <= -1
        {
            true => {
                {}
                total_expected.lock().unwrap().total_expectd -= 1;
                let entry;
                #[cfg(feature = "tracer_mpk")]
                {
                    entry = match self.tipe {
                        TracerType::MPK => TraceEntry::decode_from_std_read_mpk(&mut self.file),
                        TracerType::PANDA => TraceEntry::decode_from_std_read_panda(&mut self.file),
                    };
                }
                #[cfg(not(feature = "tracer_mpk"))]
                {
                    entry = TraceEntry::decode_from_std_read_panda(&mut self.file);
                }
                //println!("got entry {:?}", entry);
                return match entry {
                    Ok(e) => Some(Ok(e)),
                    Err(DecodeError::UnexpectedEnd) => {
                        None
                    }
                    Err(e) => {
                        print!("got an error:\n");
                        Some(Err(e.into()))
                    }
                };
            }
            false => return None,
        };
    }
}

pub type TraceWriter<W> = snap::write::FrameEncoder<W>;

/// Create a trace writer with compression.
pub fn new_trace_writer_bin<W: Write>(file: W) -> TraceWriter<W> {
    snap::write::FrameEncoder::new(file)
}

/// Parse a binary trace file.
pub fn parse_trace_file_bin_panda<R: BufRead>(
    file: R,
) -> BinTraceIterator<snap::read::FrameDecoder<R>> {
    {
        total_expected.lock().unwrap().total_expectd = -1 as i64;
    }

    BinTraceIterator {
        file: snap::read::FrameDecoder::new(file),
        tipe: TracerType::PANDA,
    }
}

pub fn parse_trace_file_bin_mpk<R: BufRead>(mut file: R) -> BinTraceIterator<R> {
    let mut buf = [0u8; 64];
    file.read_exact(&mut buf);
    let amount = u64::from_le_bytes(buf[8..16].try_into().unwrap());

    println!("amount {}", amount);

    print!("is in parse_trace_file_bin, buff: {:?}\n", buf);
    {
        total_expected.lock().unwrap().total_expectd = amount as i64;
    }

    BinTraceIterator {
        file,
        tipe: TracerType::MPK,
    }
}
/// Parse a textual trace file.
pub fn parse_trace_file_text(file: impl BufRead) -> impl Iterator<Item = Result<TraceEntry>> {
    file.lines().enumerate().filter_map(move |(id, line)| {
        lift_option((move || {
            let line = line?;
            let lineno = id + 1;
            let cols: Vec<&str> = line.split(",").collect();
            Ok(match cols[0] {
                "write" => {
                    if cols.len() != 6 {
                        bail!("line {}: wrong number of write arguments", lineno);
                    }
                    let address: usize = cols[1]
                        .parse::<usize>()
                        .with_context(|| format!("line {}: invalid address", lineno))?;
                    let size: usize = cols[2]
                        .parse::<usize>()
                        .with_context(|| format!("line {}: invalid size", lineno))?;
                    let content = hex::decode(cols[3])
                        .with_context(|| format!("line {}: invalid content", lineno))?;
                    let non_temporal = match cols[4] {
                        "True" | "true" => true,
                        "False" | "false" => false,
                        other => {
                            bail!("line {}: invalid NT flag {}", lineno, other);
                        }
                    };
                    Some(TraceEntry::Write {
                        id,
                        address,
                        size,
                        content,
                        non_temporal,
                        metadata: Default::default(),
                    })
                }
                "insn" => {
                    if cols.len() != 4 {
                        bail!("line {}: wrong number of insn arguments", lineno);
                    }
                    let insn = cols[1];
                    let address = if cols[2] == "" {
                        None
                    } else {
                        // address might be outside of PMEM area, skip these silently ("performance bug")
                        Some(
                            cols[2]
                                .parse::<usize>()
                                .with_context(|| format!("line {}: invalid address", lineno))?,
                        )
                    };
                    match insn {
                        "mfence" | "sfence" | "wbinvd" | "xchg" => Some(TraceEntry::Fence {
                            id,
                            mnemonic: insn.to_string(),
                            metadata: Default::default(),
                        }),
                        "clwb" | "clflush" => address.map(|address| TraceEntry::Flush {
                            id,
                            mnemonic: insn.to_string(),
                            address,
                            metadata: Default::default(),
                        }),
                        other => {
                            bail!("line {}: unsupported instruction {}", lineno, other);
                        }
                    }
                }
                "read" => {
                    if cols.len() != 4 {
                        bail!("line {}: wrong number of read arguments", lineno);
                    }
                    let address: usize = cols[1]
                        .parse::<usize>()
                        .with_context(|| format!("line {}: invalid address", lineno))?;
                    let size: usize = cols[2]
                        .parse::<usize>()
                        .with_context(|| format!("line {}: invalid size", lineno))?;
                    let content = hex::decode(cols[3])
                        .with_context(|| format!("line {}: invalid content", lineno))?;
                    Some(TraceEntry::Read {
                        id,
                        address,
                        size,
                        content,
                    })
                }
                "hypercall" => {
                    if cols.len() != 3 {
                        bail!("line {}: wrong number of hypercall arguments", lineno);
                    }
                    Some(TraceEntry::Hypercall {
                        id,
                        action: cols[1].into(),
                        value: cols[2].into(),
                    })
                }
                op => {
                    bail!("unsupported operation {}", op);
                }
            })
        })())
    })
}
