use anyhow::{Context, Result};
use clap::Parser;
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io::Seek;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::PathBuf;
use std::process::Command;
use vinter_common::trace::{self, TraceEntry};
#[derive(Parser, Debug)]
#[clap(version, about, long_about= None)]
struct Args {
    #[clap(long)]
    traceFile: PathBuf,
    #[clap(long)]
    outputFile: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let f1 = File::open(args.traceFile).context("could not open trace file")?;
    let mut reader = BufReader::new(f1);

    let f2 = File::create(args.outputFile).context("could not open trace file")?;
    let mut writer = BufWriter::new(f2);
    #[cfg(not(feature = "investigate_vinter"))]
    {
        for entry in trace::parse_trace_file_bin_mpk(reader).map(move |entry| {
            match &entry {
                Ok(TraceEntry::Write {
                    id,
                    address,
                    size,
                    content,
//                    origin_address,
                    non_temporal,
                    metadata,
                }) => {
                    write!(
                        &mut writer,
                        "Write, ID: {}, address: {:#x}, size: {}, non_temporal: {},  content: {:x?}\n",
                        id, address, size, non_temporal, content
                    )
                    .context("could not print write");
                }
                Ok(TraceEntry::Read {
                    id,
                    address,
                    size,
                    content,
                }) => {
                    write!(
                        &mut writer,
                        "Read, ID: {}, address: {:#x}, size: {}, content: {:x?}\n",
                        id, address, size, content
                    )
                    .context("could not print read");
                }
                Ok(TraceEntry::Fence {
                    id,
                    mnemonic,
                    metadata,
                }) => {
                    write!(&mut writer, "Fence, ID: {}, mnemonic: {}\n", id, mnemonic);
                    // A fence persists all flushed cachelines. For crash image
                    // generation, we still need to see these flushed lines, so
                    // defer the flush until the next iteration.
                }
                Ok(TraceEntry::Flush {
                    id,
                    mnemonic,
                    address,
                    ..
                }) => {
                    write!(
                        &mut writer,
                        "Flush, ID: {}, mnemonic: {}, address {:x?}\n",
                        id, mnemonic, address
                    );
                }
                Ok(TraceEntry::Hypercall { id, action, value }) => {
                    write!(
                        &mut writer,
                        "Hypercall, ID: {}, action: {}, value: {}\n",
                        id, action, value
                    );
                }

                _ => {}
            }
            entry
        }) {
            entry?;
        }
    }
    #[cfg(feature = "investigate_vinter")]
    {
        for entry in trace::parse_trace_file_bin_mpk(reader).map(move |entry| {
            match &entry {
                Ok(TraceEntry::Write {
                    id,
                    address,
                    size,
                    content,
                    non_temporal,
                    metadata,
                }) => {
                    write!(&mut writer, "{}\n", address);
                    // write!(&mut writer, "{}, {}\n", id, metadata.timestamp)
                    //    .context("could not print write");
                }
                Ok(TraceEntry::Read {
                    id,
                    address,
                    size,
                    content,
                }) => {
                    write!(&mut writer, "{}\n", address);
                    /*write!(
                                            &mut writer,
                                            "Read, ID: {}, address: {:#x}, size: {}, content: {:x?}\n",
                                            id, address, size, content
                                        )
                                        .context("could not print read");
                    */
                }
                Ok(TraceEntry::Fence {
                    id,
                    mnemonic,
                    metadata,
                }) => {
                    //write!(&mut writer, "{}", address);
                    /*write!(&mut writer, "{}, {}\n", id, metadata.timestamp)
                                            .context("could not print write");
                    */
                    // A fence persists all flushed cachelines. For crash image
                    // generation, we still need to see these flushed lines, so
                    // defer the flush until the next iteration.
                }
                Ok(TraceEntry::Flush {
                    id,
                    mnemonic,
                    address,
                    metadata,
                    ..
                }) => {
                    write!(&mut writer, "{}\n", address);
                    //write!(&mut writer, "{}, {}\n", id, metadata.timestamp)
                    //   .context("could not print flush");
                }
                Ok(TraceEntry::Hypercall { id, action, value }) => {}

                _ => {}
            }
            entry
        }) {
            entry?;
        }
    }

    return Ok(());
}
