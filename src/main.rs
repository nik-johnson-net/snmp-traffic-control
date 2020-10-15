use futures::stream::TryStreamExt;
use netlink_packet_route::rtnl::tc::nlas::{Nla, Stats};
use rtnetlink::new_connection;
use std::io;
use std::io::ErrorKind;
use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, BufWriter,
    Lines,
};
use std::cmp::Ordering;

const MIB_EXPERIMENTAL: [u16; 5] = [1, 3, 6, 1, 3];
const MIB_ID: u16 = 2020;

#[derive(Eq, PartialEq)]
struct Entry {
    oid: OID,
    type_: String,
    value: String,
}

impl PartialOrd for Entry {
    fn partial_cmp(&self, other: &Entry) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Entry {
    fn cmp(&self, other: &Entry) -> Ordering {
        self.oid.cmp(&other.oid)
    }
}

#[derive(Eq, Ord, PartialEq, PartialOrd)]
struct OID(Vec<u16>);

impl OID {
    pub fn from_string(oid: &str) -> OID {
        let mut o = oid;
        if let Some(stripped) = oid.strip_prefix(".") {
            o = stripped;
        }

        let oids: Vec<u16> = o.split(".").map(|x| x.parse::<u16>().unwrap()).collect();
        OID(oids)
    }

    pub fn append(&self, u: u16) -> OID {
        let mut new_oid = self.0.clone();
        new_oid.push(u);
        OID(new_oid)
    }

    pub fn to_string(&self) -> String {
        let new_string = self.0.iter().map(|x| format!("{}", x)).collect::<Vec<String>>().join(".");
        format!(".{}", new_string)
    }
}

#[tokio::main]
async fn main() {
    let mut stdin = BufReader::new(tokio::io::stdin()).lines();
    let mut stdout = BufWriter::new(tokio::io::stdout());

    let mut cached_results = Vec::new();
    let mut next_value_index = 0;

    while let Ok(_) = run_once(
        &mut stdin,
        &mut stdout,
        &mut cached_results,
        &mut next_value_index,
    )
    .await
    {
        // Continue running while fine
    }

    loop {
        match run_once(&mut stdin, &mut stdout, &mut cached_results, &mut next_value_index).await {
            Ok(_) => continue,
            Err(e) => eprint!("{}", e),
        }
    }
}

async fn run_once<T: AsyncRead + Unpin, U: AsyncWrite + Unpin>(
    lines: &mut Lines<BufReader<T>>,
    output: &mut U,
    cache: &mut Vec<Entry>,
    next_value_index: &mut usize,
) -> io::Result<()> {
    let command = lines.next_line().await?.expect("missing input");

    let lines = handle_command(lines, &command, cache, next_value_index).await?;

    for line in lines {
        output.write_all(&line.as_bytes()).await?;
        output.write("\n".as_bytes()).await?;
    }

    output.flush().await
}

async fn handle_command<T: AsyncRead + Unpin>(
    lines: &mut Lines<BufReader<T>>,
    command: &str,
    cache: &mut Vec<Entry>,
    next_value_index: &mut usize,
) -> io::Result<Vec<String>> {
    match command {
        "PING" => Ok(vec![String::from("PONG")]),
        "get" => {
            let oid_str = lines.next_line().await?.expect("missing input");
            let oid = OID::from_string(&oid_str);

            // Refresh cache for a new get
            let rebuilt_cache = build_results().await?;
            let _ = std::mem::replace(cache, rebuilt_cache);
            *next_value_index = 0;

            // Find the requested oid and return it
            match find_oid(cache, &oid) {
                // oid found, so return it
                Some(entry) => {
                    let output = vec![entry.oid.to_string(), entry.type_.clone(), entry.value.clone()];
                    Ok(output)
                }
                // oid not found, return NONE
                None => Ok(vec![String::from("NONE")]),
            }
        }
        "getnext" => {
            // Refresh cache for a new get
            let rebuilt_cache = build_results().await?;
            let _ = std::mem::replace(cache, rebuilt_cache);
            *next_value_index = 0;
            
            let oid_str = lines.next_line().await?.expect("missing input");
            let oid = OID::from_string(&oid_str);

            if let Some(entry) = find_next(&cache, &oid) {
                let output = vec![entry.oid.to_string(), entry.type_.clone(), entry.value.clone()];
                Ok(output)
            } else {
                Ok(vec![String::from("DONE")])
            }
        }
        "set" => {
            let _oid = lines.next_line().await?.expect("missing input");

            let _value = lines.next_line().await?.expect("missing input");
            Ok(vec![String::from("not-writable")])
        }
        _ => Err(io::Error::new(ErrorKind::NotFound, "unknown comand")),
    }
}

async fn build_results() -> io::Result<Vec<Entry>> {
    let mut entries = Vec::new();
    let (connection, handle, _) = new_connection().unwrap();
    tokio::spawn(connection);

    let mut table_index: u16 = 1;
    let mut qdiscs = handle.qdisc().get().execute();
    while let Some(tc_mesage) = qdiscs.try_next().await.unwrap() {
        // experimental.trafficControl.trafficControlTable.trafficControlTableEntry
        let oid = OID(Vec::from(MIB_EXPERIMENTAL)).append(MIB_ID).append(1).append(1);

        // Index
        entries.push(Entry {
            oid: oid.append(1).append(table_index),
            type_: "Unsigned32".to_string(),
            value: tc_mesage.header.index.to_string(),
        });

        // ifIndex
        entries.push(Entry {
            oid: oid.append(2).append(table_index),
            type_: "Integer32".to_string(),
            value: tc_mesage.header.index.to_string(),
        });
        // handle
        entries.push(Entry {
            oid: oid.append(3).append(table_index),
            type_: "Integer32".to_string(),
            value: tc_mesage.header.handle.to_string(),
        });
        // parent
        entries.push(Entry {
            oid: oid.append(4).append(table_index),
            type_: "Integer32".to_string(),
            value: tc_mesage.header.parent.to_string(),
        });

        for nla in tc_mesage.nlas {
            match nla {
                Nla::HwOffload(b) => entries.push(Entry {
                    oid: oid.append(5).append(table_index),
                    type_: "Integer32".to_string(),
                    value: b.to_string(),
                }),
                Nla::Kind(b) => entries.push(Entry {
                    oid: oid.append(6).append(table_index),
                    type_: "STRING".to_string(),
                    value: b.to_string(),
                }),
                Nla::Stats(stats) => build_stat_entries(&oid, table_index, &mut entries, &stats),
                _ => continue,
            };
        }

        table_index += 1;
    }

    entries.sort_unstable();

    Ok(entries)
}

fn find_oid<'a>(cache: &'a Vec<Entry>, oid: &OID) -> Option<&'a Entry> {
    let position = cache.iter().position(|x| &x.oid == oid);

    position.map(|p| &cache[p])
}

fn find_next<'a>(cache: &'a Vec<Entry>, oid: &OID) -> Option<&'a Entry> {
    let position = cache.iter().position(|x| &x.oid > oid);

    position.map(|p| &cache[p])
}

fn build_stat_entries(oid: &OID, table_index: u16, entries: &mut Vec<Entry>, stats: &Stats) {
    // Bytes
    entries.push(Entry {
        oid: oid.append(7).append(table_index),
        type_: "Counter64".to_string(),
        value: stats.bytes.to_string(),
    });

    // Packets
    entries.push(Entry {
        oid: oid.append(8).append(table_index),
        type_: "Counter64".to_string(),
        value: stats.packets.to_string(),
    });

    // Drops
    entries.push(Entry {
        oid: oid.append(9).append(table_index),
        type_: "Counter64".to_string(),
        value: stats.drops.to_string(),
    });

    // Overlimits
    entries.push(Entry {
        oid: oid.append(10).append(table_index),
        type_: "Counter64".to_string(),
        value: stats.overlimits.to_string(),
    });

    // bytes per second
    entries.push(Entry {
        oid: oid.append(11).append(table_index),
        type_: "Integer32".to_string(),
        value: stats.bps.to_string(),
    });

    // Packets per second
    entries.push(Entry {
        oid: oid.append(12).append(table_index),
        type_: "Integer32".to_string(),
        value: stats.pps.to_string(),
    });

    // Queue length
    entries.push(Entry {
        oid: oid.append(13).append(table_index),
        type_: "Integer32".to_string(),
        value: stats.qlen.to_string(),
    });

    // Backlog
    entries.push(Entry {
        oid: oid.append(14).append(table_index),
        type_: "Integer32".to_string(),
        value: stats.backlog.to_string(),
    });
}