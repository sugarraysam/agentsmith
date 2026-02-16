use aya::{maps::ring_buf::RingBuf, programs::TracePoint};
use log::{debug, info, warn};
use tokio::{io::unix::AsyncFd, signal};

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut bpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/agentsmith"
    )))?;

    match aya_log::EbpfLogger::init(&mut bpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger = AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;

            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    let program: &mut TracePoint = bpf
        .program_mut("handle_new_container")
        .unwrap()
        .try_into()?;
    program.load()?;
    program.attach("cgroup", "cgroup_attach_task")?;

    let container_events = RingBuf::try_from(bpf.map_mut("CONTAINER_EVENTS").unwrap())?;
    let mut container_events_fd =
        AsyncFd::with_interest(container_events, tokio::io::Interest::READABLE)?;

    let container_events_handler = async move {
        loop {
            let mut guard = container_events_fd.readable_mut().await.unwrap();
            let ring_buf = guard.get_inner_mut();

            while let Some(item) = ring_buf.next() {
                let pid: i32 = i32::from_ne_bytes((*item).try_into().unwrap());
                info!("Received pid: {:?}", pid);
            }

            guard.clear_ready();
        }
    };

    // Add all async handlers here, use `tokio::select` prioritization features
    // and optimize ordering.
    tokio::select! {
        _ = container_events_handler => {
            println!("Reader finished unexpectedly");
        },
        _ = signal::ctrl_c() => {
            println!("Exiting...");
        }
    }

    Ok(())
}
