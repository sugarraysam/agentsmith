#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext,
    helpers::bpf_probe_read_kernel_str_bytes,
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use aya_log_ebpf::debug;

const PAGE_SIZE: u32 = 4096;

#[map]
static CONTAINER_EVENTS: RingBuf = RingBuf::with_byte_size(
    PAGE_SIZE * 2, // can fit 2048 pids
    0,             // adaptive notifications, don't set flags
);

#[tracepoint]
pub fn handle_new_container(ctx: TracePointContext) -> u32 {
    match try_handle_new_container(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret.try_into().unwrap_or(1),
    }
}

const KUBEPODS_PREFIX: &'static [u8] = b"/kubepods";
const RUNC: &'static [u8] = b"runc";
const CONTAINER_ID_LEN: usize = 64;

// doodly-legion# cat cgroup/cgroup_attach_task/format
// name: cgroup_attach_task
// ID: 491
// format:
//         field:unsigned short common_type;       offset:0;       size:2; signed:0;
//         field:unsigned char common_flags;       offset:2;       size:1; signed:0;
//         field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
//         field:int common_pid;   offset:4;       size:4; signed:1;

//         field:int dst_root;     offset:8;       size:4; signed:1;
//         field:int dst_level;    offset:12;      size:4; signed:1;
//         field:u64 dst_id;       offset:16;      size:8; signed:0;
//         field:int pid;  offset:24;      size:4; signed:1;
//         field:__data_loc char[] dst_path;       offset:28;      size:4; signed:0;
//         field:__data_loc char[] comm;   offset:32;      size:4; signed:0;
fn try_handle_new_container(ctx: TracePointContext) -> Result<u32, i64> {
    // Ignore cgroups that are not long enough.
    let (dst_path_offset, dst_path_len) = unsafe { ctx.read_at::<i32>(28).map(parse_dataloc) }?;
    if dst_path_len < KUBEPODS_PREFIX.len() + CONTAINER_ID_LEN {
        return Ok(0);
    }

    // We allocate a single buffer and reuse it to read all of the strings.
    // On success `bpf_probe_read_kernel_str_bytes` always adds '/0' in the
    // destination buffer so we add 1 to our len.
    let mut buf: [u8; CONTAINER_ID_LEN + 1] = [0; CONTAINER_ID_LEN + 1];
    let src_ptr: *const u8 = ctx.as_ptr().cast();

    // Validate cgroup prefix starts with '/kubepods'
    let has_kubepods_prefix = unsafe {
        let slice = &mut buf[..KUBEPODS_PREFIX.len() + 1];
        bpf_probe_read_kernel_str_bytes(src_ptr.add(dst_path_offset), slice)? == KUBEPODS_PREFIX
    };

    if !has_kubepods_prefix {
        debug!(
            &ctx,
            "[tracepoint:cgroup:cgroup_attach_task] no kubepods prefix"
        );
        return Ok(0);
    }

    // Ignore 'runc' because it is noisy.
    let is_runc = unsafe {
        let (comm_offset, _comm_len) = ctx.read_at::<i32>(32).map(parse_dataloc)?;
        let slice = &mut buf[..RUNC.len() + 1];
        bpf_probe_read_kernel_str_bytes(src_ptr.add(comm_offset), slice)? == RUNC
    };

    if is_runc {
        debug!(&ctx, "[tracepoint:cgroup:cgroup_attach_task] is_runc");
        return Ok(0);
    }

    // ContainerId is suffix of cgroup `/kubepods/besteffort/<podId>/<containerId>`
    let container_id = unsafe {
        bpf_probe_read_kernel_str_bytes(
            src_ptr.add(dst_path_offset + dst_path_len - CONTAINER_ID_LEN - 1),
            &mut buf,
        )?
    };

    if container_id.len() != CONTAINER_ID_LEN {
        debug!(
            &ctx,
            "[tracepoint:cgroup:cgroup_attach_task] container_id len fails: {}",
            container_id.len()
        );
        return Ok(0);
    }

    // TODO: write container_id to TASK_STORAGE
    debug!(
        &ctx,
        "[tracepoint:cgroup:cgroup_attach_task] container_id: {}",
        unsafe { str::from_utf8_unchecked(container_id) }
    );

    // Stream pid
    let pid = unsafe { ctx.read_at::<i32>(24) }?;

    if let Some(mut entry) = CONTAINER_EVENTS.reserve::<i32>(0) {
        entry.write(pid);
        entry.submit(0);
    }

    debug!(&ctx, "[tracepoint:cgroup:cgroup_attach_task] pid: {}", pid);
    Ok(0)
}

fn parse_dataloc(d: i32) -> (usize, usize) {
    let offset = (d & 0xFFFF) as usize;
    let len = (d >> 16) as usize;
    (offset, len)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
