
let BIN_NAME    = "kexp_2026_05_25.bin";
let ELFLDR_NAME = "elfldr-ps5-1342.elf";

let elfldr_addr = 0n;
let elfldr_size = 0n;
let elfldr_data = null;
let allproc     = 0n;
let master_pipe = null;
let victim_pipe = null;

function find_file(filename) {
    const search = [
        "/mnt/sandbox/" + TITLE_ID + "_000/download0/cache/splash_screen/aHR0cHM6Ly93d3cueW91dHViZS5jb20vdHY=/" + filename,
        "/mnt/sandbox/" + TITLE_ID + "_001/download0/cache/splash_screen/aHR0cHM6Ly93d3cueW91dHViZS5jb20vdHY=/" + filename,
        "/mnt/sandbox/" + TITLE_ID + "_002/download0/cache/splash_screen/aHR0cHM6Ly93d3cueW91dHViZS5jb20vdHY=/" + filename,
    ];
    for (const path of search) {
        if (file_exists(path)) {
            return path;
        }
    }
    return null;
}

async function map_shellcode(bin_data) {
    const size         = BigInt(bin_data.length);
    const aligned_size = (size + BigInt(PAGE_SIZE) - 1n) & ~(BigInt(PAGE_SIZE) - 1n);

    const fd_buf  = malloc(4n);
    const exec_fd = syscall(SYSCALL.jitshm_create, 0n, aligned_size, 0x7n);
    if (exec_fd < 0n) {
        throw new Error("jitshm_create failed: " + toHex(exec_fd));
    }

    const entry_addr = syscall(SYSCALL.mmap, 0n, aligned_size, PROT_RWX, MAP_SHARED, exec_fd, 0n);
    if (entry_addr === 0n || entry_addr === BigInt(-1)) {
        throw new Error("mmap failed (size=0x" + aligned_size.toString(16) + ")");
    }

    write_buffer(entry_addr, bin_data);

    await log("Shellcode mapped @ " + toHex(entry_addr) + " (size: 0x" + aligned_size.toString(16) + ")");
    return entry_addr;
}

async function run_shellcode(entry_addr) {
    const args = malloc(0x28n);
    write32(args + 0x00n, master_pipe[0]);
    write32(args + 0x04n, master_pipe[1]);
    write32(args + 0x08n, victim_pipe[0]);
    write32(args + 0x0Cn, victim_pipe[1]);
    write64(args + 0x10n, allproc);
    write64(args + 0x18n, elfldr_addr);
    write64(args + 0x20n, elfldr_size);

    const thr_handle = malloc(8n);

    await log("Spawning shellcode thread at: " + toHex(entry_addr));

    const ret = call(Thrd_create, thr_handle, entry_addr, args);
    if (ret !== 0n) {
        throw new Error("Thrd_create failed: " + toHex(ret));
    }

    const handle = read64(thr_handle);
    await log("Shellcode thread spawned, handle: " + toHex(handle));

    const ret_val = malloc(8n);
    const join_ret = call(Thrd_join, handle, ret_val);
    if (join_ret !== 0n) {
        throw new Error("Thrd_join failed: " + toHex(join_ret));
    }

    await log("Shellcode returned: " + toHex(read64(ret_val)));
}

async function load_elfldr() {
    const path = find_file(ELFLDR_NAME);
    if (!path) {
        throw new Error("elfldr file not found: " + ELFLDR_NAME);
    }

    elfldr_data = read_file(path);
    elfldr_addr = malloc(BigInt(elfldr_data.length));
    write_buffer(elfldr_addr, elfldr_data);
    elfldr_size = BigInt(elfldr_data.length);

    await log("elfldr @ " + toHex(elfldr_addr) + " size: 0x" + elfldr_size.toString(16));
}

async function load_bin() {
    const path = find_file(BIN_NAME);
    if (!path) {
        throw new Error("kexp bin file not found: " + BIN_NAME);
    }

    const bin_data = read_file(path);
    await log("Bin size: " + bin_data.length + " (0x" + bin_data.length.toString(16) + ")");

    const entry_addr = await map_shellcode(bin_data);
    await run_shellcode(entry_addr);

    await log("=== Shellcode done ===");
}

async function load_aioshellcode(arg_allproc, arg_master_pipe, arg_victim_pipe) {
    check_jailbroken();
    
    allproc     = arg_allproc;
    master_pipe = arg_master_pipe;
    victim_pipe = arg_victim_pipe;

    await log("=== PS5 AIO JB Shellcode by ufm42 ===");
    await load_elfldr();
    await load_bin();
}

async function bin_sender(payload_buf, payload_len) {
    const TARGET_IP   = 0x0100007Fn;             
    const TARGET_PORT = 9021;
    const CHUNK_SIZE  = 64 * 1024;                

    function htons(v) {
        return ((v & 0xFFn) << 8n) | ((v >> 8n) & 0xFFn);
    }

    // ---- socket ------------------------------------------------
    const sock = syscall(SYSCALL.socket, AF_INET, SOCK_STREAM, 0n);
    if (sock === 0xffffffffffffffffn) {
        await log("ERROR: socket() failed");
        return false;
    }

    // ---- sockaddr_in -------------------------------------------
    const addr = malloc(16);
    for (let i = 0; i < 16; i++) write8(addr + BigInt(i), 0n);
    write8 (addr + 1n, AF_INET);
    write16(addr + 2n, htons(BigInt(TARGET_PORT)));
    write32(addr + 4n, TARGET_IP);

    // ---- connect -----------------------------------------------
    const c = syscall(SYSCALL.connect, sock, addr, 16n);                                      // no longer needed
    if (c === 0xffffffffffffffffn) {
        syscall(SYSCALL.close, sock);
        await log("ERROR: connect() failed");
        return false;
    }
    await log("Connected!");

    // ---- chunked send -----------------------------------------
    let offset = 0n;
    while (offset < BigInt(payload_len)) {
        const remaining = BigInt(payload_len) - offset;
        const chunk     = remaining < BigInt(CHUNK_SIZE) ? remaining : BigInt(CHUNK_SIZE);

        const sent = syscall(SYSCALL.write, sock, payload_buf + offset, chunk);
        if (sent <= 0n) {
            syscall(SYSCALL.close, sock);
            await log("ERROR: " + sent);
            return false;
        }
        offset += sent;
    }

    syscall(SYSCALL.close, sock);
    await log("Sent " + payload_len + " bytes successfully");
    return true;
}

async function autoload() {
    const INTERNAL          = "/data/ps5-linux-loader.elf";
    const PAYLOAD_NAME      = "ps5-linux-loader.elf";
    const PAYLOAD_MAX       = 5 * 1024 * 1024;
    const payload_download0_path = "/mnt/sandbox/" + get_title_id() +
                                   "_000/download0/cache/splash_screen/" +
                                   "aHR0cHM6Ly93d3cueW91dHViZS5jb20vdHY=/ps5-linux-loader.elf";

    // usb check                            
    const usb_paths = [];
    for (let i = 0; i <= 7; i++) usb_paths.push(`/mnt/usb${i}/${PAYLOAD_NAME}`);
    let usb_path = null;
    for (const p of usb_paths) if (file_exists(p)) { usb_path = p; break; }
    // either usb and internal not exist
    if (!usb_path && !file_exists(INTERNAL)) {
        await log("[-] payload not found in usb & internal storage!");
        send_notification("payload not found, executing default payload at download0");
        // check at download0
        if (!file_exists(payload_download0_path)) {
            await log("[-] fallback payload missing!");
            send_notification("fallback payload missing!");
            return;
        }
        // copy to internal
        const ok = await copy_binary_file(payload_download0_path, INTERNAL);
        if (!ok) return;                
    }
    else if (usb_path) {
        // copy new payload from usb
        const ok = await copy_binary_file(usb_path, INTERNAL);
        if (!ok) return;
    } else {
        await log("using internal payload: " + INTERNAL);
    }
    // sent payload
    const ab = await read_file(INTERNAL);
    const len = ab.byteLength;
    if (len === 0 || len > PAYLOAD_MAX) throw new Error("size check failed");

    const ptr = arrayBufferToBigInt(ab);
    const ok = await bin_sender(ptr, len);        
    if (ok) send_notification("Payload loaded!\nClosing Y2JB...");
}
