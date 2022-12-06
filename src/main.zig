const std = @import("std");
const builtin = @import("builtin");

const c = @cImport(@cInclude("pcap/pcap.h"));

const B2XTOError = error{
    ConfigInvalid,
    ConfigMissing,
    ConfigReadFailed,
    WorkerCapCrashed,
    WorkerScriptCrashed,
    ArgumentError,
    ArgumentMissing,
};

const IPv4Hdr = extern struct {
    ver_ihl: u8 align(1),
    dscp_ecn: u8 align(1),
    len_tot: u16 align(1),
    id: u16 align(1),
    flag_frag_offset: u16 align(1),
    ttl: u8 align(1),
    protocol: u8 align(1),
    hdr_checksum: u16 align(1),
    ip_src: u32 align(1),
    ip_dst: u32 align(1),
};
const IPv6Hdr = extern struct {
    ver_traffic_flow: u32 align(1),
    data_len: u16 align(1),
    hdr_next: u8 align(1),
    hop_limit: u8 align(1),
    ip_src: u128 align(1),
    ip_dst: u128 align(1),
};
const EthHdr = extern struct {
    mac_dst: [6]u8 align(1),
    mac_src: [6]u8 align(1),
    eth_type: u16 align(1),
};
const TCPUDPHdr = extern struct {
    port_src: u16 align(1),
    port_dst: u16 align(1),
};

const AppConfig = struct {
    name_len: u8,
    script_start_len: u8,
    script_stop_len: u8,
    port_tcp_len: u8,
    port_udp_len: u8,

    name: [64]u8,
    idle: u16,
    script_start: [128]u8,
    script_stop: [128]u8,
    port_tcp: [64]u16,
    port_udp: [64]u16,

    fn log(self: AppConfig, writer: std.fs.File.Writer) !void {
        try writer.print("[AppConfig] name='{s}' script_start='{s}' script_stop='{s}' port_udp={any} port_tcp={any}\n", .{
            self.name[0..self.name_len],
            self.script_start[0..self.script_start_len],
            self.script_stop[0..self.script_stop_len],
            self.port_tcp[0..self.port_tcp_len],
            self.port_udp[0..self.port_udp_len],
        });
    }
};

const AppPort = struct {
    port: []u16, // Sorted list of ports.
    app: []u8, // App index corresponding to each port.

    fn free(self: AppPort, allocator: std.mem.Allocator) void {
        allocator.free(self.port);
        allocator.free(self.app);
    }
};

const Activity = struct {
    tcp: AppPort,
    udp: AppPort,
    time: []@TypeOf(std.time.timestamp()), // Timestamps corresponding to each app.
    idle: []u16, // The idle time per app.
    event_wakeup_stopped: std.Thread.ResetEvent,

    fn free(self: Activity, allocator: std.mem.Allocator) void {
        self.tcp.free(allocator);
        self.udp.free(allocator);
        allocator.free(self.time);
        allocator.free(self.idle);
    }

    fn log(self: Activity, writer: anytype) !void {
        try writer.print("\n[Activity] ", .{});
        for (self.time) |_, i| {
            try writer.print("({}:{}) ", .{ i, self.time[i] });
        }
    }
};

const ActivityUpdate = struct {
    changed: bool, // If activity of any app has changed?
    stopped: bool, // If activity of app changed, is that app not running right now?
};

const Status = enum {
    Started,
    Stopped,
};

const Context = struct {
    phy: []const u8,
    arg: []const u8,
    activity: *Activity, // Each item holds the most recent activity timestamp for an app.

    status: []Status,

    config: []AppConfig,
    allocator: std.mem.Allocator,
};

var pcap_buf_err: [c.PCAP_ERRBUF_SIZE]u8 = undefined;
var pcap_buf_pkt: [pcap_buf_pkt_siz]u8 = undefined;

const pcap_buf_pkt_siz: u16 = 4096;
const eth_hdr_len: u8 = @sizeOf(EthHdr);
const ipv4_hdr_len_min: u8 = @sizeOf(IPv4Hdr);
const ipv4_hdr_len_max: u8 = @sizeOf(IPv4Hdr) + 15 * 4; // Including extra length described by IHL.
const ipv6_hdr_len: u8 = @sizeOf(IPv6Hdr);
const tcpudp_hdr_len: u8 = @sizeOf(TCPUDPHdr); // Only ports.
const cap_len: u8 = eth_hdr_len + @max(ipv4_hdr_len_max, ipv6_hdr_len) + tcpudp_hdr_len;

fn portLessThan(_: u8, lhs: u16, rhs: u16) bool {
    return lhs < rhs;
}

fn portCompare(_: u8, lhs: u16, rhs: u16) std.math.Order {
    if (lhs < rhs) {
        return std.math.Order.lt;
    } else if (lhs > rhs) {
        return std.math.Order.gt;
    } else {
        return std.math.Order.eq;
    }
}

fn activityUpdate(context: *Context, comptime port_type: []const u8, time_now: i64, port_src: u16, port_dst: u16) ActivityUpdate {
    const context_search: u8 = 0; // Unused but need to pass it as parameter.
    var changed: bool = false;
    var stopped: bool = false;

    const port_src_idx = std.sort.binarySearch(@TypeOf(@field(context.activity, port_type).port[0]), port_src, @field(context.activity, port_type).port, context_search, portCompare);
    const port_dst_idx = std.sort.binarySearch(@TypeOf(@field(context.activity, port_type).port[0]), port_dst, @field(context.activity, port_type).port, context_search, portCompare);

    const port_idx_opt_arr = [2]?usize{ port_src_idx, port_dst_idx };
    for (port_idx_opt_arr) |port_idx_opt| {
        if (port_idx_opt != null) {
            const app_idx = @field(context.activity, port_type).app[port_idx_opt.?];
            context.activity.time[app_idx] = time_now;
            stopped = stopped or (context.status[app_idx] == Status.Stopped);
            changed = true;
        }
    }

    return ActivityUpdate{ .changed = changed, .stopped = stopped };
}

fn mainWorkerCap(context: *Context) !void {
    const stdout = std.io.getStdOut().writer();
    const pkt_writer = if (builtin.mode == std.builtin.Mode.Debug) stdout else std.io.null_writer;

    const pcap_init_success: c_int = c.pcap_init(c.PCAP_CHAR_ENC_UTF_8, &pcap_buf_err);
    if (pcap_init_success != 0) {
        pcap_buf_err[c.PCAP_ERRBUF_SIZE - 1] = 0;
        try stdout.print("[CAP] error='Failed to init pcap: ret={}, err='{s}'.'\n", .{ pcap_init_success, pcap_buf_err });
        return B2XTOError.WorkerCapCrashed;
    }

    const pcap_handle: *c.pcap_t = c.pcap_create(@ptrCast([*c]const u8, context.phy), &pcap_buf_err) orelse {
        pcap_buf_err[c.PCAP_ERRBUF_SIZE - 1] = 0;
        try stdout.print("[CAP] error='Failed to create pcap handle: err='{s}'.'\n", .{pcap_buf_err});
        return B2XTOError.WorkerCapCrashed;
    };
    defer c.pcap_close(pcap_handle);

    // Configure the handle.
    {
        // Capture IPv6 header followed by the TCP or UDP port numbers.
        const pcap_set_snaplen_success: c_int = c.pcap_set_snaplen(pcap_handle, cap_len);
        // Disable promiscuous mode.
        const pcap_set_promisc_success: c_int = c.pcap_set_promisc(pcap_handle, 0);
        // Disable monitor mode.
        const pcap_set_rfmon_success: c_int = c.pcap_set_rfmon(pcap_handle, 0);
        // Set the packet buffer timeout to 1 second, i.e. receive for 1 second (1000 milliseconds) before returning packets (if any).
        const pcap_set_timeout_success: c_int = c.pcap_set_timeout(pcap_handle, 1000);
        // Disable immediate mode.
        const pcap_set_immediate_mode_success: c_int = c.pcap_set_immediate_mode(pcap_handle, 0);
        // Specify buffer size of the provided buffer.
        const pcap_set_buffer_size_success: c_int = c.pcap_set_buffer_size(pcap_handle, pcap_buf_pkt_siz);
        // Not changing the timestamp format. Keeping it default.

        if (pcap_set_snaplen_success != 0 or
            pcap_set_promisc_success != 0 or
            pcap_set_rfmon_success != 0 or
            pcap_set_timeout_success != 0 or
            pcap_set_immediate_mode_success != 0 or
            pcap_set_buffer_size_success != 0)
        {
            pcap_buf_err[c.PCAP_ERRBUF_SIZE - 1] = 0;
            try stdout.print("[CAP] error='Failed to configure pcap handle: snaplen={}, promisc={}, rfmon={}, timeout={}, immediate={}, bufsiz={}.'\n", .{
                pcap_set_snaplen_success,
                pcap_set_promisc_success,
                pcap_set_rfmon_success,
                pcap_set_timeout_success,
                pcap_set_immediate_mode_success,
                pcap_set_buffer_size_success,
            });
            return B2XTOError.WorkerCapCrashed;
        }
    }

    const pcap_activate_success: c_int = c.pcap_activate(pcap_handle);
    if (pcap_activate_success != 0) {
        pcap_buf_err[c.PCAP_ERRBUF_SIZE - 1] = 0;
        try stdout.print("[CAP] error='Failed to activate pcap handle: ret={}, err='{s}'.'\n", .{
            pcap_activate_success,
            pcap_buf_err,
        });
        return B2XTOError.WorkerCapCrashed;
    }

    try stdout.print("[CAP] info='Starting packet capture.'\n", .{});
    while (true) {
        try pkt_writer.print("\n", .{});

        var pkt_hdr: [*c]c.pcap_pkthdr = undefined;
        var pkt_data: [*c]const u8 = undefined;
        const pcap_next_ex_success: c_int = c.pcap_next_ex(pcap_handle, &pkt_hdr, &pkt_data);
        switch (pcap_next_ex_success) {
            0 => {
                // Timed out without getting a packet.
                continue;
            },
            1 => {
                // Got whole packet.
            },
            else => {
                pcap_buf_err[c.PCAP_ERRBUF_SIZE - 1] = 0;
                try stdout.print("[CAP] error='Failed to get next packet from pcap: ret={}, err='{s}'.'\n", .{
                    pcap_next_ex_success,
                    pcap_buf_err,
                });
                return B2XTOError.WorkerCapCrashed;
            },
        }

        // Make sure datalink is ethernet, otherwise drop the packet.
        const datalink_type: c_int = c.pcap_datalink(pcap_handle);
        if (datalink_type != c.DLT_EN10MB) {
            try pkt_writer.print("[CAP] error='Unsupported data-link layer.' ", .{});
            continue;
        }

        try pkt_writer.print("\n[CAP][  PCAP] caplen={} len={} datalink={} ", .{
            pkt_hdr.*.caplen,
            pkt_hdr.*.len,
            datalink_type,
        });

        const ip_ver_len: u8 = 1;
        if (pkt_hdr.*.caplen >= eth_hdr_len + ip_ver_len) {
            try pkt_writer.print("\n[CAP][   ETH] ", .{});

            const ip_ver: u8 = pkt_data[eth_hdr_len] >> 4;
            const pkt_ipv4_len_min: u8 = eth_hdr_len + ipv4_hdr_len_min;
            const pkt_ipv6_len: u8 = eth_hdr_len + ipv6_hdr_len;
            const cond_ipv4: bool = ip_ver == 4 and pkt_hdr.*.caplen >= pkt_ipv4_len_min;
            const cond_ipv6: bool = ip_ver == 6 and pkt_hdr.*.caplen >= pkt_ipv6_len;

            var transport_proto: u8 = undefined;
            var transport_offset: u8 = undefined;
            if (cond_ipv4) {
                try pkt_writer.print("\n[CAP][  IPv4] ", .{});
                const ip_ihl: u8 = pkt_data[eth_hdr_len] & 0x0F;
                try pkt_writer.print("ihl={} ", .{ip_ihl});
                if (ip_ihl < 5 or ip_ihl > 15) {
                    try pkt_writer.print("error='Invalid IHL.' ", .{});
                    continue;
                }

                const pkt_ipv4_len: u8 = pkt_ipv4_len_min + ((ip_ihl - 5) * 4);
                if (pkt_hdr.*.caplen < pkt_ipv4_len) {
                    try pkt_writer.print("error='Options don't fit.' ", .{});
                    continue;
                }

                transport_proto = pkt_data[eth_hdr_len + @offsetOf(IPv4Hdr, "protocol")];
                transport_offset = pkt_ipv4_len;
            } else if (cond_ipv6) {
                try pkt_writer.print("\n[CAP][  IPv6] ", .{});

                transport_proto = pkt_data[eth_hdr_len + @offsetOf(IPv6Hdr, "hdr_next")];
                transport_offset = pkt_ipv6_len;
            }

            try pkt_writer.print("transport_proto={} transport_offset={} ", .{ transport_proto, transport_offset });
            // TCP or UDP
            const transport_proto_tcp: u8 = 6;
            const transport_proto_udp: u8 = 17;
            if (transport_proto == transport_proto_tcp or transport_proto == transport_proto_udp) {
                try pkt_writer.print("\n[CAP][TCPUDP] ", .{});
                const offset_port_src: u8 = transport_offset + @offsetOf(TCPUDPHdr, "port_src");
                const offset_port_dst: u8 = transport_offset + @offsetOf(TCPUDPHdr, "port_dst");
                const port_src: u16 = std.mem.toNative(u16, std.mem.bytesToValue(u16, @ptrCast(*const [2]u8, pkt_data[offset_port_src .. offset_port_src + 1])), std.builtin.Endian.Big);
                const port_dst: u16 = std.mem.toNative(u16, std.mem.bytesToValue(u16, @ptrCast(*const [2]u8, pkt_data[offset_port_dst .. offset_port_dst + 1])), std.builtin.Endian.Big);
                try pkt_writer.print("port_src={} port_dst={} ", .{ port_src, port_dst });

                const timestamp: @TypeOf(std.time.timestamp()) = std.time.timestamp();

                var activity_update: ActivityUpdate = undefined;
                if (transport_proto == transport_proto_tcp) {
                    activity_update = activityUpdate(context, "tcp", timestamp, port_src, port_dst);
                } else {
                    activity_update = activityUpdate(context, "udp", timestamp, port_src, port_dst);
                }

                if (activity_update.changed) {
                    if (activity_update.stopped) {
                        context.activity.event_wakeup_stopped.set();
                        try stdout.print("\n[CAP]", .{});
                        try context.activity.log(stdout);
                    } else {
                        try pkt_writer.print("\n[CAP]", .{});
                        try context.activity.log(pkt_writer);
                    }
                }
            } else {
                try pkt_writer.print("error='Unsupported transport layer.' ", .{});
                continue;
            }
        } else {
            try pkt_writer.print("error='Packet too short.' ", .{});
            continue;
        }
    }
}

fn configLoad(allocator: std.mem.Allocator, path: []const u8) ![]AppConfig {
    const cwd_dir = std.fs.cwd();
    var config_file = cwd_dir.openFile(path, .{}) catch return B2XTOError.ConfigMissing;
    defer config_file.close();

    const config_data: []u8 = config_file.readToEndAlloc(allocator, 16384) catch return B2XTOError.ConfigReadFailed;
    defer allocator.free(config_data);

    var config_parser: std.json.Parser = std.json.Parser.init(allocator, false);
    defer config_parser.deinit();

    var config_root_raw: std.json.ValueTree = config_parser.parse(config_data) catch return B2XTOError.ConfigInvalid;
    defer config_root_raw.deinit();

    var config: []AppConfig = undefined;
    switch (config_root_raw.root) {
        .Array => |config_root_arr| {
            config = try allocator.alloc(AppConfig, config_root_arr.items.len);
            errdefer allocator.free(config);

            for (config_root_arr.items) |config_obj_raw, i| {
                switch (config_obj_raw) {
                    .Object => |config_obj| {
                        const config_name_str_raw: std.json.Value = config_obj.get("name") orelse return B2XTOError.ConfigInvalid;
                        const config_port_obj_raw: std.json.Value = config_obj.get("port") orelse return B2XTOError.ConfigInvalid;
                        const config_idle_int_raw: std.json.Value = config_obj.get("idle") orelse return B2XTOError.ConfigInvalid;
                        const config_script_obj_raw: std.json.Value = config_obj.get("script") orelse return B2XTOError.ConfigInvalid;

                        switch (config_name_str_raw) {
                            .String => |config_name_str| {
                                std.mem.copy(@TypeOf(config[i].name[0]), &config[i].name, config_name_str);
                                if (config_name_str.len < 0 or config_name_str.len > 1 << @bitSizeOf(@TypeOf(config[i].name_len))) {
                                    return B2XTOError.ConfigInvalid;
                                }
                                config[i].name_len = @intCast(@TypeOf(config[i].name_len), config_name_str.len);
                            },
                            else => return B2XTOError.ConfigInvalid,
                        }
                        switch (config_port_obj_raw) {
                            .Object => |config_port_obj| {
                                const config_port_tcp_arr_raw: std.json.Value = config_port_obj.get("tcp") orelse return B2XTOError.ConfigInvalid;
                                const config_port_udp_arr_raw: std.json.Value = config_port_obj.get("udp") orelse return B2XTOError.ConfigInvalid;

                                switch (config_port_tcp_arr_raw) {
                                    .Array => |config_port_tcp_arr| {
                                        if (config_port_tcp_arr.items.len > @sizeOf(@TypeOf(config[i].port_tcp)) / @sizeOf(@TypeOf(config[i].port_tcp[0]))) {
                                            return B2XTOError.ConfigInvalid;
                                        }
                                        if (config_port_tcp_arr.items.len > 1 << @bitSizeOf(@TypeOf(config[i].port_tcp_len))) {
                                            return B2XTOError.ConfigInvalid;
                                        }
                                        config[i].port_tcp_len = @intCast(@TypeOf(config[i].port_tcp_len), config_port_tcp_arr.items.len);

                                        for (config_port_tcp_arr.items) |config_port_tcp_raw, j| {
                                            switch (config_port_tcp_raw) {
                                                .Integer => |config_port_tcp| {
                                                    if (config_port_tcp < 0 or config_port_tcp > (1 << @bitSizeOf(@TypeOf(config[i].port_tcp[j])))) {
                                                        return B2XTOError.ConfigInvalid;
                                                    }
                                                    config[i].port_tcp[j] = @intCast(@TypeOf(config[i].port_tcp[j]), config_port_tcp);
                                                },
                                                .Null => {}, // Do nothing when no TCP ports
                                                else => return B2XTOError.ConfigInvalid,
                                            }
                                        }
                                    },
                                    else => return B2XTOError.ConfigInvalid,
                                }

                                switch (config_port_udp_arr_raw) {
                                    .Array => |config_port_udp_arr| {
                                        if (@sizeOf(@TypeOf(config_port_udp_arr.items.len)) > @sizeOf(@TypeOf(config[i].port_udp)) / @sizeOf(@TypeOf(config[i].port_udp[0]))) {
                                            return B2XTOError.ConfigInvalid;
                                        }
                                        if (config_port_udp_arr.items.len > 1 << @bitSizeOf(@TypeOf(config[i].port_udp_len))) {
                                            return B2XTOError.ConfigInvalid;
                                        }
                                        config[i].port_udp_len = @intCast(@TypeOf(config[i].port_udp_len), config_port_udp_arr.items.len);

                                        for (config_port_udp_arr.items) |config_port_udp_raw, j| {
                                            switch (config_port_udp_raw) {
                                                .Integer => |config_port_udp| {
                                                    if (config_port_udp < 0 or config_port_udp > 1 << @bitSizeOf(@TypeOf(config[i].port_udp[j]))) {
                                                        return B2XTOError.ConfigInvalid;
                                                    }
                                                    config[i].port_udp[j] = @intCast(@TypeOf(config[i].port_udp[j]), config_port_udp);
                                                },
                                                .Null => {}, // Do nothing when no UDP ports
                                                else => return B2XTOError.ConfigInvalid,
                                            }
                                        }
                                    },
                                    else => return B2XTOError.ConfigInvalid,
                                }
                            },
                            else => return B2XTOError.ConfigInvalid,
                        }

                        switch (config_idle_int_raw) {
                            .Integer => |config_idle_int| {
                                if (config_idle_int < 0 or config_idle_int > (1 << @bitSizeOf(@TypeOf(config[i].idle)))) {
                                    return B2XTOError.ConfigInvalid;
                                }
                                config[i].idle = @intCast(@TypeOf(config[i].idle), config_idle_int);
                            },
                            else => return B2XTOError.ConfigInvalid,
                        }
                        switch (config_script_obj_raw) {
                            .Object => |config_script_obj| {
                                const config_script_start_str_raw: std.json.Value = config_script_obj.get("start") orelse return B2XTOError.ConfigInvalid;
                                const config_script_stop_str_raw: std.json.Value = config_script_obj.get("stop") orelse return B2XTOError.ConfigInvalid;

                                switch (config_script_start_str_raw) {
                                    .String => |config_script_start_str| {
                                        std.mem.copy(@TypeOf(config[i].script_start[0]), &config[i].script_start, config_script_start_str);
                                        if (config_script_start_str.len > 1 << @bitSizeOf(@TypeOf(config[i].script_start_len))) {
                                            return B2XTOError.ConfigInvalid;
                                        }
                                        config[i].script_start_len = @intCast(@TypeOf(config[i].script_start_len), config_script_start_str.len);
                                    },
                                    else => return B2XTOError.ConfigInvalid,
                                }
                                switch (config_script_stop_str_raw) {
                                    .String => |config_script_stop_str| {
                                        std.mem.copy(@TypeOf(config[i].script_stop[0]), &config[i].script_stop, config_script_stop_str);
                                        if (config_script_stop_str.len > 1 << @bitSizeOf(@TypeOf(config[i].script_stop_len))) {
                                            return B2XTOError.ConfigInvalid;
                                        }
                                        config[i].script_stop_len = @intCast(@TypeOf(config[i].script_stop_len), config_script_stop_str.len);
                                    },
                                    else => return B2XTOError.ConfigInvalid,
                                }
                            },
                            else => return B2XTOError.ConfigInvalid,
                        }
                    },
                    else => return B2XTOError.ConfigInvalid,
                }
            }
        },
        else => return B2XTOError.ConfigInvalid,
    }
    return config;
}

fn activityCreate(allocator: std.mem.Allocator, config: []const AppConfig) !*Activity {
    var port_tcp_count: u8 = 0;
    var port_udp_count: u8 = 0;
    if (config.len > 1 << @bitSizeOf(u8)) {
        return B2XTOError.ConfigInvalid;
    }
    const config_count: u8 = @intCast(u8, config.len);

    for (config) |config_i, i| {
        if (port_tcp_count + config_i.port_tcp_len > 1 << @bitSizeOf(@TypeOf(port_tcp_count))) {
            return B2XTOError.ConfigInvalid;
        }
        port_tcp_count += config_i.port_tcp_len;

        if (port_udp_count + config_i.port_udp_len > 1 << @bitSizeOf(@TypeOf(port_udp_count))) {
            return B2XTOError.ConfigInvalid;
        }
        port_udp_count += config_i.port_udp_len;

        std.debug.print("[activityCreate] app={} port_tcp_count={} port_udp_count={}\n", .{ i, config_i.port_tcp_len, config_i.port_udp_len });
    }

    std.debug.print("[activityCreate] app=all port_tcp_count={} port_udp_count={}\n", .{ port_tcp_count, port_udp_count });

    const activity: *Activity = try allocator.create(Activity);
    errdefer allocator.destroy(activity);

    // Make sure the wakeup event is reset by default.
    activity.event_wakeup_stopped.reset();

    activity.tcp.port = try allocator.alloc(@TypeOf(activity.tcp.port[0]), port_tcp_count);
    errdefer allocator.free(activity.tcp.port);
    activity.udp.port = try allocator.alloc(@TypeOf(activity.udp.port[0]), port_udp_count);
    errdefer allocator.free(activity.udp.port);

    activity.time = try allocator.alignedAlloc(@TypeOf(activity.time[0]), @alignOf(@TypeOf(activity.time)), config_count);
    errdefer allocator.free(activity.time);
    const timestamp: @TypeOf(std.time.timestamp()) = std.time.timestamp();
    for (activity.time) |_, i| {
        activity.time[i] = timestamp;
    }

    activity.idle = try allocator.alignedAlloc(@TypeOf(activity.idle[0]), @alignOf(@TypeOf(activity.idle)), config_count);
    errdefer allocator.free(activity.idle);
    for (activity.idle) |_, i| {
        activity.idle[i] = config[i].idle;
    }

    activity.tcp.app = try allocator.alloc(@TypeOf(activity.tcp.app[0]), port_tcp_count);
    errdefer allocator.free(activity.tcp.app);
    activity.udp.app = try allocator.alloc(@TypeOf(activity.udp.app[0]), port_udp_count);
    errdefer allocator.free(activity.udp.app);

    var port_tcp_offset: u8 = 0;
    var port_udp_offset: u8 = 0;
    for (config) |config_i| {
        for (config_i.port_tcp[0..config_i.port_tcp_len]) |port_tcp_i| {
            activity.tcp.port[port_tcp_offset] = port_tcp_i;
            port_tcp_offset += 1;
        }
        for (config_i.port_udp[0..config_i.port_udp_len]) |port_udp_i| {
            activity.udp.port[port_udp_offset] = port_udp_i;
            port_udp_offset += 1;
        }
    }

    const context: u8 = 0; // Unused but need to pass something.
    std.sort.insertionSort(@TypeOf(activity.tcp.port[0]), activity.tcp.port, context, portLessThan);
    std.sort.insertionSort(@TypeOf(activity.udp.port[0]), activity.udp.port, context, portLessThan);

    // Check for repeated ports.
    for (activity.tcp.port[0 .. activity.tcp.port.len - 1]) |_, i| {
        if (activity.tcp.port[i] == activity.tcp.port[i + 1]) {
            return B2XTOError.ConfigInvalid;
        }
    }
    for (activity.udp.port[0 .. activity.udp.port.len - 1]) |_, i| {
        if (activity.udp.port[i] == activity.udp.port[i + 1]) {
            return B2XTOError.ConfigInvalid;
        }
    }

    std.debug.print("[activityCreate] tcp.port={any} udp.port={any}\n", .{ activity.tcp.port, activity.udp.port });

    for (config) |config_i, i| {
        for (config_i.port_tcp[0..config_i.port_tcp_len]) |port_tcp| {
            const port_idx = std.sort.binarySearch(@TypeOf(activity.tcp.port[0]), port_tcp, activity.tcp.port, context, portCompare) orelse unreachable;
            std.debug.print("[activityCreate] tcp_search_key={} found_idx={} app={}\n", .{ port_tcp, port_idx, i });
            activity.tcp.app[port_idx] = @intCast(@TypeOf(config_count), i);
        }
        for (config_i.port_udp[0..config_i.port_udp_len]) |port_udp| {
            const port_idx = std.sort.binarySearch(@TypeOf(activity.udp.port[0]), port_udp, activity.udp.port, context, portCompare) orelse unreachable;
            std.debug.print("[activityCreate] udp_search_key={} found_idx={} app={}\n", .{ port_udp, port_idx, i });
            activity.udp.app[port_idx] = @intCast(@TypeOf(config_count), i);
        }
    }

    return activity;
}

fn scriptRun(writer: anytype, allocator: std.mem.Allocator, argv: []const []const u8) !void {
    const script_result: std.ChildProcess.ExecResult = try std.ChildProcess.exec(.{ .allocator = allocator, .argv = argv });

    // No docs for assume that caller should free (only) these buffers.
    defer allocator.free(script_result.stdout);
    defer allocator.free(script_result.stderr);

    try writer.print("[scriptRun] stdout='{s}' stderr='{s}' code={}\n", .{ script_result.stdout, script_result.stderr, script_result.term.Exited });
}

fn mainWorkerScript(context: *Context) !void {
    const stdout = std.io.getStdOut().writer();

    // Make sure the time array is aligned to at least the type of timestamp.
    // This allows us to safely copy the items of the time array atomically.
    const activity_time_type: type = @TypeOf(context.activity.time);
    std.debug.assert(@alignOf(activity_time_type) >= @alignOf(@TypeOf(context.activity.time[0])));

    var argv = [_][]const u8{ "bash", "-c", undefined };

    try stdout.print("[SCRIPT] info='Starting to monitor port activity.'\n", .{});
    while (true) {
        const time_now: @TypeOf(std.time.timestamp()) = std.time.timestamp();
        for (context.activity.time) |_, i| {
            const time_activity = context.activity.time[i];
            const idle = context.activity.idle[i] * 60; // Minutes to seconds.

            switch (context.status[i]) {
                Status.Started => {
                    if (time_activity + idle <= time_now) {
                        try stdout.print("[SCRIPT] info='Stopping app={}.'\n", .{i});
                        argv[2] = context.config[i].script_stop[0..context.config[i].script_stop_len];
                        try stdout.print("[SCRIPT]", .{});
                        try scriptRun(stdout, context.allocator, &argv);
                        context.status[i] = Status.Stopped;
                    }
                },
                Status.Stopped => {
                    if (time_activity + idle > time_now) {
                        try stdout.print("[SCRIPT] info='Starting app={}.'\n", .{i});
                        argv[2] = context.config[i].script_start[0..context.config[i].script_start_len];
                        try stdout.print("[SCRIPT]", .{});
                        try scriptRun(stdout, context.allocator, &argv);
                        context.status[i] = Status.Started;
                    }
                },
            }
        }

        // Wait until the cap thread receives a packet for a stopped app or after 1 minute.
        const ns_1m: u64 = 60000000000;
        context.activity.event_wakeup_stopped.reset();
        context.activity.event_wakeup_stopped.timedWait(ns_1m) catch {}; // Ignore timeout error.
    }
}

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();

    var allocator_gp = std.heap.GeneralPurposeAllocator(.{}){};
    defer std.debug.assert(!allocator_gp.deinit());
    const allocator: std.mem.Allocator = allocator_gp.allocator();

    var arg_iter: std.process.ArgIterator = std.process.argsWithAllocator(allocator) catch return B2XTOError.AllocationError;
    defer arg_iter.deinit();
    if (!arg_iter.skip()) {
        return B2XTOError.ArgumentMissing;
    }
    const arg_phy: []const u8 = arg_iter.next() orelse return B2XTOError.ArgumentMissing;
    const arg_config: []const u8 = arg_iter.next() orelse return B2XTOError.ArgumentMissing;

    const config: []AppConfig = try configLoad(allocator, arg_config);
    defer allocator.free(config);
    try stdout.print("[MAIN] info='Config loaded.'\n", .{});

    for (config) |config_i| {
        try config_i.log(stdout);
    }

    const activity = try activityCreate(allocator, config);
    defer activity.free(allocator);
    defer allocator.destroy(activity);
    try stdout.print("[MAIN] info='Activity created.'\n", .{});

    const status: []Status = try allocator.alloc(Status, config.len);
    defer allocator.free(status);
    for (status) |_, i| {
        status[i] = Status.Stopped;
    }
    try stdout.print("[MAIN] info='Status created.'\n", .{});

    var context = Context{
        .phy = arg_phy,
        .arg = arg_config,
        .activity = activity,
        .status = status,
        .config = config,
        .allocator = allocator,
    };
    const spawn_config_cap: std.Thread.SpawnConfig = std.Thread.SpawnConfig{ .stack_size = 256 };
    const worker_cap: std.Thread = std.Thread.spawn(spawn_config_cap, mainWorkerCap, .{&context}) catch return B2XTOError.WorkerCapCrashed;

    const spawn_config_script: std.Thread.SpawnConfig = std.Thread.SpawnConfig{ .stack_size = 256 };
    const worker_script: std.Thread = std.Thread.spawn(spawn_config_script, mainWorkerScript, .{&context}) catch return B2XTOError.WorkerScriptCrashed;

    worker_cap.join();
    worker_script.join();
}
