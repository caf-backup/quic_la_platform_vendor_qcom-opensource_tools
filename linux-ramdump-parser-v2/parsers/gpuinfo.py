# Copyright (c) 2013-2015, 2020 The Linux Foundation. All rights reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 and
# only version 2 as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

from parser_util import register_parser, RamParser
from print_out import print_out_str
import linux_list
import traceback
import linux_radix_tree

# Global Configurations
ADRENO_DISPATCH_DRAWQUEUE_SIZE = 128
KGSL_PRIORITY_MAX_RB_LEVELS = 4
KGSL_MAX_PWRLEVELS = 10
MAX_CONTEXT_ID = 800


def strhex(x): return str(hex(x))


@register_parser('--print-gpuinfo',
                 'print gpu driver related info', optional=True)
class GpuParser(RamParser):
    def __init__(self, dump):
        super(GpuParser, self).__init__(dump)

        # List of all sub-parsers as (func, info) tuples.
        self.parser_list = [
            (self.parse_kgsl_data, "KGSL"),
            (self.parse_pwrctrl_data, "KGSL Power"),
            (self.parse_rb_inflight_data, "Ringbuffer and Inflight Queues"),
            (self.parse_dispatcher_data, "Dispatcher"),
            (self.parse_mutex_data, "KGSL Mutexes"),
            (self.parse_scratch_memory, "Scratch Memory"),
            (self.parse_memstore_memory, "Memstore"),
            (self.parse_context_data, "Open Contexts"),
            (self.parse_open_process_data, "Open Processes"),
            (self.parse_fence_data, "Fences"),
            (self.parse_open_process_mementry, "Open Process Mementries"),
        ]

        self.rtw = linux_radix_tree.RadixTreeWalker(dump)

    def parse(self):
        self.out = self.ramdump.open_file('gpuinfo.txt')

        for subparser in self.parser_list:
            try:
                self.write(subparser[1].center(90, '-') + '\n')
                subparser[0](self.ramdump)
                self.writeln()
            except Exception:
                print_out_str("GPU info: Parsing failed in "
                              + subparser[0].__name__)
                print_out_str(traceback.format_exc())

    def write(self, string):
        self.out.write(string)

    def writeln(self, string=""):
        self.out.write(string + '\n')

    def print_context_data(self, ctx_addr):
        dump = self.ramdump
        context_id = str(dump.read_structure_field(
            ctx_addr, 'struct kgsl_context', 'id'))

        proc_priv_offset = dump.field_offset('struct kgsl_context',
                                             'proc_priv')
        proc_priv = dump.read_pointer(ctx_addr + proc_priv_offset)
        pid = str(dump.read_structure_field(
            proc_priv, 'struct kgsl_process_private', 'pid'))

        comm_offset = dump.field_offset('struct kgsl_process_private',
                                        'comm')
        comm = str(dump.read_cstring(proc_priv + comm_offset))
        ptr = strhex(ctx_addr)
        format_str = '{0:20} {1:20} {2:20} {3:30}'

    def parse_context_data(self, dump):
        format_str = '{0:20} {1:20} {2:20} {3:30}'
        self.writeln(format_str.format("CONTEXT ID", "PID", "PROCESS_NAME",
                                       "ADRENO_DRAW_CONTEXT_PTR"))
        context_idr = dump.read('device_3d0.dev.context_idr')
        self.rtw.walk_radix_tree(context_idr, self.print_context_data)

    def parse_open_process_mementry(self, dump):
        self.writeln('WARNING: Some nodes can be corrupted one, Ignore them.')
        format_str = '{0:20} {1:20} {2:20} {3:30} {4:20} {5:20}'
        print_str = format_str.format("PID", "PNAME", "INDEX", "MEMENTRY_NODE",
                                      "MEMDESC_SIZE", "GPUADDR")
        self.writeln(print_str)

        node_addr = dump.read('kgsl_driver.process_list.next')
        list_elem_offset = dump.field_offset(
            'struct kgsl_process_private', 'list')
        open_process_list_walker = linux_list.ListWalker(
            dump, node_addr, list_elem_offset)
        open_process_list_walker.walk(
            node_addr, self.__walk_process_mementry, dump, format_str)

    def __walk_process_mementry(self, kgsl_private_base_addr, dump,
                              format_string):
        pid = dump.read_structure_field(kgsl_private_base_addr,
                                        'struct kgsl_process_private', 'pid')

        comm_offset = dump.field_offset('struct kgsl_process_private', 'comm')
        pname = str(dump.read_cstring(kgsl_private_base_addr + comm_offset))

        mem_idr_offset = dump.field_offset('struct kgsl_process_private',
                                           'mem_idr')
        mementry_rt = kgsl_private_base_addr + mem_idr_offset

        try:
            self.rtw.walk_radix_tree(mementry_rt, self.__print_mementry_info,
                                     pid, pname, [True])
        except Exception:
            self.writeln("Ramdump has a corrupted mementry: pid: " + str(pid) +
                         " comm: " + pname)

    def __print_mementry_info(self, mementry_addr, pid, pname, print_header):
        dump = self.ramdump
        format_string = '{0:20} {1:20} {2:20} {3:30} {4:20} {5:20}'
        memdesc_offset = dump.field_offset('struct kgsl_mem_entry', 'memdesc')
        kgsl_memdesc_address = mementry_addr + memdesc_offset

        size = dump.read_structure_field(kgsl_memdesc_address,
                                         'struct kgsl_memdesc', 'size')
        gpuaddr = dump.read_structure_field(kgsl_memdesc_address,
                                            'struct kgsl_memdesc',
                                            'gpuaddr')
        idr_id = dump.read_structure_field(mementry_addr,
                                           'struct kgsl_mem_entry', 'id')

        if print_header[0] == True:
            self.writeln(format_string.format(str(pid), pname, hex(idr_id),
                                         hex(kgsl_memdesc_address),
                                         str(size), hex(gpuaddr)))
            # Set to False to skip printing pid and pname for the rest
            print_header[0] = False
        else:
            self.writeln(format_string.format("", "", hex(idr_id),
                                         hex(kgsl_memdesc_address),
                                         str(size), hex(gpuaddr)))

    def parse_kgsl_data(self, dump):
        open_count = dump.read('device_3d0.dev.open_count')
        state = dump.read('device_3d0.dev.state')
        requested_state = dump.read('device_3d0.dev.requested_state')
        reg_phys = dump.read('device_3d0.dev.reg_phys')
        reg_virt = dump.read('device_3d0.dev.reg_virt')
        ft_policy = dump.read('device_3d0.ft_policy')
        long_ib_detect = dump.read('device_3d0.long_ib_detect')
        pwrctrl_flag = dump.read('device_3d0.pwrctrl_flag')
        speed_bin = dump.read('device_3d0.speed_bin')
        cur_rb = dump.read('device_3d0.cur_rb')
        next_rb = dump.read('device_3d0.next_rb')
        prev_rb = dump.read('device_3d0.prev_rb')
        cur_rb_id = dump.read_structure_field(cur_rb,
                                              'struct adreno_ringbuffer', 'id')
        next_rb_id = dump.read_structure_field(next_rb,
                                              'struct adreno_ringbuffer', 'id')
        prev_rb_id = dump.read_structure_field(prev_rb,
                                              'struct adreno_ringbuffer', 'id')

        self.writeln('open_count: ' + str(open_count))
        self.writeln('state: ' + str(state))
        self.writeln('requested_state: ' + str(requested_state))
        self.writeln('reg_phys: ' + strhex(reg_phys))
        self.writeln('reg_virt: ' + strhex(reg_virt))
        self.writeln('ft_policy: ' + str(ft_policy))
        self.writeln('long_ib_detect: ' + str(long_ib_detect))
        self.writeln('pwrctrl_flag: ' + strhex(pwrctrl_flag))
        self.writeln('speed_bin: ' + str(speed_bin))
        self.writeln('cur_rb: ' + strhex(cur_rb))
        self.writeln('cur_rb_id: ' + str(cur_rb_id))
        self.writeln('next_rb: ' + strhex(next_rb))
        self.writeln('next_rb_id: ' + str(next_rb_id))
        self.writeln('prev_rb_ptr: ' + strhex(prev_rb))
        self.writeln('prev_rb_id: ' + str(prev_rb_id))

    def parse_dispatcher_data(self, dump):
        inflight = dump.read('device_3d0.dispatcher.inflight')
        pending_address = dump.read('device_3d0.dispatcher.pending')
        fault_counter = dump.read('device_3d0.dispatcher.fault')

        self.writeln('inflight: ' + str(inflight))
        self.writeln('pending address: '
                     + strhex(pending_address))
        self.writeln('fault_counter: ' + str(fault_counter))

    def parse_rb_inflight_data(self, dump):
        ringbuffers_base_address = dump.read('device_3d0.ringbuffers')
        ringbuffers = []
        inflight_queue_result = []

        for i in range(0, KGSL_PRIORITY_MAX_RB_LEVELS):
            ringbuffers_temp = []
            rb_array_index_addr = dump.array_index(
                ringbuffers_base_address, "struct adreno_ringbuffer", i)
            wptr = dump.read_structure_field(rb_array_index_addr,
                                             'struct adreno_ringbuffer',
                                             'wptr')
            _wptr = dump.read_structure_field(rb_array_index_addr,
                                              'struct adreno_ringbuffer',
                                              '_wptr')
            last_wptr = dump.read_structure_field(
                        rb_array_index_addr,
                        'struct adreno_ringbuffer', 'last_wptr')
            id = dump.read_structure_field(rb_array_index_addr,
                                           'struct adreno_ringbuffer', 'id')
            flags = dump.read_structure_field(rb_array_index_addr,
                                              'struct adreno_ringbuffer',
                                              'flags')

            drawctxt_active = dump.read_structure_field(
                rb_array_index_addr, 'struct adreno_ringbuffer',
                'drawctxt_active')

            if drawctxt_active != 0:
                kgsl_context_id = dump.read_structure_field(
                    drawctxt_active, 'struct kgsl_context', 'id')
                proc_priv_val = dump.read_structure_field(
                    drawctxt_active, 'struct kgsl_context', 'proc_priv')
                if proc_priv_val != 0:
                    comm_offset = dump.field_offset(
                        'struct kgsl_process_private', 'comm')
                    process_name = dump.read_cstring(proc_priv_val
                                                     + comm_offset)
                else:
                    process_name = "NULL"
            else:
                kgsl_context_id = "NULL"
                process_name = "NULL"

            dispatch_q_address = rb_array_index_addr + \
                dump.field_offset('struct adreno_ringbuffer', 'dispatch_q')
            inflight = dump.read_structure_field(
                dispatch_q_address, 'struct adreno_dispatcher_drawqueue',
                'inflight')
            cmd_q_address = dispatch_q_address + dump.field_offset(
                'struct adreno_dispatcher_drawqueue', 'cmd_q')
            head = dump.read_structure_field(
                dispatch_q_address, 'struct adreno_dispatcher_drawqueue',
                'head')
            tail = dump.read_structure_field(
                dispatch_q_address, 'struct adreno_dispatcher_drawqueue',
                'tail')

            dispatcher_result = []
            while head is not tail:
                dispatcher_temp = []
                inflight_queue_index_address = dump.array_index(
                    cmd_q_address, 'struct kgsl_drawobj_cmd *', head)
                inflight_queue_index_value = dump.read_word(
                    inflight_queue_index_address)

                if inflight_queue_index_value != 0:
                    global_ts = dump.read_structure_field(
                        inflight_queue_index_value,
                        'struct kgsl_drawobj_cmd', 'global_ts')
                    fault_policy = dump.read_structure_field(
                        inflight_queue_index_value,
                        'struct kgsl_drawobj_cmd', 'fault_policy')
                    fault_recovery = dump.read_structure_field(
                        inflight_queue_index_value,
                        'struct kgsl_drawobj_cmd', 'fault_recovery')

                    base_address = inflight_queue_index_value + \
                        dump.field_offset('struct kgsl_drawobj_cmd', 'base')
                    drawobj_type = dump.read_structure_field(
                        base_address, 'struct kgsl_drawobj', 'type')
                    timestamp = dump.read_structure_field(
                        base_address, 'struct kgsl_drawobj', 'timestamp')
                    flags = dump.read_structure_field(
                        base_address, 'struct kgsl_drawobj', 'flags')
                    context_pointer = dump.read_pointer(dump.field_offset(
                        'struct kgsl_drawobj', 'context')+base_address)
                    context_id = dump.read_structure_field(
                        context_pointer, 'struct kgsl_context', 'id')
                    proc_priv = dump.read_structure_field(
                        context_pointer, 'struct kgsl_context', 'proc_priv')
                    pid = dump.read_structure_field(
                        proc_priv, 'struct kgsl_process_private', 'pid')
                else:
                    global_ts = 'NULL'
                    fault_policy = 'NULL'
                    fault_recovery = 'NULL'
                    drawobj_type = 'NULL'
                    timestamp = 'NULL'
                    flags = 'NULL'
                    context_id = 'NULL'
                    pid = 'NULL'

                dispatcher_temp.extend([i, global_ts, fault_policy,
                                        fault_recovery, drawobj_type,
                                        timestamp, flags, context_id, pid])

                dispatcher_result.append(dispatcher_temp)
                head = (head + 1) % ADRENO_DISPATCH_DRAWQUEUE_SIZE

            inflight_queue_result.append(dispatcher_result)

            ringbuffers_temp.append(rb_array_index_addr)
            ringbuffers_temp.append(wptr)
            ringbuffers_temp.append(_wptr)
            ringbuffers_temp.append(last_wptr)
            ringbuffers_temp.append(id)
            ringbuffers_temp.append(flags)
            ringbuffers_temp.append(kgsl_context_id)
            ringbuffers_temp.append(process_name)
            ringbuffers_temp.append(inflight)
            ringbuffers.append(ringbuffers_temp)

        format_str = "{0:20} {1:20} {2:20} {3:20} " \
            "{4:20} {5:20} {6:20} {7:20} {8:20}"

        print_str = format_str.format('INDEX', 'WPTR', '_WPTR', 'LAST_WPTR',
                                      'ID', 'FLAGS', 'KGSL_CONTEXT_ID',
                                      'PROCESS_NAME', 'INFLIGHT')
        self.writeln(print_str)

        index = 0
        for rb in ringbuffers:
            print_str = format_str.format(str(index), str(rb[1]), str(rb[2]),
                                          str(rb[3]), str(rb[4]), str(rb[5]),
                                          str(rb[6]), str(rb[7]), str(rb[8]))
            self.writeln(print_str)
            index = index + 1

        self.writeln()
        self.writeln("Inflight Queues:")

        format_str = "{0:20} {1:20} {2:20} {3:20} {4:20} " \
            "{5:20} {6:20} {7:20} {8:20}"

        print_str = format_str.format("ringbuffer", "global_ts",
                                      "fault_policy", "fault_recovery",
                                      "type", "timestamp", "flags",
                                      "context_id", "pid")
        self.writeln(print_str)

        # Flatten the 3D list to 1D list
        queues = sum(inflight_queue_result, [])
        for queue in queues:
            # Skip if all the entries excluding rb of the queue are empty
            if all([i == 'NULL' for i in queue[1:]]):
                pass

            self.writeln(format_str.format(queue[0], queue[1], queue[2],
                                           queue[3], queue[4], queue[5],
                                           queue[6], queue[7], queue[8]))

    def parse_pwrctrl_data(self, dump):
        pwrctrl_address = dump.read('device_3d0.dev.pwrctrl')
        active_pwrlevel = dump.read('device_3d0.dev.pwrctrl.active_pwrlevel')
        prev_pwrlevel = dump.read('device_3d0.dev.pwrctrl.previous_pwrlevel')
        power_flags = dump.read('device_3d0.dev.pwrctrl.power_flags')
        ctrl_flags = dump.read('device_3d0.dev.pwrctrl.ctrl_flags')
        min_pwrlevel = dump.read('device_3d0.dev.pwrctrl.min_pwrlevel')
        max_pwrlevel = dump.read('device_3d0.dev.pwrctrl.max_pwrlevel')
        bus_percent_ab = dump.read('device_3d0.dev.pwrctrl.bus_percent_ab')
        bus_width = dump.read('device_3d0.dev.pwrctrl.bus_width')
        bus_ab_mbytes = dump.read('device_3d0.dev.pwrctrl.bus_ab_mbytes')
        pwr_levels_result = []
        pwrlevels_base_address = pwrctrl_address + \
            dump.field_offset('struct kgsl_pwrctrl', 'pwrlevels')

        for i in range(0, KGSL_MAX_PWRLEVELS):
            pwr_levels_temp = []
            pwrlevels_array_idx_addr = dump.array_index(
                pwrlevels_base_address, "struct kgsl_pwrlevel", i)
            gpu_freq = dump.read_structure_field(
                pwrlevels_array_idx_addr, 'struct kgsl_pwrlevel', 'gpu_freq')
            bus_freq = dump.read_structure_field(
                pwrlevels_array_idx_addr, 'struct kgsl_pwrlevel', 'bus_freq')
            bus_min = dump.read_structure_field(
                pwrlevels_array_idx_addr, 'struct kgsl_pwrlevel', 'bus_min')
            bus_max = dump.read_structure_field(
                pwrlevels_array_idx_addr, 'struct kgsl_pwrlevel', 'bus_max')
            pwr_levels_temp.append(pwrlevels_array_idx_addr)
            pwr_levels_temp.append(gpu_freq)
            pwr_levels_temp.append(bus_freq)
            pwr_levels_temp.append(bus_min)
            pwr_levels_temp.append(bus_max)
            pwr_levels_result.append(pwr_levels_temp)

        self.writeln('pwrctrl_address:  ' + strhex(pwrctrl_address))
        self.writeln('active_pwrlevel:  ' + str(active_pwrlevel))
        self.writeln('previous_pwrlevel:  ' + str(prev_pwrlevel))
        self.writeln('power_flags:  ' + strhex(power_flags))
        self.writeln('ctrl_flags:  ' + strhex(ctrl_flags))
        self.writeln('min_pwrlevel:  ' + str(min_pwrlevel))
        self.writeln('max_pwrlevel:  ' + str(max_pwrlevel))
        self.writeln('bus_percent_ab:  ' + str(bus_percent_ab))
        self.writeln('bus_width:  ' + str(bus_width))
        self.writeln('bus_ab_mbytes:  ' + str(bus_ab_mbytes))
        self.writeln()

        self.writeln('pwrlevels_base_address:  '
                     + strhex(pwrlevels_base_address))
        format_str = '{0:<20} {1:<20} {2:<20} {3:<20} {4:<20}'
        self.writeln(format_str.format("INDEX", "GPU_FREQ",
                                       "BUS_FREQ", "BUS_MIN", "BUS_MAX"))

        index = 0
        for powerlevel in pwr_levels_result:
            print_str = format_str.format(index, powerlevel[1], powerlevel[2],
                                          powerlevel[3], powerlevel[4])
            self.writeln(print_str)
            index = index + 1

    def parse_mutex_data(self, dump):
        self.writeln("device_mutex:")
        device_mutex = dump.read('device_3d0.dev.mutex')
        mutex_val = dump.read_word(device_mutex)

        if mutex_val:
            tgid = dump.read_structure_field(
                mutex_val, 'struct task_struct', 'tgid')
            comm_add = mutex_val + \
                dump.field_offset('struct task_struct', 'comm')
            comm_val = dump.read_cstring(comm_add)
            self.writeln("tgid: " + str(tgid))
            self.writeln("comm: " + comm_val)
        else:
            self.writeln("UNLOCKED")

        self.writeln()
        self.writeln("dispatcher_mutex:")
        dispatcher_mutex = dump.read('device_3d0.dispatcher')
        dispatcher_mutex_val = dump.read_word(dispatcher_mutex)

        if dispatcher_mutex_val:
            tgid = dump.read_structure_field(
                dispatcher_mutex_val, 'struct task_struct', 'tgid')
            comm_add = dispatcher_mutex_val + \
                dump.field_offset('struct task_struct', 'comm')
            comm_val = dump.read_cstring(comm_add)
            self.writeln("tgid: " + str(tgid))
            self.writeln("comm: " + str(comm_val))
        else:
            self.writeln("UNLOCKED")

    def parse_scratch_memory(self, dump):
        hostptr = dump.read('device_3d0.dev.scratch.hostptr')
        self.writeln("hostptr:  " + strhex(hostptr))

        def add_increment(x): return x + 4

        format_str = '{0:20} {1:20} {2:20}'
        self.writeln(format_str.format("Ringbuffer_id", "RPTR_Value",
                                       "CTXT_RESTORE_ADD"))

        rptr_0 = dump.read_s32(hostptr)
        hostptr = add_increment(hostptr)
        rptr_1 = dump.read_s32(hostptr)
        hostptr = add_increment(hostptr)
        rptr_2 = dump.read_s32(hostptr)
        hostptr = add_increment(hostptr)
        rptr_3 = dump.read_s32(hostptr)
        hostptr = add_increment(hostptr)
        ctxt_0 = dump.read_s32(hostptr)
        hostptr = add_increment(hostptr)
        ctxt_1 = dump.read_s32(hostptr)
        hostptr = add_increment(hostptr)
        ctxt_2 = dump.read_s32(hostptr)
        hostptr = add_increment(hostptr)
        ctxt_3 = dump.read_s32(hostptr)

        self.writeln(format_str.format(str(0), str(rptr_0), strhex(ctxt_0)))
        self.writeln(format_str.format(str(1), str(rptr_1), strhex(ctxt_1)))
        self.writeln(format_str.format(str(2), str(rptr_2), strhex(ctxt_2)))
        self.writeln(format_str.format(str(3), str(rptr_3), strhex(ctxt_3)))

    def parse_memstore_memory(self, dump):
        hostptr = dump.read('device_3d0.dev.memstore.hostptr')
        self.write("hostptr:  " + strhex(hostptr) + "\n")

        def add_increment(x): return x + 4

        format_str = '{0:^20} {1:^20} {2:^20} {3:^20} {4:^20}'
        print_str = format_str.format("soptimestamp", "eoptimestamp",
                                      "preempted", "ref_wait_ts",
                                      "current_context")
        self.writeln(print_str)

        hostptr_init = hostptr
        while (hostptr - hostptr_init) <= 8*1024:
            soptimestamp = dump.read_s32(hostptr)
            hostptr = add_increment(hostptr)
            # skip unused entry
            hostptr = add_increment(hostptr)
            eoptimestamp = dump.read_s32(hostptr)
            hostptr = add_increment(hostptr)
            # skip unused entry
            hostptr = add_increment(hostptr)
            preempted = dump.read_s32(hostptr)
            hostptr = add_increment(hostptr)
            # skip unused entry
            hostptr = add_increment(hostptr)
            ref_wait_ts = dump.read_s32(hostptr)
            hostptr = add_increment(hostptr)
            # skip unused entry
            hostptr = add_increment(hostptr)
            current_context = dump.read_s32(hostptr)
            hostptr = add_increment(hostptr)
            # skip unused entry
            hostptr = add_increment(hostptr)

            if (soptimestamp or eoptimestamp or preempted or ref_wait_ts
                    or current_context):
                print_str = format_str.format(hex(soptimestamp),
                                              hex(eoptimestamp), preempted,
                                              hex(ref_wait_ts),
                                              current_context)
                self.writeln(print_str)

    def parse_fence_data(self, dump):
        context_idr = dump.read('device_3d0.dev.context_idr')
        self.rtw.walk_radix_tree(context_idr, self.__print_fence_info)
        return

    def __print_fence_info(self, context_addr):
        dump = self.ramdump
        context_id = dump.read_structure_field(context_addr,
                                               'struct kgsl_context', 'id')
        ktimeline_offset = dump.field_offset('struct kgsl_context',
                                             'ktimeline')
        ktimeline_addr = dump.read_pointer(context_addr + ktimeline_offset)

        name_offset = dump.field_offset('struct kgsl_sync_timeline',
                                        'name')
        name_addr = ktimeline_addr + name_offset
        kgsl_sync_timeline_name = dump.read_cstring(name_addr)

        kgsl_sync_timeline_last_ts = dump.read_structure_field(
            ktimeline_addr, 'struct kgsl_sync_timeline',
            'last_timestamp')
        kgsl_sync_timeline_kref_counter = dump.read_byte(
            ktimeline_addr)

        self.writeln("context id: " + str(context_id))
        self.writeln("\t" + "kgsl_sync_timeline_name: "
                     + str(kgsl_sync_timeline_name))
        self.writeln("\t" + "kgsl_sync_timeline_last_timestamp: "
                     + str(kgsl_sync_timeline_last_ts))
        self.writeln("\t" + "kgsl_sync_timeline_kref_counter: "
                     + str(kgsl_sync_timeline_kref_counter))

    def parse_open_process_data(self, dump):
        format_str = '{0:20} {1:20} {2:20} {3:20}'
        self.writeln(format_str.format("PID", "PNAME", "PROCESS_PRIVATE_PTR",
                                       "kgsl-pagetable-address"))

        node_addr = dump.read('kgsl_driver.process_list.next')
        list_elem_offset = dump.field_offset(
                            'struct kgsl_process_private', 'list')
        open_process_list_walker = linux_list.ListWalker(
                                    dump, node_addr, list_elem_offset)
        open_process_list_walker.walk(node_addr, self.walk_process_private,
                                      dump, format_str)

    def walk_process_private(self, kgsl_private_base_addr, dump, format_str):
        pid = dump.read_structure_field(
            kgsl_private_base_addr, 'struct kgsl_process_private', 'pid')

        comm_offset = dump.field_offset('struct kgsl_process_private', 'comm')
        pname = dump.read_cstring(kgsl_private_base_addr + comm_offset)

        kgsl_pagetable_address = dump.read_structure_field(
            kgsl_private_base_addr, 'struct kgsl_process_private', 'pagetable')

        self.writeln(format_str.format(
            str(pid), str(pname), hex(kgsl_private_base_addr),
            hex(kgsl_pagetable_address)))
