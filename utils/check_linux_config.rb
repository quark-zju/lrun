#!/usr/bin/env ruby
################################################################################
# Copyright (C) 2012-2013 WU Jun <quark@zju.edu.cn>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
################################################################################

@no_problem = true
@kernel_version = `uname -r`
@config = if File.exists? '/proc/config.gz'
            `zcat /proc/config.gz`
          else
            # Ubuntu favor
            uname_r = `uname -r`.chomp
            `cat /boot/config-#{uname_r}`
          end

if @config.empty?
  raise RuntimeError.new('Can not load config')
end

def check_kernel version_range
  version_range.cover? @kernel_version
end

def check_config name, config
  exists = (@config =~ /^#{config}=[ym]/)
  @no_problem = false if not exists
  puts '%-12s: %s' % [name, exists ? 'OK' : 'MISSING?']
end

check_config 'Namespaces',    'CONFIG_NAMESPACES'
check_config '    pid',       'CONFIG_PID_NS'
check_config '    ipc',       'CONFIG_IPC_NS'
check_config '    network',   'CONFIG_NET_NS'
check_config 'Cgroup',        'CONFIG_CGROUPS'
check_config '    device',    'CONFIG_CGROUP_DEVICE'
check_config '    cpuacct',   'CONFIG_CGROUP_CPUACCT'
# Since 2.6.39-bpo60-2 for Squeeze the memory cgroup support is built in
if check_kernel [0]..[2, 6, 39]
  check_config '    memory',    'CONFIG_CGROUP_MEM_RES_CTLR'
end
check_config '    freezer',   'CONFIG_CGROUP_FREEZER'

exit(@no_problem ? 0 : 1)
