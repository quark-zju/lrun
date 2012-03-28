#!/usr/bin/env ruby
################################################################################
# Copyright (C) 2012 WU Jun <quark@zju.edu.cn>
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

def check name, config
  status = (@config =~ /^#{config}=[ym]/) ? 'OK' : 'MISSING'
  puts '%-12s: %s' % [name, status]
end


check 'Namespaces',    'CONFIG_NAMESPACES'
check '    pid',       'CONFIG_PID_NS'
check '    ipc',       'CONFIG_IPC_NS'
check '    network',   'CONFIG_NET_NS'
check 'Cgroup',        'CONFIG_CGROUPS'
check '    device',    'CONFIG_CGROUP_DEVICE'
check '    cpuacct',   'CONFIG_CGROUP_CPUACCT'
check '    memory',    'CONFIG_CGROUP_MEM_RES_CTLR'
check '    freezer',   'CONFIG_CGROUP_FREEZER'


