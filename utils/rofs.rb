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

# what rofs.rb do:
#   make a /rofs which is the mirror of parts of /, but read-only
#   - mkdir /rofs
#   - mkdir ESSENTIAL_DIRS (mkdir -p)
#   - mount --bind MIRRORED_DIRS to /rofs and make them read-only
#   - generate a `/etc/passwd` file
#   - mount a tmpfs at `/tmp`
#   - prepare `/dev/#{*DEV_NODES.keys}`

ESSENTIAL_DIRS = ['/usr', '/bin', '/opt', '/lib', '/lib64', '/etc', '/dev', '/tmp', '/proc']
MIRRORED_DIRS  = ['/usr', '/bin', '/opt', '/lib', '/lib64']
DEV_NODES      = {null: 3, zero: 5, random: 8, urandom: 9, full: 7}

ROFS_DEST      = ENV['ROFS_DEST'] || '/rofs'
TMPFS_SIZE     = ENV['ROFS_TMPSIZE'] || '49152k'

if Process.uid != 0
  puts 'root required'
  exit 1
end

require 'fileutils'

def assert_execute(*cmd)
  print ['>', *cmd, '... '].join(' ')
  if system *cmd
    puts 'ok'
  else
    puts 'failed'
    exit 2
  end
end

def mount(src, dest, param, mount_opt = 'defaults', remount_opt = nil)
  print "bind #{src} -> #{dest} (#{[mount_opt, remount_opt].compact.join(' -> ')}) ... "
  entry = File.read('/proc/mounts').lines.map(&:split).find{|e| e[1] == dest}
  if entry && ((remount_opt || mount_opt).to_s.split(',') - entry[3].split(',')).empty?
    puts 'already done'
    return
  elsif entry
    p entry
    puts 'need umount'
    assert_execute 'umount', dest
  else
    puts 'processing'
  end

  # do mount 
  if mount_opt
    assert_execute *['mount', *param, '-o', mount_opt.to_s, src, dest].compact
  end

  # do remount
  if remount_opt
    if param.to_s['bind']
      # bind workround, use -o remount,bind and provide src, mount will
      # skip problemic /etc/mtab
      assert_execute *['mount', '-o', "remount,bind,#{remount_opt}", src, dest].compact
    else
      assert_execute *['mount', '-o', "remount,#{remount_opt}", dest].compact
    end
  end
end

FileUtils.mkdir_p ROFS_DEST

ESSENTIAL_DIRS.each do |x|
  dir = File.join(ROFS_DEST, x)
  next unless Dir.exists?(x) && (! Dir.exists?(dir))
  FileUtils.mkdir_p dir
end

# permission fix
[['chown', 'root:root', ROFS_DEST],
 ['chmod', 'a+rwX', File.join(ROFS_DEST, '/tmp')],
 ['chmod', 'go-w', ROFS_DEST, File.join(ROFS_DEST, 'etc')]
].each do |cmd|
  assert_execute *cmd
end

# bind rofs
MIRRORED_DIRS.each do |src|
  dest = File.join(ROFS_DEST, src)
  next unless Dir.exists?(src) && Dir.exists?(dest)
  mount src, dest, '--bind', 'defaults', 'ro,noatime,nosuid,nodev'
end

# devfs
if ESSENTIAL_DIRS.include?('/dev')
  dev_path = File.join(ROFS_DEST, 'dev')
  File.unlink *Dir[File.join(dev_path, '*')]
end

DEV_NODES.each do |dev, id|
  assert_execute 'mknod', '-m', '666', File.join(dev_path, dev.to_s), 'c', '1', id.to_s
end

# /etc/passwd
if ESSENTIAL_DIRS.include?('/etc')
  File.open(File.join(ROFS_DEST, 'etc/passwd'), 'w') do |f|
    f.puts "guest:x:2000:200:bin:/bin:/bin/false"
  end
end

# tmpfs
if ESSENTIAL_DIRS.include?('/tmp')
  mount 'none', File.join(ROFS_DEST, 'tmp'), ['-t', 'tmpfs'], "size=#{TMPFS_SIZE},relatime,nosuid"
end

# done
puts "ROFS: #{ROFS_DEST} is ready."
