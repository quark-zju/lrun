#!/usr/bin/env ruby

if Process.uid != 0
  puts 'root required'
  exit 1
end

require 'fileutils'

ROFS_DEST  = ENV['ROFS_DEST'] || '/rofs'
TMPFS_SIZE = ENV['ROFS_TMPSIZE'] || '49152k'

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

['/usr', '/bin', '/opt', '/lib', '/lib64', '/etc', '/dev', '/tmp', '/proc'].each do |x|
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
['/usr', '/bin', '/opt', '/lib', '/lib64'].each do |src|
  dest = File.join(ROFS_DEST, src)
  next unless Dir.exists?(src) && Dir.exists?(dest)
  mount src, dest, '--bind', 'defaults', 'ro,noatime,nosuid,nodev'
end

# devfs
dev_path = File.join(ROFS_DEST, 'dev')
File.unlink *Dir[File.join(dev_path, '*')]

{null: 3, zero: 5, random: 8, urandom: 9, full: 7}.each do |dev, id|
  assert_execute 'mknod', '-m', '666', File.join(dev_path, dev.to_s), 'c', '1', id.to_s
end

# passwd
File.open(File.join(ROFS_DEST, 'etc/passwd'), 'w') do |f|
  f.puts "guest:x:2000:200:bin:/bin:/bin/false"
end

# tmpfs
mount 'none', File.join(ROFS_DEST, 'tmp'), ['-t', 'tmpfs'], "size=#{TMPFS_SIZE},relatime,nosuid"

# done
puts "ROFS: #{ROFS_DEST} is ready."
