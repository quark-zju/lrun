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

require 'minitest/autorun'
begin
  require 'purdytest'
rescue LoadError
end
require 'lrun/runner'
require 'fileutils'

# need File.write
unless File.respond_to?(:write)
  def File.write f, s
    File.open(f, 'w') { |f| f.write s }
  end
end

class TestLrunRunner < MiniTest::Unit::TestCase

  def l(*opts)
    Lrun::Runner.new(*opts)
  end

  TMPDIR = '/tmp/testdir'

  def prepare_tmpdir
    FileUtils.rm_rf   TMPDIR
    FileUtils.mkdir_p TMPDIR
    TMPDIR
  end

  # combined runner

  def b
    skip unless File.exists? '/rofs/bin/sh'
    @b ||= l.restricted.binded(TMPDIR, '/rofs')
  end

  def run_c_code(code, options = nil)
    File.write(File.join(TMPDIR, 'foo.c'), code)

    r = b.run("#!/bin/sh\nrm foo;\ngcc ./foo.c -Wall -o foo")
    assert_equal 0, r.exitcode

    b.run("#!/bin/sh\n./foo", options)
  end

  def run_bad_c_code(code, options = nil)
    File.write(File.join(TMPDIR, 'foo.c'), code)

    r = b.run("#!/bin/sh\nrm foo;\ngcc ./foo.c -O0 -o foo")
    if 0 != r.exitcode
      puts r.stderr
      puts r.stdout
      assert false
    end

    # run with 0.5s time limit, 256MB memory limit, 32MB output limit
    b.max_cpu_time(0.5).max_real_time(0.6).max_memory(256000000).max_output(32000000).run("./foo", options)
  end

  # test

  def test_run
    assert_equal 1, l.run('/bin/false').exitcode
  end

  def test_options
    assert_equal false, l.network(false).chroot('/tmp').options[:network]
    assert_equal '/tmp', l.network(false).chroot('/tmp').options[:chroot]
    assert_equal [['a'], ['b'], [['c']], ['d']], l.cmd('a').cmd('b').cmd(['c']).cmd('d').options[:cmd]
    assert_equal ({uid: 1000, cmd: [['abc'],['def']]}), l(l(cmd: 'abc', uid: 234), uid: 1000, cmd: ['def']).merge_options
  end

  def test_chained
    o1 = l(l).max_real_time(0.1)
    assert_equal :time, l(l(o1)).run(['sleep', '2']).exceed
  end

  def test_restricted
    assert_equal 0, l.run(['/sbin/ifconfig', 'eth0']).exitcode
    refute_equal 0, l.network(true).restricted.network(true).run(['ifconfig', 'eth0']).exitcode
  end

  def test_rofs_binded
    tmp_dir = prepare_tmpdir

    b.run(['bash', '-c', "echo hello > world"])

    assert_equal true, File.exists?(File.join(tmp_dir, 'world'))
    assert_equal 'hello', File.read(File.join(tmp_dir, 'world')).chomp

    assert_equal 0, b.run(['bash', '-c', "echo hello | grep hello"]).exitcode
    refute_equal 0, b.run(['bash', '-c', "echo hello | grep -v hello"]).exitcode

    # alnative script form
    assert_equal 0, b.run("#!/bin/sh\necho hello | grep hello").exitcode
    refute_equal 0, b.run("#!/bin/sh\necho hello | grep -v hello").exitcode
  end

  def test_compile_hello_c
    tmp_dir = prepare_tmpdir

    # compile should fail
    File.write(File.join(tmp_dir, 'hello.c'), 'main() { ff3; return 37; }')
    r = b.run("#!/bin/sh\ngcc hello.c -Wall -o hello")
    refute_equal 0, r.exitcode

    # comple hello.c
    File.write(File.join(tmp_dir, 'hello.c'), 'main() { puts("hello world"); return 37; }')
    r = b.run("#!/bin/sh\ngcc hello.c -Wall -o hello")

    # check compiler result
    assert_equal 0, r.exitcode
    assert_nil r.stdout
    assert_match /warning/i, r.stderr

    dest = File.join(tmp_dir, 'hello')
    assert File.exists?(dest)
    assert_equal `#{dest}`.chomp, 'hello world'

    # check run result
    r = b.run("#!/bin/sh\n./hello")
    assert_equal 'hello world', r.stdout.chomp
    assert_equal 37, r.exitcode
  end

  def test_output_redirect
    tmp_dir = prepare_tmpdir

    in_path = File.join(tmp_dir, 'input')
    out_path = File.join(tmp_dir, 'output')

    File.write(in_path, [*1..10].join("\n"))

    run_c_code 's;i;main(){for(;scanf("%d",&i)==1;)s+=i;printf("%d",s);exit(0);}', in: in_path, out: out_path, err: :close

    assert_equal 55, File.read(out_path).to_i
  end

  def test_complex_rofs
    prepare_tmpdir

    assert_equal true, (b.run("#!/bin/bash\n/bin/ls -d /proc/[0-9]* | wc -l").stdout.to_i <= 3)
    assert_equal 0, b.run("#!/bin/bash\n/bin/ls -d /rofs /var /sys | wc -l").stdout.to_i
  end

  def test_script
    skip if `lua -v 2>&1`.empty?

    prepare_tmpdir

    assert_equal 'hello', b.run("#!/usr/bin/env lua\nprint 'hello'").stdout.chomp
  end

  def test_badprog_forkforever
    prepare_tmpdir
    r = run_bad_c_code('main() { for(;;)fork();}')
    assert [:time, :memory].include?(r.exceed)
  end

  def test_badprog_overflow
    prepare_tmpdir
    r = run_bad_c_code('i;c;main(ac,av) { int *j;for(;j=(int*)malloc(4096000);){ for(i=0;i<1024;++i)j[i*999]=i+ac;printf("%d MB\n", ++c * 4); } }')
    assert_equal r.exceed, :memory
  end

  def test_badprog_return3
    prepare_tmpdir
    assert_equal 3, run_bad_c_code('main() { return 3; }').exitcode
  end

  def test_badprog_runforever
    prepare_tmpdir
    assert_equal :time, run_bad_c_code('main() { while(1); }').exceed
  end

  def test_badprog_sleepforever
    prepare_tmpdir
    assert_equal :time, run_bad_c_code('main() { while(1) sleep(1); }').exceed
  end

  def test_badprog_sigfpe
    prepare_tmpdir
    r = run_bad_c_code('main(ac,av) { printf("%d", ac / (ac * 0)); return 0; }')
    assert Signal.list["FPE"], r.signal
  end

  def test_badprog_sigsegv
    prepare_tmpdir
    r = run_bad_c_code('main(ac,av) { ((int*)main)[1+ac] = 2; return 0; }')
    assert Signal.list["SEGV"], r.signal
  end

end
