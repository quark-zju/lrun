require 'minitest/autorun'
require 'purdytest' rescue nil
require 'lrun'
require 'fileutils'

# use autotest to test, no Guardfile required

class TestLrun < MiniTest::Unit::TestCase

  def test_lrun_private
    assert_raises(NoMethodError) { Lrun.new }
  end

  def test_merge_options
    assert_equal Lrun.merge_options(), {}
    assert_equal Lrun.merge_options(nil, nil, nil), {}
    assert_equal Lrun.merge_options({:a => :abc}, {:a => :def}), {:a => :def}

    opt = Lrun::LRUN_OPTIONS.select { |k, v| v == 1 }
    assert_equal Lrun.merge_options(opt), Hash[opt]
    assert_equal Lrun.merge_options(Hash[opt]), Hash[opt]
    assert_equal Lrun.merge_options(Hash[opt], opt, {:chroot => 'sdfsdf'}, opt), Hash[opt]

    assert_equal \
      ({cmd: [['abc'], ['def', 'def2'], ['ghi', 'ghi2']]}),
      Lrun.merge_options({cmd: 'abc'}, nil, [], [[:cmd, [['def', 'def2']]]], {cmd: ['ghi', 'ghi2']})

    assert_equal \
      ({chdir: '/', bindfs: [['a', 1], ['b', 2], ['c', 3]]}),
      Lrun.merge_options(nil, [], {}, {bindfs: ['a', 1]}, {bindfs: [['b', 2]]}, chdir: '/', bindfs: ['c', 3])
  end

  def test_exitcode
    assert_equal Lrun.run('/bin/true').exitcode, 0
    assert_equal Lrun.run('/bin/false').exitcode, 1
    assert_equal Lrun.run('/bin/true', in: :close, out: :close, err: :close).exitcode, 0
    assert_equal Lrun.run('/bin/false', in: :close, out: :close, err: :close).exitcode, 1
  end

  def test_redirects
    assert_equal Lrun.run(['/bin/echo', 'f' * 40000], truncate: 40).stdout, ('f' * 40)
    assert_equal Lrun.run(['/bin/echo', 'f' * 40000], truncate: 30000).stdout, ('f' * 30000)
    refute_equal Lrun.run(['/bin/ls', 'doesnot_exist_file'], truncate: 40).stderr.length, 0
    assert_nil Lrun.run(['/bin/ls', '/bin/ls'], truncate: 40).stderr
  end

  def test_limits
    # output limit
    assert_equal Lrun.run(['/bin/sh', '-c', '/bin/cat /dev/full > /dev/null'], max_output: 1000000).exceed, :output

    # time limit
    assert_equal Lrun.run(['sleep', '300'], max_real_time: 0.1).exceed, :time
    assert_equal Lrun.run(['/bin/sh', '-c', '/bin/cat /dev/full > /dev/null'], max_cpu_time: 0.1).exceed, :time

    # memory limit
    assert_equal :memory, Lrun.run(['cpp', '/dev/full', '-o', '/dev/null'], max_memory: 1_000_000).exceed
  end

end
