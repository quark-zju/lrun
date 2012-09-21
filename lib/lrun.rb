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

require 'tempfile'


module Lrun
  LRUN_BINARY = 'lrun'
  LRUN_PATH   = ENV['PATH'].split(':').map{|p| File.join(p, LRUN_BINARY)}.find{|p| File.executable? p}

  # available lrun options whitelist
  #   1: unique
  #   2: repeatable
  LRUN_OPTIONS = {
    :max_cpu_time => 1,
    :max_real_time => 1,
    :max_memory => 1,
    :max_output => 1,
    :max_nprocess => 1,
    :min_nice => 1,
    :max_rtprio => 1,
    :max_nfile => 1,
    :max_stack => 1,
    :isolate_process => 1,
    :basic_devices => 1,
    :reset_env => 1,
    :network => 1,
    :chroot => 1,
    :chdir => 1,
    :nice => 1,
    :umask => 1,
    :uid => 1,
    :gid => 1,
    :interval => 1,
    :cgname => 1,
    :bindfs => 2,
    :tmpfs => 2,
    :env => 2,
    :fd => 2,
    :group => 2,
    :cmd => 2,
  }
  
  DEFAULT_TRUNCATE = 4096

  # memory:   bytes
  # time:     seconds
  # exceed:   nil || :time || :memory
  # exitcode: int
  # signal:   nil || int
  # stdout:   nil || string
  # stderr:   nil || string
  Result = Struct.new(:memory, :cputime, :exceed, :exitcode, :signal, :stdout, :stderr)

  def self.merge_options(*opts)
    # make things little faster
    opts = opts.compact.reject { |o| [Hash, Array].include?(o.class) && o.size == 0 }
    return Hash[[*opts[0]]] if opts.size <= 1

    # do the merge
    opts.inject({}) do |res, opt| 
      opt.each do |k, v|
        case LRUN_OPTIONS[k]
        when 2
          res[k] ||= []
          res[k] += make_aoa(v)
        else
          res[k] = v
        end
      end
      res
    end
  end

  # Run command
  #
  #  opt: Hash
  #     in:  File path in REAL FS
  #     out:
  #     err:
  #
  # Returns LrunResult
  def self.run(commands, opt = nil)
    opt ||= {}
    stdout, stderr = nil

    IO.pipe do |r3, w3| IO.pipe
      command_line = [LRUN_BINARY, *format_options(opt), *commands]

      pid = Process.spawn(*command_line, {0 => opt[:in] || :close,
                                          1 => opt[:out] || (stdout = Tempfile.new("lrun.stdout.#{$$}")).path,
                                          2 => opt[:err] || (stderr = Tempfile.new("lrun.stderr.#{$$}")).path,
                                          3 => w3.fileno})
      [w3].each(&:close)
      
      report = Hash[r3.lines.map{|l| l.chomp.split(' ', 2)}]

      stat = Process.wait2(pid)[-1]
      [r3].each {|io| io.close unless io.closed?}

      if stat.signaled? || stat.exitstatus != 0
        require 'shellwords'
        raise RuntimeError.new("#{Shellwords.shelljoin command_line} (#{stat}) #{stderr.read}")
      end

      exceed = case report['EXCEED']
               when 'none'
                 nil
               when /TIME/
                 :time
               when /OUTPUT/
                 :output
               when /MEMORY/
                 :memory
               end
      signal = report['SIGNALED'].to_i == 0 ? nil : report['TERMSIG'].to_i
      Result.new(report['MEMORY'].to_i, report['CPUTIME'].to_f, exceed, report['EXITCODE'].to_i, signal,
                 stdout && stdout.read(opt[:truncate] || DEFAULT_TRUNCATE),
                 stderr && stderr.read(opt[:truncate] || DEFAULT_TRUNCATE))
    end
  ensure
    [stdout, stderr].each { |f| f && (f.close; f.unlink) }
  end

  autoload :Runner, 'lrun/runner'
  autoload :RestrictedRunner, 'lrun/restricted_runner'
  autoload :BindDirRunner, 'lrun/binddir_runner'

  private

  # make param to array of array
  def self.make_aoa(param)
    if param.nil?
      []
    elsif param.is_a?(Array) && param.all?{|a| a.is_a?(Array)}
      param
    else
      [[*param]]
    end
  end
  
  def self.format_options(*opts)
    merge_options(*opts).select {|k,v| LRUN_OPTIONS.has_key?(k) }.to_a.flatten.compact.map do |e|
       case e
       when Symbol
         "--#{e.to_s.gsub('_', '-')}"
       else
         e.to_s
       end
    end.reject(&:empty?)
  end

end
