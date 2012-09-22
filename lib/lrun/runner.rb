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

require 'lrun'

class Lrun::Runner

  attr_accessor :options

  def initialize(*options)
    @runner = Lrun
    @runner = options.shift if options.first.respond_to?(:run)

    @options = Lrun.merge_options(*options)
  end

  # options
  [:in, :out, :err, *Lrun::LRUN_OPTIONS.keys].each do |name|
    define_method name do |val| chain(name => val) end
  end

  # multiple options
  Lrun::LRUN_OPTIONS.group_by(&:last)[2].map(&:first).each do |name|
    define_method name do |*arr| chain(name => [*@options[name], arr]) end
  end

  def run(commands, opt = nil)
    @runner.run commands, merge_options(options, opt)
  end

  # decorators
  
  def restricted
    Lrun::RestrictedRunner.new(self)
  end

  def binded(dir, chroot = '/')
    Lrun::BindDirRunner.new(self, bind: dir, chroot: chroot)
  end

  # merge_options is useful for debug
  def merge_options(*opts)
    @runner.merge_options(@options, *opts)
  end

  private

  def chain(new_options)
    # avoid Lrun.merge_options to make repeatable option 
    # overrideable. avoid delegate to be faster.
    self.class.new Hash[[*@options, *new_options]]
  end

end
