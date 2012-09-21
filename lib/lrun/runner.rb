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
    @runner.run commands, merge_options(opt)
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
