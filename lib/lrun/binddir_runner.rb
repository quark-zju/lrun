require 'lrun/runner'
require 'tempfile'

class Lrun::BindDirRunner < Lrun::Runner

  attr_accessor :bind, :dest

  def run(commands, opt = nil)
    curopt = Hash[[*options, *opt]]

    root   = curopt[:chroot] || '/'
    dest   = @dest || '/tmp'
    dir    = curopt[:bind] || self.bind || dest

    begin
      script_base = ".lrun.#{$$}.sh"
      script_path = File.join(dir, script_base)

      if commands.is_a?(String) && commands.start_with?('#!')
        # wrap command into temp script automatically
        File.write(script_path, commands)
        File.chmod(0777, dir) rescue nil
        File.chmod(0777, script_path)
        commands = File.join(dest, script_base)
      end

     @runner.run commands, Lrun.merge_options(@options, opt, chdir: dest, bindfs: [File.join(root, dest), dir])
   ensure
     File.unlink(script_path) rescue nil if File.exists?(script_path)
   end
  end

end

