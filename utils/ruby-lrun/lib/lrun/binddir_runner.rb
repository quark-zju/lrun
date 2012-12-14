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

