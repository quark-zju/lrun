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

class Lrun::RestrictedRunner < Lrun::Runner

  LOCAL_OPTIONS = {
      network: false, basic_devices: true, isolate_process: true, 
      max_nprocess: 2048, max_nfile: 256, umask: 022,
      max_nice: 2, nice: 2, max_rtprio: 0,
  }

  def run(commands, opt = nil)
    @runner.run commands, Lrun.merge_options(options, opt, LOCAL_OPTIONS)
  end

end


