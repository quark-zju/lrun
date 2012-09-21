require 'lrun/runner'

class Lrun::RestrictedRunner < Lrun::Runner

  LOCAL_OPTIONS = {
      network: false, basic_devices: true, isolate_process: true, 
      max_nprocess: 2048, max_nfile: 256, umask: 022,
      max_nice: 2, nice: 2, max_rtprio: 1,
  }

  def run(commands, opt = nil)
    @runner.run commands, Lrun.merge_options(options, opt, LOCAL_OPTIONS)
  end

end


