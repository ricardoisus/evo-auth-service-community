# Every Sidekiq process sweeps; row locks make concurrent sweeps harmless.
# No token/email is stored in scheduling arguments. Survives queue outages/restarts.
Sidekiq.configure_server do |config|
  sweeper = nil
  config.on(:startup) do
    sweeper = Thread.new do
      loop do
        begin
          Rails.application.executor.wrap { UserInvitationSweepJob.new.perform }
        rescue StandardError
          Rails.logger.warn('Invitation sweep failed; retrying next minute')
        end
        sleep 60
      end
    end
  end
  config.on(:shutdown) { sweeper&.kill }
end
