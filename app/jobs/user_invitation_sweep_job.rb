class UserInvitationSweepJob
  include Sidekiq::Job
  sidekiq_options retry: false

  def perform
    UserInvitationDelivery.where(status: %w[queued sending]).find_each do |delivery|
      delivery.user.with_lock do
        delivery.lock!
        if delivery.status == 'sending' && delivery.started_at < 2.minutes.ago
          delivery.update!(status: 'uncertain', error_code: 'WORKER_INTERRUPTED', finished_at: Time.current)
        elsif delivery.status == 'queued'
          if delivery.requested_at < 10.minutes.ago
            delivery.update!(status: 'failed', error_code: 'QUEUE_TIMEOUT', finished_at: Time.current)
          elsif UserInvitations.enabled?
            delivery.dispatch
          end
        end
      end
    end
  end
end
