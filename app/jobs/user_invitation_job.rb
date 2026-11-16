class UserInvitationJob
  include Sidekiq::Job
  sidekiq_options retry: false

  def perform(id)
    delivery = UserInvitationDelivery.find_by(id: id)
    return unless delivery && UserInvitations.enabled?
    user = delivery.user
    raw = digest = nil
    UserInvitations.with_lock(user) do
      delivery.lock!
      return unless delivery.status == 'queued'
      if delivery.requested_at < 10.minutes.ago
        delivery.update!(status: 'failed', error_code: 'QUEUE_TIMEOUT', finished_at: Time.current)
        return
      end
      unless UserInvitations.eligible?(user) && UserInvitations.recipient_allowed?(user)
        delivery.update!(status: 'cancelled', finished_at: Time.current)
        return
      end
      raw, digest = Devise.token_generator.generate(User, :reset_password_token)
      user.update!(reset_password_token: digest, reset_password_sent_at: Time.current)
      delivery.update!(status: 'sending', started_at: Time.current)
    end
    # A second transaction persists the digest before SMTP. Lock order is always user -> delivery.
    UserInvitations.with_lock(user) do
      delivery.lock!
      return unless delivery.status == 'sending'
      unless UserInvitations.enabled? && UserInvitations.eligible?(user) && UserInvitations.recipient_allowed?(user) && user.reset_password_token == digest
        delivery.update!(status: 'cancelled', finished_at: Time.current)
        return
      end
      UserMailer.invitation(user, SensitiveMailToken.new(raw)).deliver_now
      now = Time.current
      delivery.update!(status: 'sent', smtp_accepted_at: now, finished_at: now)
      user.update!(invitation_sent_at: now)
    end
  rescue StandardError => error
    # Only an explicit authentication rejection is definitely before SMTP DATA.
    # Every ambiguous transport/commit error is uncertain and never auto-retried.
    user&.with_lock do
      delivery.reload.lock!
      if delivery.status == 'sending'
        auth_error = error.is_a?(Net::SMTPAuthenticationError)
        delivery.update!(status: auth_error ? 'failed' : 'uncertain',
                         error_code: auth_error ? 'SMTP_AUTH_FAILED' : 'SMTP_UNAVAILABLE', finished_at: Time.current)
        if auth_error && user.reset_password_token == digest
          user.update!(reset_password_token: nil, reset_password_sent_at: nil)
        end
      end
    end
  end
end
