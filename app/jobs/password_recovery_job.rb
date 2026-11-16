class PasswordRecoveryJob
  include Sidekiq::Job
  sidekiq_options retry: false

  def perform(encrypted_email)
    email = PasswordRecovery.encryptor.decrypt_and_verify(encrypted_email)
    user = User.from_email(email)
    return unless user && user.provider == 'email'
    user.with_lock do
      if user.invited_at && !user.invitation_accepted_at
        UserInvitations.reserve!(user, actor: nil, origin: 'self_recovery')
      else
        raw, digest = Devise.token_generator.generate(User, :reset_password_token)
        user.update!(reset_password_token: digest, reset_password_sent_at: Time.current)
        UserMailer.password_recovery(user, SensitiveMailToken.new(raw)).deliver_now
      end
    end
  rescue StandardError
    Rails.logger.warn('Password recovery could not complete')
  end
end
