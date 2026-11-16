class PasswordRecovery
  MESSAGE = 'Se o endereço estiver cadastrado, você receberá as instruções por e-mail.'.freeze
  ORIGIN = 'https://evo.agenciavetorial.com'.freeze

  def self.url(raw, invite: false)
    # Never trust Host, redirect_url, or an origin from an incoming request.
    configured = ENV.fetch('FRONTEND_URL', ORIGIN).delete_suffix('/')
    raise 'Invalid frontend origin' unless configured == ORIGIN
    query = { reset_password_token: raw }
    query[:purpose] = 'invite' if invite
    "#{ORIGIN}/auth/reset-password?#{URI.encode_www_form(query)}"
  end

  def self.encryptor
    ActiveSupport::MessageEncryptor.new(Rails.application.key_generator.generate_key('password-recovery-queue', 32))
  end

  def self.request(email, ip)
    normalized = email.to_s.strip.downcase
    hmac = OpenSSL::HMAC.hexdigest('SHA256', Rails.application.secret_key_base, normalized)
    InvitationRateLimiter.consume!("recovery-ip:#{ip}", 5, 1.hour)
    InvitationRateLimiter.consume!("recovery-email:#{hmac}", 3, 24.hours)
    # Same asynchronous path for known/unknown addresses; Redis stores only ciphertext.
    encrypted = encryptor.encrypt_and_sign(normalized)
    PasswordRecoveryJob.perform_async(encrypted)
  rescue StandardError
    # Uniform public response, including limiter/queue outages. Fail closed for sending.
    nil
  end

  def self.consume!(raw, password, confirmation)
    user = User.with_reset_password_token(raw.to_s)
    raise UserInvitations::Error.new('INVALID_OR_EXPIRED_TOKEN', 422) unless user
    user.with_lock do
      digest = Devise.token_generator.digest(User, :reset_password_token, raw)
      unless user.reset_password_token == digest && user.reset_password_period_valid?
        raise UserInvitations::Error.new('INVALID_OR_EXPIRED_TOKEN', 422)
      end
      raise UserInvitations::Error.new('VALIDATION_ERROR', 422) if password.blank? || password != confirmation
      user.password = password
      user.password_confirmation = confirmation
      user.reset_password_token = nil
      user.reset_password_sent_at = nil
      user.save!
      UserInvitations.accept!(user)
      revoke!(user)
    end
    user
  end

  def self.revoke!(user)
    user.update!(tokens: {})
    TokenValidationService.invalidate_cache_for_user(user)
    active = Doorkeeper::AccessToken.where(resource_owner_id: user.id, revoked_at: nil)
    active.pluck(:token).each { |token| TokenValidationService.invalidate_cache_for_token(token) }
    active.update_all(revoked_at: Time.current)
  end
end
