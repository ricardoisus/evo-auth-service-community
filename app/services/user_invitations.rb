# The database is the source of truth; Redis only adds the shared abuse ceiling.
class UserInvitations
  class Error < StandardError
    attr_reader :code, :status, :next_at
    def initialize(code, status, next_at = nil)
      @code, @status, @next_at = code, status, next_at
      super(code)
    end
  end

  def self.enabled?
    ENV['USER_INVITATIONS_ENABLED'] == 'true'
  end

  def self.recipient_allowed?(user)
    allowlist = ENV.fetch('USER_INVITATIONS_RECIPIENT_ALLOWLIST', '').split(',').map { |email| email.strip.downcase }.reject(&:empty?)
    allowlist.empty? || allowlist.include?(user.email.downcase)
  end

  def self.administrator?(actor)
    actor && actor.has_permission?('users.manage') && actor.has_permission?('users.update')
  end

  def self.eligible?(user)
    user.invited_at.present? && user.invitation_accepted_at.nil? &&
      user.provider == 'email' && user.sign_in_count.to_i.zero? &&
      user.current_sign_in_at.nil? && user.last_sign_in_at.nil?
  end

  def self.next_at(user, deliveries = user.user_invitation_deliveries.to_a)
    times = [user.invitation_last_requested_at && user.invitation_last_requested_at + 5.minutes]
    recent = deliveries.select { |d| d.requested_at > 24.hours.ago }.sort_by(&:requested_at)
    times << recent[-3].requested_at + 24.hours if recent.size >= 3
    times.compact.max
  end

  def self.with_lock(user)
    User.transaction do
      User.connection.execute("SET LOCAL lock_timeout = '30s'")
      User.connection.execute("SET LOCAL statement_timeout = '35s'")
      user.with_lock { yield }
    end
  end

  def self.reserve!(user, actor:, origin: 'admin')
    raise Error.new('INVITATIONS_DISABLED', 503) unless enabled?
    user.with_lock do
      raise Error.new('INVITE_NOT_ELIGIBLE', 409) unless eligible?(user)
      raise Error.new('INVITE_IN_PROGRESS', 409) if user.user_invitation_deliveries.where(status: %w[queued sending]).exists?
      next_time = next_at(user)
      raise Error.new('INVITE_RATE_LIMITED', 429, next_time) if next_time && next_time > Time.current
      InvitationRateLimiter.consume!("actor:#{actor.id}", 50, 1.hour) if actor
      user.update!(reset_password_token: nil, reset_password_sent_at: nil, invitation_last_requested_at: Time.current)
      user.user_invitation_deliveries.create!(requested_by: actor, requested_at: Time.current, origin: origin)
    end
  end

  def self.accept!(user)
    return unless user.invited_at && !user.invitation_accepted_at
    user.update!(invitation_accepted_at: Time.current, reset_password_token: nil, reset_password_sent_at: nil)
    user.user_invitation_deliveries.where(status: %w[queued sending]).update_all(status: 'cancelled', finished_at: Time.current)
  end

  def self.data(user)
    deliveries = user.user_invitation_deliveries.to_a
    delivery = deliveries.max_by(&:requested_at)
    next_time = next_at(user, deliveries)
    state = user.invitation_accepted_at ? 'accepted' : (user.invited_at ? 'pending' : 'not_invited')
    { invitation_status: state, invitation_sent_at: user.invitation_sent_at,
      invitation_last_requested_at: user.invitation_last_requested_at,
      invitation_delivery_status: delivery&.status, invitation_error_code: delivery&.error_code,
      invitation_request_id: delivery&.id, next_resend_at: next_time&.iso8601,
      can_resend_invite: enabled? && eligible?(user) && !%w[queued sending].include?(delivery&.status) && (!next_time || next_time <= Time.current) }
  end
end
