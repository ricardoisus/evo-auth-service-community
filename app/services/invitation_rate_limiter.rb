class InvitationRateLimiter
  SCRIPT = <<~LUA.freeze
    local count = redis.call('INCR', KEYS[1])
    if count == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
    return count
  LUA

  def self.consume!(key, limit, period)
    count = Sidekiq.redis { |redis| redis.call("EVAL", SCRIPT, 1, "user-invitation:#{key}", period.to_i) }
    raise UserInvitations::Error.new('INVITE_RATE_LIMITED', 429, Time.current + period) if count > limit
    true
  rescue UserInvitations::Error
    raise
  rescue StandardError
    raise UserInvitations::Error.new('INVITE_QUEUE_UNAVAILABLE', 503)
  end
end
