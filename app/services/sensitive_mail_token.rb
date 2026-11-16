# Keep ActionMailer process-action arguments safe to inspect/serialize in APM.
# The string is exposed only while constructing the URL in mailer memory.
class SensitiveMailToken
  def initialize(value)
    @value = value
  end

  def to_s
    @value
  end

  def inspect
    '[FILTERED]'
  end

  def as_json(*)
    '[FILTERED]'
  end
end
