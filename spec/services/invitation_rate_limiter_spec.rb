require 'rails_helper'
RSpec.describe InvitationRateLimiter do
  it 'uses an atomic Redis counter with expiry and denies the next request' do
    key = "test:#{SecureRandom.hex(6)}"
    expect(described_class.consume!(key, 1, 60)).to be true
    expect { described_class.consume!(key, 1, 60) }.to raise_error(UserInvitations::Error, 'INVITE_RATE_LIMITED')
    ttl = Sidekiq.redis { |redis| redis.ttl("user-invitation:#{key}") }
    expect(ttl).to be_between(1, 60)
  end
  it 'fails closed on Redis outage' do
    allow(Sidekiq).to receive(:redis).and_raise(IOError)
    expect { described_class.consume!('outage', 1, 60) }.to raise_error(UserInvitations::Error, 'INVITE_QUEUE_UNAVAILABLE')
  end
end
