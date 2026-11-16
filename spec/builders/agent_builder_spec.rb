require 'rails_helper'
RSpec.describe AgentBuilder do
  before do
    @flag = ENV['USER_INVITATIONS_ENABLED']
    ENV['USER_INVITATIONS_ENABLED'] = 'true'
    allow(InvitationRateLimiter).to receive(:consume!).and_return(true)
    Role.find_or_create_by!(key: 'agent') { |r| r.name = 'Agent'; r.type = 'user' }
  end
  after { ENV['USER_INVITATIONS_ENABLED'] = @flag }
  it 'creates confirmed pending user and durable outbox in one transaction' do
    user = described_class.new(email: 'new@example.com', inviter: nil).perform
    expect(user.confirmed?).to be true
    expect(user.invited_at).to be_present
    expect(user.user_invitation_deliveries.count).to eq(1)
  end
  it 'keeps explicit-password creation without invitation when flag is off' do
    ENV['USER_INVITATIONS_ENABLED'] = 'false'
    user = described_class.new(email: 'new@example.com', password: 'Strong123!', inviter: nil).perform
    expect(user.valid_password?('Strong123!')).to be true
    expect(user.invited_at).to be_nil
    expect(user.user_invitation_deliveries.count).to eq(0)
  end
  it 'rejects existing address without mutating password or role' do
    user = User.create!(name: 'N4 Synthetic', email: 'exists@example.com', password: 'Strong123!')
    expect { described_class.new(email: user.email, inviter: nil).perform }.to raise_error(UserInvitations::Error, 'USER_NOT_CREATED')
    expect(user.reload.valid_password?('Strong123!')).to be true
    expect(user.roles.count).to eq(0)
  end
  it 'rejects unknown role and rolls back user and invitation' do
    expect { described_class.new(email: 'new@example.com', role: 'missing', inviter: nil).perform }.to raise_error(UserInvitations::Error, 'USER_NOT_CREATED')
    expect(User.from_email('new@example.com')).to be_nil
  end
  it 'rolls back creation when limiter is unavailable' do
    allow(InvitationRateLimiter).to receive(:consume!).and_raise(UserInvitations::Error.new('INVITE_QUEUE_UNAVAILABLE', 503))
    actor = User.create!(name: 'N4 Synthetic', email: 'actor@example.com', password: 'Strong123!')
    expect { described_class.new(email: 'new@example.com', inviter: actor).perform }.to raise_error(UserInvitations::Error)
    expect(User.from_email('new@example.com')).to be_nil
  end
end
