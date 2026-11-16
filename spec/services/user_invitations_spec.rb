require 'rails_helper'
require 'sidekiq/testing'
Sidekiq::Testing.fake!

RSpec.describe UserInvitations do
  include ActiveSupport::Testing::TimeHelpers
  before do
    @flag = ENV['USER_INVITATIONS_ENABLED']
    ENV['USER_INVITATIONS_ENABLED'] = 'true'
    allow(InvitationRateLimiter).to receive(:consume!).and_return(true)
  end
  after { ENV['USER_INVITATIONS_ENABLED'] = @flag }
  let(:user) { User.create!(email: "invite-#{SecureRandom.hex(4)}@example.com", name: '<Teste>', password: 'Strong123!', confirmed_at: Time.current, invited_at: Time.current) }
  def reserve
    described_class.reserve!(user, actor: nil)
  end
  def expire_delivery(delivery)
    delivery.update!(status: 'failed')
    travel 301.seconds
  end

  it 'persists a request, invalidates the previous digest, and passes only the id to Redis' do
    user.update!(reset_password_token: 'old', reset_password_sent_at: Time.current)
    delivery = reserve
    expect(user.reload.reset_password_token).to be_nil
    expect(delivery.status).to eq('queued')
    delivery.dispatch
    expect(UserInvitationJob.jobs.last['args']).to eq([delivery.id])
  end
  it 'rejects legacy users' do
    user.update!(invited_at: nil)
    expect { reserve }.to raise_error(UserInvitations::Error, 'INVITE_NOT_ELIGIBLE')
  end
  it 'rejects users with evidence of access even without accepted_at' do
    user.update!(last_sign_in_at: Time.current)
    expect { reserve }.to raise_error(UserInvitations::Error, 'INVITE_NOT_ELIGIBLE')
  end
  it 'rejects SSO users' do
    user.update!(provider: 'google')
    expect { reserve }.to raise_error(UserInvitations::Error, 'INVITE_NOT_ELIGIBLE')
  end
  it 'checks in-progress before cooldown without inserting another request' do
    reserve
    expect { reserve }.to raise_error(UserInvitations::Error, 'INVITE_IN_PROGRESS')
    expect(user.user_invitation_deliveries.count).to eq(1)
  end
  it 'counts failures against the cooldown and daily ceiling' do
    delivery = reserve
    delivery.update!(status: 'failed')
    expect { reserve }.to raise_error(UserInvitations::Error, 'INVITE_RATE_LIMITED')
    travel 301.seconds
    expire_delivery(reserve)
    expire_delivery(reserve)
    expect { reserve }.to raise_error(UserInvitations::Error, 'INVITE_RATE_LIMITED')
    travel 24.hours
    expect(reserve).to be_persisted
  end
  it 'fails closed when disabled' do
    ENV['USER_INVITATIONS_ENABLED'] = 'false'
    expect { reserve }.to raise_error(UserInvitations::Error, 'INVITATIONS_DISABLED')
  end
  it 'retains durable queued requests when enqueue fails' do
    delivery = reserve
    allow(UserInvitationJob).to receive(:perform_async).and_raise(Redis::CannotConnectError)
    expect { delivery.dispatch }.not_to raise_error
    expect(delivery.reload.status).to eq('queued')
  end
  it 'delivers once, records SMTP acceptance, and never stores raw tokens in the outbox' do
    delivery = reserve
    tokens = []
    allow(UserMailer).to receive(:invitation) do |recipient, token|
      tokens << token.to_s
      expect(recipient.id).to eq(user.id)
      double(deliver_now: true)
    end
    2.times { UserInvitationJob.new.perform(delivery.id) }
    expect(tokens.size).to eq(1)
    expect(delivery.reload.status).to eq('sent')
    expect(user.reload.invitation_sent_at).to be_present
    expect(user.reset_password_token).not_to eq(tokens.first)
    expect(delivery.attributes.to_s).not_to include(tokens.first)
    expect(User.with_reset_password_token(tokens.first).id).to eq(user.id)
  end
  it 'classifies authentication rejection as failed and removes its digest' do
    delivery = reserve
    allow(UserMailer).to receive(:invitation).and_raise(Net::SMTPAuthenticationError.new('535 invalid'))
    UserInvitationJob.new.perform(delivery.id)
    expect(delivery.reload.status).to eq('failed')
    expect(delivery.error_code).to eq('SMTP_AUTH_FAILED')
    expect(user.reload.reset_password_token).to be_nil
  end
  it 'classifies transport uncertainty without retrying or invalidating a possibly delivered link' do
    delivery = reserve
    allow(UserMailer).to receive(:invitation).and_raise(Net::ReadTimeout)
    UserInvitationJob.new.perform(delivery.id)
    expect(delivery.reload.status).to eq('uncertain')
    expect(user.reload.reset_password_token).to be_present
    expect(UserMailer).not_to receive(:invitation)
    UserInvitationJob.new.perform(delivery.id)
  end
  it 'never sends an orphan queued more than ten minutes' do
    delivery = reserve
    travel 11.minutes
    expect(UserMailer).not_to receive(:invitation)
    UserInvitationJob.new.perform(delivery.id)
    expect(delivery.reload.error_code).to eq('QUEUE_TIMEOUT')
  end
  it 'watchdogs interrupted sends and preserves completed sends' do
    delivery = reserve
    delivery.update!(status: 'sending', started_at: 3.minutes.ago)
    UserInvitationSweepJob.new.perform
    expect(delivery.reload.status).to eq('uncertain')
    delivery.update!(status: 'sent')
    UserInvitationSweepJob.new.perform
    expect(delivery.reload.status).to eq('sent')
  end
  it 'sweeps queued work after enqueue outage' do
    delivery = reserve
    expect(UserInvitationJob).to receive(:perform_async).with(delivery.id)
    UserInvitationSweepJob.new.perform
  end
  it 'consumes a token once and accepts pending invitation atomically' do
    raw, digest = Devise.token_generator.generate(User, :reset_password_token)
    user.update!(reset_password_token: digest, reset_password_sent_at: Time.current)
    PasswordRecovery.consume!(raw, 'Changed123!', 'Changed123!')
    expect(user.reload.invitation_accepted_at).to be_present
    expect(user.valid_password?('Changed123!')).to be true
    expect { PasswordRecovery.consume!(raw, 'Other123!', 'Other123!') }.to raise_error(UserInvitations::Error, 'INVALID_OR_EXPIRED_TOKEN')
  end
  it 'retains token after weak password and rejects expired token uniformly' do
    raw, digest = Devise.token_generator.generate(User, :reset_password_token)
    user.update!(reset_password_token: digest, reset_password_sent_at: Time.current)
    expect { PasswordRecovery.consume!(raw, 'weak', 'weak') }.to raise_error(ActiveRecord::RecordInvalid)
    expect(user.reload.reset_password_token).to eq(digest)
    travel 6.hours + 1.second
    expect { PasswordRecovery.consume!(raw, 'Changed123!', 'Changed123!') }.to raise_error(UserInvitations::Error, 'INVALID_OR_EXPIRED_TOKEN')
  end
  it 'invalidates the old link as soon as resend is reserved' do
    raw, digest = Devise.token_generator.generate(User, :reset_password_token)
    user.update!(reset_password_token: digest, reset_password_sent_at: Time.current)
    reserve
    expect { PasswordRecovery.consume!(raw, 'Changed123!', 'Changed123!') }.to raise_error(UserInvitations::Error)
  end
  it 'accepts and invalidates on authenticated session issuance' do
    delivery = reserve
    user.with_lock { described_class.accept!(user) }
    expect(delivery.reload.status).to eq('cancelled')
    expect { reserve }.to raise_error(UserInvitations::Error, 'INVITE_NOT_ELIGIBLE')
  end
  it 'has no invitation state for legacy and keeps SMTP failure pending' do
    user.update!(invited_at: nil)
    expect(described_class.data(user)[:invitation_status]).to eq('not_invited')
    user.update!(invited_at: Time.current)
    reserve.update!(status: 'failed')
    expect(described_class.data(user)[:invitation_status]).to eq('pending')
  end
  it 'accepts on OAuth issuance (common path for password, completed MFA and SSO)' do
    delivery = reserve
    application = OauthApplication.create!(name: 'N4 synthetic', uid: SecureRandom.hex(8), secret: 'synthetic', redirect_uri: 'urn:ietf:wg:oauth:2.0:oob', scopes: 'read write')
    Doorkeeper::AccessToken.create!(application: application, resource_owner_id: user.id, scopes: 'read write', expires_in: 7200)
    expect(user.reload.invitation_accepted_at).to be_present
    expect(user.sign_in_count).to eq(1)
    expect(delivery.reload.status).to eq('cancelled')
  end
  it 'accepts and persists the alternative Devise session under lock' do
    delivery = reserve
    token = user.create_token
    expect(user.reload.invitation_accepted_at).to be_present
    expect(user.tokens).to have_key(token.client)
    expect(delivery.reload.status).to eq('cancelled')
  end
  it 'cancels before SMTP when the temporary production allowlist excludes the target' do
    previous = ENV['USER_INVITATIONS_RECIPIENT_ALLOWLIST']
    ENV['USER_INVITATIONS_RECIPIENT_ALLOWLIST'] = 'ricardohenrique@agenciavetorial.com'
    delivery = reserve
    expect(UserMailer).not_to receive(:invitation)
    UserInvitationJob.new.perform(delivery.id)
    expect(delivery.reload.status).to eq('cancelled')
  ensure
    ENV['USER_INVITATIONS_RECIPIENT_ALLOWLIST'] = previous
  end

end
