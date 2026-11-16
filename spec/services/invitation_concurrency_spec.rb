require 'rails_helper'
# Real connections, committed fixtures: transactional test fixtures would hide
# the row from the competing connection and make this proof meaningless.
RSpec.describe 'Invitation races', type: :model do
  self.use_transactional_tests = false
  before do
    @flag = ENV['USER_INVITATIONS_ENABLED']
    ENV['USER_INVITATIONS_ENABLED'] = 'true'
    @user = User.create!(name: 'N4 race synthetic', email: "n4-race-#{SecureRandom.hex(6)}@example.com",
                         password: 'Strong123!', confirmed_at: Time.current, invited_at: Time.current)
  end
  after do
    @user.destroy!
    ENV['USER_INVITATIONS_ENABLED'] = @flag
  end
  def race(*operations)
    gate, ready, results = Queue.new, Queue.new, Queue.new
    threads = operations.map do |operation|
      Thread.new do
        ActiveRecord::Base.connection_pool.with_connection do |connection|
          ready << connection.select_value('SELECT pg_backend_pid()')
          gate.pop
          begin
            results << operation.call
          rescue UserInvitations::Error => error
            results << error.code
          end
        end
      end
    end
    pids = operations.size.times.map { ready.pop }
    expect(pids.uniq.size).to eq(operations.size)
    operations.size.times { gate << true }
    threads.each(&:join)
    operations.size.times.map { results.pop }
  end
  def token
    raw, digest = Devise.token_generator.generate(User, :reset_password_token)
    @user.update!(reset_password_token: digest, reset_password_sent_at: Time.current)
    raw
  end
  it 'serializes resend versus resend into exactly one request' do
    action = -> { UserInvitations.reserve!(User.find(@user.id), actor: nil); 'queued' }
    expect(race(action, action)).to contain_exactly('queued', 'INVITE_IN_PROGRESS')
    expect(@user.user_invitation_deliveries.count).to eq(1)
  end
  it 'serializes consumption versus consumption into one password update' do
    raw = token
    action = -> { PasswordRecovery.consume!(raw, 'Changed123!', 'Changed123!'); 'accepted' }
    expect(race(action, action)).to contain_exactly('accepted', 'INVALID_OR_EXPIRED_TOKEN')
    expect(@user.reload.invitation_accepted_at).to be_present
  end
  it 'serializes resend versus reset: only the winning operation succeeds' do
    raw = token
    resend = -> { UserInvitations.reserve!(User.find(@user.id), actor: nil); 'queued' }
    consume = -> { PasswordRecovery.consume!(raw, 'Changed123!', 'Changed123!'); 'accepted' }
    result = race(resend, consume)
    expect([['queued', 'INVALID_OR_EXPIRED_TOKEN'].sort, ['INVITE_NOT_ELIGIBLE', 'accepted'].sort]).to include(result.sort)
    expect(@user.reload.reset_password_token).to be_nil
  end
  it 'serializes worker versus resend without duplicating delivery' do
    delivery = UserInvitations.reserve!(@user, actor: nil)
    expect(UserMailer).to receive(:invitation).once.and_return(double(deliver_now: true))
    worker = -> { UserInvitationJob.new.perform(delivery.id); 'processed' }
    resend = -> { UserInvitations.reserve!(User.find(@user.id), actor: nil); 'unexpected' }
    result = race(worker, resend)
    expect(result).to include('processed')
    expect(result & %w[INVITE_IN_PROGRESS INVITE_RATE_LIMITED]).not_to be_empty
    expect(delivery.reload.status).to eq('sent')
    expect(@user.user_invitation_deliveries.count).to eq(1)
  end
  it 'shares the outbox limits between public recovery and administrative resend' do
    email = PasswordRecovery.encryptor.encrypt_and_sign(@user.email)
    recovery = -> { PasswordRecoveryJob.new.perform(email); 'recovery processed' }
    resend = -> { UserInvitations.reserve!(User.find(@user.id), actor: nil); 'queued' }
    race(recovery, resend)
    expect(@user.user_invitation_deliveries.count).to eq(1)
    expect(@user.reload.reset_password_token).to be_nil
  end

end
