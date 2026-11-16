require 'rails_helper'
RSpec.describe 'User invitations', type: :request do
  before do
    @flag = ENV['USER_INVITATIONS_ENABLED']
    ENV['USER_INVITATIONS_ENABLED'] = 'true'
    load Rails.root.join('db/seeds/rbac.rb')
    allow(InvitationRateLimiter).to receive(:consume!).and_return(true)
  end
  after { ENV['USER_INVITATIONS_ENABLED'] = @flag }
  let(:admin) do
    user = User.create!(name: 'N4 Synthetic', email: 'admin-n4@example.com', password: 'Strong123!', confirmed_at: Time.current)
    UserRole.create!(user: user, role: Role.find_by!(key: 'super_admin'))
    user
  end
  let(:target) { User.create!(name: 'N4 Synthetic', email: 'target-n4@example.com', password: 'Strong123!', confirmed_at: Time.current, invited_at: Time.current) }
  def headers(user)
    token = AccessToken.create!(owner: user, name: SecureRandom.hex(4), scopes: 'default')
    { 'api_access_token' => token.token, 'Host' => 'localhost' }
  end
  it 'queues authorized resend and audits actor, never returns token' do
    post "/api/v1/users/#{target.id}/resend_invite", headers: headers(admin), as: :json
    expect(response).to have_http_status(:accepted)
    body = response.parsed_body
    expect(body.dig('data', 'delivery_status')).to eq('queued')
    expect(body.to_s).not_to include('reset_password_token')
    expect(target.user_invitation_deliveries.last.requested_by_id).to eq(admin.id)
  end
  it 'denies before lookup for user with only read permission' do
    role = Role.create!(name: 'Reader N4', key: 'reader-n4', type: 'user')
    role.role_permissions_actions.create!(permission_key: 'users.read')
    UserRole.create!(user: target, role: role)
    post "/api/v1/users/#{SecureRandom.uuid}/resend_invite", headers: headers(target), as: :json
    expect(response).to have_http_status(:forbidden)
  end
  it 'reports processing and cooldown with Retry-After' do
    delivery = UserInvitations.reserve!(target, actor: admin)
    post "/api/v1/users/#{target.id}/resend_invite", headers: headers(admin), as: :json
    expect(response).to have_http_status(:conflict)
    delivery.update!(status: 'failed')
    post "/api/v1/users/#{target.id}/resend_invite", headers: headers(admin), as: :json
    expect(response).to have_http_status(:too_many_requests)
    expect(response.headers['Retry-After'].to_i).to be > 0
  end
  it 'deduplicates bulk and returns actual partial successes, preserving existing users' do
    post '/api/v1/users/bulk_create', params: { emails: [' NEW@example.com ', 'new@example.com', target.email], role: 'agent' }, headers: headers(admin), as: :json
    expect(response).to have_http_status(:ok)
    expect(response.parsed_body.dig('data', 'count')).to eq(1)
    expect(response.parsed_body.dig('data', 'failed_invitations').size).to eq(1)
  end
  it 'blocks oversized and disabled batches' do
    post '/api/v1/users/bulk_create', params: { emails: Array.new(51, 'x@example.com') }, headers: headers(admin), as: :json
    expect(response).to have_http_status(:unprocessable_entity)
    ENV['USER_INVITATIONS_ENABLED'] = 'false'
    post '/api/v1/users/bulk_create', params: { emails: ['x@example.com'] }, headers: headers(admin), as: :json
    expect(response).to have_http_status(:service_unavailable)
  end
  it 'exposes invitation state only to administrative readers' do
    target
    get '/api/v1/users', headers: headers(admin)
    expect(response.parsed_body.dig('data').find { |u| u['id'] == target.id }['invitation_status']).to eq('pending')
    role = Role.create!(name: 'Reader N4', key: 'reader-n4', type: 'user')
    role.role_permissions_actions.create!(permission_key: 'users.read')
    UserRole.create!(user: target, role: role)
    get '/api/v1/users', headers: headers(target)
    expect(response.body).not_to include('invitation_status', 'invitation_request_id')
  end
  it 'returns uniform 202 on both recovery routes regardless of address or malicious redirect' do
    ['/api/v1/auth/forgot_password', '/auth/password'].each do |path|
      bodies = [target.email, 'missing@example.com'].map do |email|
        post path, params: { email: email, redirect_url: 'https://attacker.example' }, headers: { 'Host' => 'localhost' }, as: :json
        expect(response).to have_http_status(:accepted)
        response.parsed_body
      end
      expect(bodies[0]).to eq(bodies[1])
    end
  end
  it 'denies unauthenticated requests and service tokens before target lookup' do
    post "/api/v1/users/#{SecureRandom.uuid}/resend_invite", headers: { 'Host' => 'localhost' }, as: :json
    expect(response).to have_http_status(:unauthorized)
    previous = ENV['EVOAI_CRM_API_TOKEN']
    ENV['EVOAI_CRM_API_TOKEN'] = 'n4-service-synthetic'
    post "/api/v1/users/#{SecureRandom.uuid}/resend_invite", headers: { 'Host' => 'localhost', 'X-Internal-API-Token' => 'n4-service-synthetic' }, as: :json
    expect(response).to have_http_status(:forbidden)
  ensure
    ENV['EVOAI_CRM_API_TOKEN'] = previous
  end
  it 'requires update as well as manage, with no fallback bypass' do
    role = Role.create!(name: 'Manage only N4', key: 'manage-only-n4', type: 'user')
    role.role_permissions_actions.create!(permission_key: 'users.manage')
    UserRole.create!(user: target, role: role)
    post "/api/v1/users/#{SecureRandom.uuid}/resend_invite", headers: headers(target), as: :json
    expect(response).to have_http_status(:forbidden)
  end
  it 'returns a scoped 404 for an administrator' do
    post "/api/v1/users/#{SecureRandom.uuid}/resend_invite", headers: headers(admin), as: :json
    expect(response).to have_http_status(:not_found)
    expect(response.parsed_body.dig('error', 'code')).to eq('USER_NOT_FOUND')
  end
  it 'blocks missing-password creation while capability is off and keeps explicit password creation' do
    ENV['USER_INVITATIONS_ENABLED'] = 'false'
    post '/api/v1/users', params: { email: 'created-n4@example.com', name: 'N4 test' }, headers: headers(admin), as: :json
    expect(response).to have_http_status(:service_unavailable)
    post '/api/v1/users', params: { email: 'created-n4@example.com', name: 'N4 test', password: 'Strong123!' }, headers: headers(admin), as: :json
    expect(response).to have_http_status(:created)
    expect(response.parsed_body.dig('data', 'user', 'invitation_status')).to eq('not_invited')
  end
  it 'GET of a mail link leaves the digest untouched and never creates a session' do
    raw, digest = Devise.token_generator.generate(User, :reset_password_token)
    target.update!(reset_password_token: digest, reset_password_sent_at: Time.current)
    expect { get '/auth/password/edit', params: { reset_password_token: raw }, headers: { 'Host' => 'localhost' } }.not_to change(Doorkeeper::AccessToken, :count)
    expect(response).to have_http_status(:found)
    expect(response.headers['Location']).to start_with('https://evo.agenciavetorial.com/auth/reset-password?')
    expect(target.reload.reset_password_token).to eq(digest)
  end
  it 'accepts an invitation through the mounted Devise password route without auto login' do
    raw, digest = Devise.token_generator.generate(User, :reset_password_token)
    target.update!(reset_password_token: digest, reset_password_sent_at: Time.current)
    put '/auth/password', params: { reset_password_token: raw, password: 'Changed123!', password_confirmation: 'Changed123!' }, headers: { 'Host' => 'localhost' }, as: :json
    expect(response).to have_http_status(:ok)
    expect(target.reload.invitation_accepted_at).to be_present
    expect(target.reset_password_token).to be_nil
    expect(target.tokens).to eq({})
  end

end
