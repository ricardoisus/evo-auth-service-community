require 'rails_helper'
require 'socket'
RSpec.describe 'Invitation local SMTP integration' do
  it 'delivers to the local sink and supports definition, password verification, and replay rejection without internet' do
    flag = ENV['USER_INVITATIONS_ENABLED']
    ENV['USER_INVITATIONS_ENABLED'] = 'true'
    server = TCPServer.new('127.0.0.1', 0)
    port = server.addr[1]
    received = Queue.new
    sink = Thread.new do
      client = server.accept
      client.write("220 localhost SMTP ready\r\n")
      data, reading = '', false
      while line = client.gets
        if reading
          if line == ".\r\n"
            received << data
            reading = false
            client.write("250 accepted\r\n")
          else
            data << line
          end
        elsif line.start_with?('DATA')
          reading = true
          client.write("354 send data\r\n")
        elsif line.start_with?('QUIT')
          client.write("221 bye\r\n")
          break
        else
          client.write("250 OK\r\n")
        end
      end
      client.close
    end
    values = { 'SMTP_ADDRESS' => '127.0.0.1', 'SMTP_PORT' => port,
               'SMTP_ENABLE_STARTTLS_AUTO' => false, 'SMTP_USERNAME' => nil }
    allow(GlobalConfigService).to receive(:load) { |key, default = nil| values.fetch(key, default) }
    user = User.create!(name: 'N4 Synthetic', email: 'ricardohenrique@agenciavetorial.com',
                        password: 'Strong123!', confirmed_at: Time.current, invited_at: Time.current)
    delivery = UserInvitations.reserve!(user, actor: nil)
    UserInvitationJob.new.perform(delivery.id)
    expect(delivery.reload.status).to eq('sent')
    expect(user.reload.invitation_accepted_at).to be_nil
    mime = Mail.read_from_string(received.pop)
    expect(mime.to).to eq(['ricardohenrique@agenciavetorial.com'])
    url = mime.text_part.body.decoded[/https:\/\/evo[^\s]+/]
    raw = URI.decode_www_form(URI(url).query).to_h.fetch('reset_password_token')
    PasswordRecovery.consume!(raw, 'Changed123!', 'Changed123!')
    expect(user.reload.valid_password?('Changed123!')).to be true
    expect(UserInvitations.eligible?(user)).to be false
    expect { PasswordRecovery.consume!(raw, 'Changed123!', 'Changed123!') }.to raise_error(UserInvitations::Error, 'INVALID_OR_EXPIRED_TOKEN')
  ensure
    ENV['USER_INVITATIONS_ENABLED'] = flag
    server&.close
    sink&.join(2)
    sink&.kill if sink&.alive?
  end
end
