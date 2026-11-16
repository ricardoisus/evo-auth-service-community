require 'rails_helper'
RSpec.describe UserMailer, type: :mailer do
  it 'renders escaped multipart pt-BR mail with fixed HTTPS origin, no tracking and bounded SMTP' do
    user = User.new(name: '<img src=x>', email: 'ricardohenrique@agenciavetorial.com')
    mail = described_class.invitation(user, 'synthetic-token').message
    expect(mail.subject).to eq('Seu convite para o Evo CRM da Vetorial')
    expect(mail.from).to eq(['envio-automatico@agenciavetorial.com'])
    expect(mail.to).to eq(['ricardohenrique@agenciavetorial.com'])
    expect(mail.text_part.body.decoded).to include('6 horas', 'purpose=invite')
    expect(mail.html_part.body.decoded).to include('&lt;img src=x&gt;')
    expect(mail.html_part.body.decoded).not_to include('<img', '<script', 'http://')
  end
  it 'rejects origin override' do
    original = ENV['FRONTEND_URL']
    ENV['FRONTEND_URL'] = 'https://attacker.example'
    expect { PasswordRecovery.url('synthetic') }.to raise_error('Invalid frontend origin')
  ensure
    ENV['FRONTEND_URL'] = original
  end
end
