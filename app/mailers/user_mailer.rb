# frozen_string_literal: true

class UserMailer < ApplicationMailer
  # ActionMailer debug output includes full MIME content, including reset links.
  self.logger = ActiveSupport::Logger.new(File::NULL)
  after_action :bound_invitation_transport

  def invitation(user, raw_token)
    @user = user
    @reset_url = PasswordRecovery.url(raw_token, invite: true)
    mail(to: user.email, from: 'Agência Vetorial <envio-automatico@agenciavetorial.com>',
         subject: 'Seu convite para o Evo CRM da Vetorial')
  end

  def password_recovery(user, raw_token)
    @user = user
    @reset_url = PasswordRecovery.url(raw_token)
    mail(to: user.email, from: 'Agência Vetorial <envio-automatico@agenciavetorial.com>',
         subject: 'Redefina sua senha do Evo CRM da Vetorial')
  end

  def bound_invitation_transport
    return unless %w[invitation password_recovery].include?(action_name)
    message.delivery_method.settings.merge!(open_timeout: 10, read_timeout: 15, write_timeout: 15) if message.delivery_method.respond_to?(:settings)
  end

  def two_factor_authentication_code(user, code)
    @user = user
    @code = code

    mail(
      to: user.email,
      subject: "Your verification code: #{code}"
    )
  end
end
