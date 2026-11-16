class DeviseOverrides::PasswordsController < DeviseTokenAuth::PasswordsController
  # The inherited callback requires a caller-controlled redirect. It is unused here.
  skip_before_action :validate_redirect_url_param, raise: false

  def create
    PasswordRecovery.request(params[:email] || params.dig(:user, :email), request.remote_ip)
    render json: { success: true, data: {}, message: PasswordRecovery::MESSAGE }, status: :accepted
  end

  def edit
    response.set_header('Referrer-Policy', 'no-referrer')
    redirect_to PasswordRecovery.url(params[:reset_password_token]), allow_other_host: true
  end

  def update
    PasswordRecovery.consume!(params[:reset_password_token], params[:password], params[:password_confirmation])
    render json: { success: true, message: 'Senha definida. Entre com seu e-mail e senha.' }
  rescue UserInvitations::Error, ActiveRecord::RecordInvalid
    render json: { success: false, error: { code: 'INVALID_OR_EXPIRED_TOKEN' } }, status: :unprocessable_entity
  end
end
