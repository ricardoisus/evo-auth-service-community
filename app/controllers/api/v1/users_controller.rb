class Api::V1::UsersController < Api::BaseController
  AUTHZ_CACHE_TTL = 60.seconds

  # Authorization first, or the lookup leaks an id's existence to a caller
  # without users.read.
  before_action :check_authorization
  before_action :fetch_user, except: [:create, :index, :bulk_create, :invitation_capabilities]

  def index
    @users = Users::FilterService.new(params[:filters], params[:q], params[:sort], params[:order],
                                      relation: users_index_scope).resolve

    apply_pagination
    @users = @users.includes(:user_invitation_deliveries) if UserInvitations.administrator?(current_user)

    paginated_response(
      data: @users.map { |user| serialize_directory_user(user) },
      collection: @users,
      message: 'Users retrieved successfully'
    )
  end

  def create
    builder = AgentBuilder.new(
      email: new_user_params['email'],
      name: new_user_params['name'],
      # The form sends the user's chosen password and the controller permits it
      # in `new_user_params`. Forward it so AgentBuilder uses it instead of
      # silently generating a random one — otherwise the user is created with
      # a password they don't know and login always returns 401.
      password: new_user_params['password'],
      role: new_user_params['role'].presence || 'agent',
      availability: new_user_params['availability'],
      inviter: current_user
    )

    @user = builder.perform
    success_response(
      data: { user: serialize_user(@user) },
      message: 'User created successfully',
      status: :created
    )
  rescue UserInvitations::Error => error
    invitation_error(error)
  rescue ActiveRecord::RecordNotUnique
    error_response('USER_NOT_CREATED', 'Não foi possível criar este usuário.', status: :unprocessable_entity)
  rescue ActiveRecord::RecordInvalid => e
    error_response(
      ApiErrorCodes::VALIDATION_ERROR,
      'Validation failed',
      details: format_validation_errors(e.record.errors),
      status: :unprocessable_entity
    )
  end

  def update
    ActiveRecord::Base.transaction do
      @user.update!(user_params.slice(:name, :availability).compact)

      if user_params[:role].present?
        update_user_role(user_params[:role])
      end
    end

    success_response(
      data: { user: serialize_user(@user) },
      message: 'User updated successfully'
    )
  rescue StandardError => e
    Rails.logger.error "❌ Error updating user: #{e.message}"
    Rails.logger.error e.backtrace.join("\n")
    error_response('VALIDATION_ERROR', e.message, status: :unprocessable_entity)
  end

  def destroy
    if @user.id == current_user.id
      return error_response('SELF_DELETION', 'You cannot delete your own account', status: :unprocessable_entity)
    end

    @user.destroy!
    success_response(
      data: { id: @user.id },
      message: 'User deleted successfully'
    )
  end

  def bulk_create
    emails = params[:emails]
    unless emails.is_a?(Array) && emails.any? && emails.size <= 50 && emails.all? { |email| email.is_a?(String) }
      return error_response('VALIDATION_ERROR', 'Informe até 50 endereços.', status: :unprocessable_entity)
    end
    return error_response('INVITATIONS_DISABLED', 'Convites indisponíveis.', status: :service_unavailable) unless UserInvitations.enabled?
    invited, failed = [], []
    emails.map { |email| email.strip.downcase }.uniq.each do |email|
      begin
        user = AgentBuilder.new(email: email, name: email.split('@').first,
                                role: params[:role].presence || 'agent', inviter: current_user).perform
        invited << serialize_user(user).slice(:id, :email, :name, :invitation_status, :invitation_delivery_status)
      rescue ActiveRecord::RecordInvalid, ActiveRecord::RecordNotUnique, UserInvitations::Error
        failed << { email: email, code: 'USER_NOT_CREATED', error: 'Não foi possível criar este usuário. Revise os dados ou a lista de usuários.' }
      end
    end
    success_response(data: { count: invited.size, invited_users: invited, failed_invitations: failed },
                     message: 'Convites solicitados.', status: invited.empty? ? :unprocessable_entity : :ok)
  end

  def resend_invite
    delivery = UserInvitations.reserve!(@user, actor: current_user)
    success_response(data: { user_id: @user.id, invitation_status: 'pending', delivery_status: 'queued',
                            request_id: delivery.id, next_resend_at: UserInvitations.next_at(@user)&.iso8601 },
                     message: 'Reenvio solicitado.', status: :accepted)
  rescue UserInvitations::Error => error
    invitation_error(error)
  end

  def invitation_capabilities
    success_response(data: { user_invitations_enabled: UserInvitations.enabled? && UserInvitations.administrator?(current_user) })
  end

  def check_permission
    permission_key = params[:permission_key]

    return error_response('VALIDATION_ERROR', 'Permission key is required', status: :bad_request) if permission_key.blank?

    has_permission = Rails.cache.fetch(
      permission_cache_key(@user.id, permission_key),
      expires_in: AUTHZ_CACHE_TTL
    ) do
      @user.has_permission?(permission_key)
    end

    success_response(data: {
      permission_key: permission_key,
      has_permission: has_permission,
      role: @user.role_data
    }, message: has_permission ? 'Permission granted' : 'Permission denied')
  end

  def role
    role_data = Rails.cache.fetch(
      role_cache_key(@user.id),
      expires_in: AUTHZ_CACHE_TTL
    ) do
      @user.role_data
    end

    success_response(
      data: { role: role_data },
      message: 'User role retrieved successfully'
    )
  end

  # CRM-210: admin sets another user's password. users.manage is required on top
  # of users.reset_password via administrative_action?. Revoking the target's
  # sessions is deliberate — a stolen one must not outlive the reset.
  def set_password
    @user.with_lock { set_password_under_lock }
  end

  def set_password_under_lock
    # Target guards run BEFORE input validation: a caller who may not touch this
    # user gets 403, not a 422 teaching it the password policy first.
    if @user.id == current_user.id
      return error_response('FORBIDDEN', 'Use the account settings flow to change your own password',
                            status: :forbidden)
    end

    if target_outranks_caller?
      return error_response('FORBIDDEN', "You cannot set a super_admin's password", status: :forbidden)
    end

    password = params[:password].to_s
    confirmation = params[:password_confirmation].to_s

    return error_response('VALIDATION_ERROR', 'Password is required', status: :unprocessable_entity) if password.blank?

    if password != confirmation
      return error_response('VALIDATION_ERROR', 'Password confirmation does not match',
                            details: [{ field: 'password_confirmation', message: 'does not match password' }],
                            status: :unprocessable_entity)
    end

    @user.password = password
    @user.password_confirmation = confirmation

    unless @user.save
      # The model's password_complexity validation is what rejects weak input —
      # this endpoint deliberately does not relax it for admins.
      return error_response('VALIDATION_ERROR', @user.errors.full_messages.join(', '),
                            status: :unprocessable_entity)
    end

    revoked = revoke_active_sessions_for(@user)

    # Audit trail: who reset whose password, and how many sessions died with it.
    Rails.logger.warn(
      "[Users#set_password] actor=#{current_user.id} target=#{@user.id} revoked_tokens=#{revoked}"
    )

    success_response(
      data: { success: true, revoked_sessions: revoked },
      message: 'Password updated successfully. The user has been signed out of all sessions.'
    )
  end

  private

  # Mirrors auth#reset_password: drop the cached validations first, then revoke,
  # so a token cannot be served from cache after being revoked.
  def revoke_active_sessions_for(user)
    active = Doorkeeper::AccessToken.where(resource_owner_id: user.id, revoked_at: nil)
    active.pluck(:token).each { |t| TokenValidationService.invalidate_cache_for_token(t) }
    active.update_all(revoked_at: Time.current)
  end

  def target_outranks_caller?
    target_super_admin = @user.roles.exists?(key: 'super_admin')
    return false unless target_super_admin

    !current_user.roles.exists?(key: 'super_admin')
  end

  def serialize_directory_user(user)
    data = UserSerializer.directory(user)
    data.merge!(UserInvitations.data(user)) if UserInvitations.administrator?(current_user)
    data
  end

  def serialize_user(user)
    UserSerializer.for_reader(user, current_user)
  end

  def invitation_error(error)
    if error.next_at
      response.set_header('Retry-After', [(error.next_at - Time.current).ceil, 1].max.to_s)
    end
    error_response(error.code, 'Não foi possível solicitar o convite.',
                   details: { next_resend_at: error.next_at&.iso8601 }, status: error.status)
  end

  def update_user_role(role_key)
    system_role = Role.find_by(key: role_key)
    raise ActiveRecord::RecordNotFound, "Role '#{role_key}' not found" unless system_role

    existing = replaceable_roles_of(@user)
    existing.destroy_all if existing.exists?

    UserRole.assign_role_to_user(@user, system_role, current_user)
  end

  # Every grant the update replaces. Revoking only `system: false` roles meant
  # revoking nothing at all — the seeded roles are all system — so a promotion
  # added a second role instead of replacing the first (CRM-496). Derived rows
  # are excluded because the attendance-permission sync owns them.
  def replaceable_roles_of(user)
    user.user_roles.joins(:role)
        .where('NOT starts_with(roles.key, ?)', User::DERIVED_ROLE_KEY_PREFIX)
  end

  def check_authorization
    if %w[resend_invite create bulk_create].include?(action_name)
      keys = action_name == 'resend_invite' ? %w[users.manage users.update] : %w[users.manage users.create]
      keys << 'users.bulk_operations' if action_name == 'bulk_create'
      unless Current.service_authenticated != true && current_user && keys.all? { |key| current_user.has_permission?(key) }
        return respond_forbidden('Sem permissão para administrar convites.')
      end
      return true
    end
    return true if action_name == 'invitation_capabilities' && current_user
    # IMPORTANT: read actions stay gated on `users.read` (OPERATIONAL), not
    # `users.manage` (ADMINISTRATIVE). The Conversations screen needs to load
    # the attendant list/filters via GET /api/v1/users, so any role with
    # conversations.read receives users.read operationally (see User model's
    # OPERATIONAL_IMPLICATIONS). Gating these endpoints on users.manage would
    # 403 the attendant dropdown in Conversations — rejected by design.
    # The administrative gate (Settings > Agents) is keyed on users.manage and
    # IS enforced here, on top of the fine keys — see administrative_action?.
    # The frontend gate remains, but is no longer the only one.
    action_map = {
      'index' => 'users.read',
      'create' => 'users.create',
      'update' => 'users.update',
      'destroy' => 'users.delete',
      'bulk_create' => 'users.bulk_operations',
      'check_permission' => 'users.read',
      'role' => 'users.read',
      # CRM-210: standalone key, never implied by users.write.
      'set_password' => 'users.reset_password'
    }

    required_permission = action_map[action_name]
    if required_permission
      authorize_resource!('users', required_permission.split('.').last)
      # authorize_resource! renders on deny (truthy return) — performed? is the
      # halt signal; a second authorize after a render would DoubleRenderError.
      return false if performed?
      # Administrative user management (creating/deleting agents, batch
      # imports, role assignment) additionally requires users.manage — the
      # endpoint-level mirror of the frontend Settings > Agents gate. Reads and
      # self-service updates (no role CHANGE) stay on the fine keys alone.
      return authorize_resource!('users', 'manage') if administrative_action?

      return true
    end

    # Fail closed: an action with no explicit permission mapping must never be
    # implicitly authorized when it can mutate state. Read-only verbs (GET/HEAD)
    # carry no mutation risk and stay permissive so self/read endpoints keep
    # working; any other verb is denied unless it arrives through an already
    # authorized service or exempt channel (parity with authorize_resource!).
    return true if request.get? || request.head?
    return true if exempt_from_permission_check?
    return true if Current.service_authenticated == true

    respond_forbidden("You don't have permission to perform this action")
  end

  # Mutations that manage OTHER users (the Settings > Agents surface): create,
  # destroy, batch import, and any update that CHANGES the role set. The
  # community frontend sends `role` on every user update, so an update that
  # leaves the role set untouched must not trip the administrative gate (a
  # users.update-only caller renaming a user would 403 otherwise).
  def administrative_action?
    # CRM-210: set_password is administrative, like create/destroy.
    return true if %w[create destroy bulk_create set_password].include?(action_name)
    return false unless action_name == 'update' && params[:role].present?

    role_set_change?
  end

  # The question is not "is the submitted key one the target already holds?" but
  # "will update_user_role change what the target holds?" — it destroys EVERY
  # replaceable role before assigning, so resubmitting a role the target already
  # has still REVOKES any other one. Both are role management.
  def role_set_change?
    target = @user || User.find_by(id: params[:id])
    return true unless target&.has_role?(params[:role])

    replaceable_roles_of(target).where.not(roles: { key: params[:role] }).exists?
  end

  # Base relation of #index, before search, filters and sort. A deployment that
  # restricts the directory prepends an override here; nothing else may widen it.
  def users_index_scope
    User.all
  end

  # A lookup by id needs neither the ordering nor the includes of the #index scope.
  def fetch_user
    @user = users_index_scope.find(params[:id])
  end

  def allowed_user_params
    [:name, :email, :role, :availability, :password]
  end

  def user_params
    params.permit(allowed_user_params)
  end

  def new_user_params
    params.permit(:email, :name, :role, :availability, :password)
  end

  def permission_cache_key(user_id, permission_key)
    "authz:permission:user=#{user_id}:permission=#{permission_key}"
  end

  def role_cache_key(user_id)
    "authz:role:user=#{user_id}"
  end
end
