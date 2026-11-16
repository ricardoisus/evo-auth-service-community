# The AgentBuilder class is responsible for creating a new agent (user) and assigning their role.
class AgentBuilder
  pattr_initialize [:email, :password, { name: '' }, :inviter, { role: :agent }, { availability: :offline }]

  # Creates a user and assigns their role in a transaction.
  # @return [User] the created or found user.
  def perform
    ActiveRecord::Base.transaction do
      @user = find_or_create_user
      assign_role
      UserInvitations.reserve!(@user, actor: inviter) if password.blank?
    end
    @user
  end

  private

  def find_or_create_user
    user = User.from_email(email)
    raise UserInvitations::Error.new('USER_NOT_CREATED', 422) if user
    raise UserInvitations::Error.new('INVITATIONS_DISABLED', 503) if password.blank? && !UserInvitations.enabled?

    generated_password = password.presence || "1!aA#{SecureRandom.alphanumeric(12)}"
    user = User.new(email: email, name: name, password: generated_password, invited_at: password.blank? ? Time.current : nil)
    user.skip_confirmation!
    user.save!
    user
  end

  def assign_role
    system_role = Role.find_by(key: role)
    raise UserInvitations::Error.new('USER_NOT_CREATED', 422) unless system_role
    if inviter && !inviter.roles.exists?(key: 'super_admin')
      allowed = system_role.permission_keys.all? { |key| inviter.has_permission?(key) }
      raise UserInvitations::Error.new('USER_NOT_CREATED', 422) if system_role.key == 'super_admin' || !allowed
    end

    existing = @user.user_roles.joins(:role).where(roles: { system: false })
    existing.destroy_all if existing.exists?

    UserRole.assign_role_to_user(@user, system_role, inviter)
  end
end
