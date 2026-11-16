# All OAuth issuers (password, MFA, SSO, refresh, authorization code) converge
# on AccessToken creation. A challenge alone does not reach this hook.
Rails.application.config.to_prepare do
  unless Doorkeeper::AccessToken.method_defined?(:accept_user_invitation)
    Doorkeeper::AccessToken.class_eval do
      before_create :accept_user_invitation
      def accept_user_invitation
        user = User.find_by(id: resource_owner_id)
        return unless user
        user.with_lock do
          UserInvitations.accept!(user)
          user.update!(sign_in_count: user.sign_in_count.to_i + 1,
                       last_sign_in_at: user.current_sign_in_at, current_sign_in_at: Time.current)
        end
      end
    end
  end
end
