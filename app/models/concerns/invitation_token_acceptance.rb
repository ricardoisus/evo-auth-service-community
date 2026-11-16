# Devise defines create_token directly on the User class from an included block;
# prepend is required to wrap it rather than being overwritten by that block.
module InvitationTokenAcceptance
  def create_token(*args, **kwargs)
    with_lock do
      UserInvitations.accept!(self)
      token = super
      save!
      token
    end
  end
end
