class UserInvitationDelivery < ApplicationRecord
  belongs_to :user
  belongs_to :requested_by, class_name: 'User', optional: true
  validates :status, inclusion: { in: %w[queued sending sent failed uncertain cancelled] }
  validates :origin, inclusion: { in: %w[admin self_recovery] }
  after_create_commit :dispatch

  def dispatch
    UserInvitationJob.perform_async(id)
  rescue StandardError
    # The durable outbox is recovered by the minute sweep. Do not log mail or tokens.
    Rails.logger.warn('Invitation queue unavailable; durable request retained')
  end
end
