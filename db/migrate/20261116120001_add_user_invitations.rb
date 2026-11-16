class AddUserInvitations < ActiveRecord::Migration[7.1]
  def up
    raise 'users must use UUID identifiers' unless connection.columns(:users).find { |c| c.name == 'id' }.sql_type == 'uuid'
    %i[invited_at invitation_accepted_at invitation_sent_at invitation_last_requested_at].each do |field|
      add_column :users, field, :timestamptz, if_not_exists: true
    end
    create_table :user_invitation_deliveries, id: :uuid, if_not_exists: true do |t|
      t.references :user, type: :uuid, null: false, foreign_key: { on_delete: :cascade }
      t.references :requested_by, type: :uuid, foreign_key: { to_table: :users, on_delete: :nullify }
      t.string :origin, null: false, default: 'admin'
      t.string :status, null: false, default: 'queued'
      t.string :error_code
      t.timestamptz :requested_at, null: false
      t.timestamptz :started_at
      t.timestamptz :finished_at
      t.timestamptz :smtp_accepted_at
      t.timestamps
    end
    add_index :user_invitation_deliveries, [:user_id, :requested_at], if_not_exists: true
    add_index :user_invitation_deliveries, [:status, :requested_at], if_not_exists: true
    add_index :user_invitation_deliveries, :user_id, unique: true,
              where: "status IN ('queued', 'sending')", name: 'one_active_user_invitation', if_not_exists: true
    add_check_constraint :user_invitation_deliveries,
      "status IN ('queued','sending','sent','failed','uncertain','cancelled')",
      name: 'invitation_delivery_status', if_not_exists: true
  end

  def down
    drop_table :user_invitation_deliveries, if_exists: true
    %i[invited_at invitation_accepted_at invitation_sent_at invitation_last_requested_at].each do |field|
      remove_column :users, field, if_exists: true
    end
  end
end
