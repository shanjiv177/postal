# frozen_string_literal: true

class AddAllowedSendersTextToCredentials < ActiveRecord::Migration[8.1]

  def change
    add_column :credentials, :allowed_senders_text, :text
  end

end
