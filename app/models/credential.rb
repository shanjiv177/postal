# frozen_string_literal: true

# == Schema Information
#
# Table name: credentials
#
#  id                   :integer          not null, primary key
#  server_id            :integer
#  key                  :string(255)
#  type                 :string(255)
#  name                 :string(255)
#  options              :text(65535)
#  last_used_at         :datetime
#  created_at           :datetime
#  updated_at           :datetime
#  hold                 :boolean          default(FALSE)
#  uuid                 :string(255)
#  allowed_senders_text :text(65535)
#

class Credential < ApplicationRecord

  include HasUUID

  belongs_to :server

  TYPES = %w[SMTP API SMTP-IP].freeze

  # A full e-mail address: a local part without whitespace or address
  # punctuation, and a domain made of at least two lowercase labels.
  ALLOWED_SENDER_FORMAT = /\A[^\s@<>,;"()]+@[a-z0-9-]+(\.[a-z0-9-]+)+\z/

  validates :key, presence: true, uniqueness: { case_sensitive: false }
  validates :type, inclusion: { in: TYPES }
  validates :name, presence: true
  validate :validate_key_cannot_be_changed
  validate :validate_key_for_smtp_ip
  validate :validate_allowed_senders

  serialize :options, type: Hash

  before_validation :generate_key
  before_validation :normalise_allowed_senders_text

  def generate_key
    return if type == "SMTP-IP"
    return if persisted?

    self.key = SecureRandom.alphanumeric(24)
  end

  def to_param
    uuid
  end

  def use
    update_column(:last_used_at, Time.now)
  end

  def usage_type
    if last_used_at.nil?
      "Unused"
    elsif last_used_at < 1.year.ago
      "Inactive"
    elsif last_used_at < 6.months.ago
      "Dormant"
    elsif last_used_at < 1.month.ago
      "Quiet"
    else
      "Active"
    end
  end

  def to_smtp_plain
    Base64.encode64("\0XX\0#{key}").strip
  end

  def ipaddr
    return unless type == "SMTP-IP"

    @ipaddr ||= IPAddr.new(key)
  rescue IPAddr::InvalidAddressError
    nil
  end

  # The addresses this credential may send from, lowercased. An empty array
  # means the credential is not restricted.
  #
  # @return [Array<String>]
  def allowed_senders
    @allowed_senders ||= allowed_senders_text.to_s.split(/\r?\n/).map { |entry| entry.strip.downcase }.reject(&:blank?).uniq
  end

  def allowed_senders_text=(value)
    @allowed_senders = nil
    super
  end

  def restricted_senders?
    allowed_senders.any?
  end

  # Is the given address on this credential's list of allowed senders? Only
  # exact (case-insensitive) matches count.
  #
  # @param address [String] a bare e-mail address
  # @return [Boolean]
  def sender_allowed?(address)
    allowed_senders.include?(address.to_s.downcase)
  end

  def reload(*)
    @allowed_senders = nil
    super
  end

  private

  def normalise_allowed_senders_text
    self.allowed_senders_text = allowed_senders.empty? ? nil : allowed_senders.join("\n")
  end

  def validate_allowed_senders
    invalid = allowed_senders.grep_v(ALLOWED_SENDER_FORMAT)
    return if invalid.empty?

    errors.add :allowed_senders_text, "must only contain full e-mail addresses, one per line " \
                                      "(not valid: #{invalid.join(', ')})"
  end

  def validate_key_cannot_be_changed
    return if new_record?
    return unless key_changed?
    return if type == "SMTP-IP"

    errors.add :key, "cannot be changed"
  end

  def validate_key_for_smtp_ip
    return unless type == "SMTP-IP"

    IPAddr.new(key.to_s)
  rescue IPAddr::InvalidAddressError
    errors.add :key, "must be a valid IPv4 or IPv6 address"
  end

end
