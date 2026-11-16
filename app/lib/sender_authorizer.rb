# frozen_string_literal: true

# Decides whether a message may be sent from the addresses in its From
# (and, when the server allows it, Sender) header, and which of the server's
# domains should be used to authenticate it.
#
# This is used by every route that accepts outgoing mail with a credential
# (SMTP, the legacy send API and the web UI) so that the rules are the same
# everywhere.
class SenderAuthorizer

  # @param server [Server] the server the message is being sent through
  # @param credential [Credential, nil] the credential used to send the message
  def initialize(server:, credential: nil)
    @server = server
    @credential = credential
  end

  # Every address in the From header must belong to a domain that the server
  # can send from and, if the credential is restricted, be one of the
  # credential's allowed senders. If not, and the server allows it, every
  # address in the Sender header must meet the same conditions instead.
  #
  # @param from [String, Array<String>, nil] the From header value(s)
  # @param sender [String, Array<String>, nil] the Sender header value(s)
  # @return [Array(Domain, nil), Array(nil, Symbol)] the domain to authenticate
  #   the message with, or nil and the reason the sender was not authorised:
  #   :unauthenticated_domain or :sender_not_permitted
  def authorize(from:, sender:)
    headers = [from]
    headers << sender if @server.allow_sender?

    sender_not_permitted = false
    headers.each do |header|
      addresses = addresses_from(header)
      next if addresses.empty?

      domains = addresses.map { |address| @server.authenticated_domain_for_address(address) }
      next if domains.include?(nil)

      unless addresses.all? { |address| permitted_by_credential?(address) }
        sender_not_permitted = true
        next
      end

      return [domains.first, nil]
    end

    [nil, sender_not_permitted ? :sender_not_permitted : :unauthenticated_domain]
  end

  private

  def permitted_by_credential?(address)
    return true if @credential.nil? || !@credential.restricted_senders?

    @credential.sender_allowed?(address)
  end

  # Extract every e-mail address from a header. A single header value can
  # hold several addresses (e.g. "A <a@x.com>, B <b@y.com>"), so each value is
  # parsed as an address list rather than as one address.
  #
  # Entries with no domain are ignored. They come from display names with an
  # unquoted comma ("Smith, John <john@x.com>" gives "Smith" and
  # "john@x.com") and can't claim to be from any domain.
  #
  # @param header [String, Array<String>, nil]
  # @return [Array<String>] the addresses, or an empty array if there are none
  #   or any value cannot be parsed
  def addresses_from(header)
    Array(header).flat_map do |value|
      value = value.to_s.dup.force_encoding(Encoding::UTF_8).scrub
      Mail::AddressList.new(value).addresses.select { |address| address.domain.present? }.map(&:address)
    end
  rescue Mail::Field::ParseError
    []
  end

end
