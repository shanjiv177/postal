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

  # @param from [String, Array<String>, nil] the From header value(s)
  # @param sender [String, Array<String>, nil] the Sender header value(s)
  # @return [Array(Domain, nil), Array(nil, Symbol)] the domain to authenticate
  #   the message with, or nil and the reason the sender was not authorised
  def authorize(from:, sender:)
    headers = [from]
    headers << sender if @server.allow_sender?

    headers.each do |header|
      values = header.is_a?(Array) ? header : [header.to_s]
      domains = values.map { |value| @server.authenticated_domain_for_address(value) }.compact
      next unless domains.size == values.size

      return domains.first ? [domains.first, nil] : [nil, :unauthenticated_domain]
    end

    [nil, :unauthenticated_domain]
  end

end
