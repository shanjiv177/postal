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
  # can send from. If not, and the server allows it, every address in the
  # Sender header must instead.
  #
  # @param from [String, Array<String>, nil] the From header value(s)
  # @param sender [String, Array<String>, nil] the Sender header value(s)
  # @return [Array(Domain, nil), Array(nil, Symbol)] the domain to authenticate
  #   the message with, or nil and the reason the sender was not authorised
  def authorize(from:, sender:)
    headers = [from]
    headers << sender if @server.allow_sender?

    headers.each do |header|
      addresses = addresses_from(header)
      next if addresses.empty?

      domains = addresses.map { |address| @server.authenticated_domain_for_address(address) }
      next if domains.include?(nil)

      return [domains.first, nil]
    end

    [nil, :unauthenticated_domain]
  end

  # Extract every e-mail address from a header. A single header value can
  # hold several addresses (e.g. "A <a@x.com>, B <b@y.com>"), so each value is
  # parsed as an address list rather than as one address.
  #
  # Entries with no domain are ignored. They come from display names with an
  # unquoted comma ("Smith, John <john@x.com>" gives "Smith" and
  # "john@x.com") and can't claim to be from any domain.
  #
  # Some senders use display names that aren't valid RFC 5322, such as
  # "Joe [Work] <joe@x.com>", which can't be parsed as an address list. A
  # value like that with a single "@" can only hold one address, so it is read
  # the lenient way Postal always has. One with several "@"s might hide an
  # extra address, so nothing is returned and the header is rejected.
  #
  # @param header [String, Array<String>, nil]
  # @return [Array<String>] the addresses, or an empty array if there are none
  #   or the header can't be read safely
  def self.addresses_in(header)
    Array(header).flat_map do |value|
      value = value.to_s.dup.force_encoding(Encoding::UTF_8).scrub
      begin
        Mail::AddressList.new(value).addresses.select { |address| address.domain.present? }.map(&:address)
      rescue Mail::Field::ParseError
        return [] unless value.count("@") == 1

        [Postal::Helpers.strip_name_from_address(value)]
      end
    end
  end

  private

  def addresses_from(header)
    self.class.addresses_in(header)
  end

end
