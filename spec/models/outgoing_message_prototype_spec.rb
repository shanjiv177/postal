# frozen_string_literal: true

require "rails_helper"

describe OutgoingMessagePrototype do
  let(:server) { create(:server) }
  it "should create a new message" do
    domain = create(:domain, owner: server)
    prototype = OutgoingMessagePrototype.new(server, "127.0.0.1", "TestSuite", {
      from: "test@#{domain.name}",
      to: "test@example.com",
      subject: "Test Message",
      plain_body: "A plain body!"
    })

    expect(prototype.valid?).to be true
    message = prototype.create_message("test@example.com")
    expect(message).to be_a Hash
    expect(message[:id]).to be_a Integer
    expect(message[:token]).to be_a String
  end

  describe "#create_message" do
    it "uses the first From address as the envelope sender when there are several" do
      domain = create(:domain, owner: server)
      other_domain = create(:domain, owner: server)
      prototype = OutgoingMessagePrototype.new(server, "127.0.0.1", "TestSuite", {
        from: "a@#{domain.name}, B <b@#{other_domain.name}>",
        to: "test@example.com",
        subject: "Test Message",
        plain_body: "A plain body!"
      })

      expect(prototype.valid?).to be true
      result = prototype.create_message("test@example.com")
      expect(server.message(result[:id]).mail_from).to eq "a@#{domain.name}"
    end

    it "keeps using the address from a single From value" do
      domain = create(:domain, owner: server)
      prototype = OutgoingMessagePrototype.new(server, "127.0.0.1", "TestSuite", {
        from: "Joe [Work] <joe@#{domain.name}>",
        to: "test@example.com",
        subject: "Test Message",
        plain_body: "A plain body!"
      })

      result = prototype.create_message("test@example.com")
      expect(server.message(result[:id]).mail_from).to eq "joe@#{domain.name}"
    end
  end

  describe "#domain" do
    let(:domain) { create(:domain, owner: server) }

    def build_prototype(**attributes)
      OutgoingMessagePrototype.new(server, "127.0.0.1", "TestSuite", {
        to: "test@example.com",
        subject: "Test Message",
        plain_body: "A plain body!"
      }.merge(attributes))
    end

    it "returns the domain for an authenticated From address" do
      expect(build_prototype(from: "Test <test@#{domain.name}>").domain).to eq domain
    end

    it "returns nil for an unauthenticated From address" do
      prototype = build_prototype(from: "test@unverified.example")
      expect(prototype.domain).to be nil
      expect(prototype.valid?).to be false
      expect(prototype.errors).to include "UnauthenticatedFromAddress"
    end

    context "when the From address is unauthenticated but the Sender address is" do
      it "returns nil when the server does not allow the Sender header" do
        expect(build_prototype(from: "test@unverified.example", sender: "test@#{domain.name}").domain).to be nil
      end

      context "when the server allows the Sender header" do
        let(:server) { create(:server, allow_sender: true) }

        it "returns the Sender address's domain" do
          expect(build_prototype(from: "test@unverified.example", sender: "test@#{domain.name}").domain).to eq domain
        end
      end
    end
  end
end
