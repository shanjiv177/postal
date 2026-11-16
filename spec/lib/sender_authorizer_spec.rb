# frozen_string_literal: true

require "rails_helper"

describe SenderAuthorizer do
  let(:server) { create(:server) }
  let(:credential) { create(:credential, server: server) }

  subject(:authorizer) { described_class.new(server: server, credential: credential) }

  describe "#authorize" do
    context "when none of the from addresses have a valid domain" do
      it "returns the unauthenticated_domain reason" do
        expect(authorizer.authorize(from: "test@lemons.com", sender: nil)).to eq [nil, :unauthenticated_domain]
      end
    end

    context "when the from address has a valid domain" do
      it "returns the domain" do
        domain = create(:domain, owner: server)
        expect(authorizer.authorize(from: "hello@#{domain.name}", sender: nil)).to eq [domain, nil]
      end

      it "returns the domain when the address includes a name" do
        domain = create(:domain, owner: server)
        expect(authorizer.authorize(from: "Hello <hello@#{domain.name}>", sender: nil)).to eq [domain, nil]
      end
    end

    context "when there is no from address" do
      it "returns the unauthenticated_domain reason" do
        expect(authorizer.authorize(from: nil, sender: nil)).to eq [nil, :unauthenticated_domain]
        expect(authorizer.authorize(from: [], sender: nil)).to eq [nil, :unauthenticated_domain]
      end
    end

    context "when there are multiple from addresses" do
      context "when none of them match a domain" do
        it "returns the unauthenticated_domain reason" do
          result = authorizer.authorize(from: ["hello@lemons.com", "hello@apples.com"], sender: nil)
          expect(result).to eq [nil, :unauthenticated_domain]
        end
      end

      context "when some but not all match" do
        it "returns the unauthenticated_domain reason" do
          domain = create(:domain, owner: server)
          result = authorizer.authorize(from: ["hello@#{domain.name}", "hello@lemons.com"], sender: nil)
          expect(result).to eq [nil, :unauthenticated_domain]
        end
      end

      context "when all match" do
        it "returns the first domain that matched" do
          domain1 = create(:domain, owner: server)
          domain2 = create(:domain, owner: server)
          result = authorizer.authorize(from: ["hello@#{domain1.name}", "hello@#{domain2.name}"], sender: nil)
          expect(result).to eq [domain1, nil]
        end
      end
    end

    context "when the server has a domain that can be used for any address" do
      it "returns that domain for any from address" do
        domain = create(:domain, owner: server, use_for_any: true)
        expect(authorizer.authorize(from: "hello@lemons.com", sender: nil)).to eq [domain, nil]
      end
    end

    context "when the server is not allowed to use the sender header" do
      context "when the sender header has a valid address" do
        it "does not return the domain" do
          domain = create(:domain, owner: server)
          result = authorizer.authorize(from: "hello@lemons.com", sender: "hello@#{domain.name}")
          expect(result).to eq [nil, :unauthenticated_domain]
        end
      end
    end

    context "when the server is allowed to use the sender header" do
      let(:server) { create(:server, allow_sender: true) }

      context "when none of the from addresses match but sender domains do" do
        it "returns the domain that does match" do
          domain = create(:domain, owner: server)
          result = authorizer.authorize(from: "hello@lemons.com", sender: "hello@#{domain.name}")
          expect(result).to eq [domain, nil]
        end
      end

      context "when neither the from nor the sender addresses match" do
        it "returns the unauthenticated_domain reason" do
          result = authorizer.authorize(from: "hello@lemons.com", sender: "hello@apples.com")
          expect(result).to eq [nil, :unauthenticated_domain]
        end
      end
    end

    context "when no credential is given" do
      subject(:authorizer) { described_class.new(server: server) }

      it "authorises the same way" do
        domain = create(:domain, owner: server)
        expect(authorizer.authorize(from: "hello@#{domain.name}", sender: nil)).to eq [domain, nil]
      end
    end
  end
end
