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

    context "when a single header value contains several addresses" do
      let!(:domain) { create(:domain, owner: server) }

      it "rejects the message if any address is not authenticated" do
        [
          "<someone@unverified.example>, <hello@#{domain.name}>",
          "Eve <someone@unverified.example>, Me <hello@#{domain.name}>",
          "hello@#{domain.name}, someone@unverified.example",
        ].each do |from|
          expect(authorizer.authorize(from: from, sender: nil)).to eq([nil, :unauthenticated_domain]), from
        end
      end

      it "accepts the message if every address is authenticated" do
        other_domain = create(:domain, owner: server)
        result = authorizer.authorize(from: "A <a@#{domain.name}>, B <b@#{other_domain.name}>", sender: nil)
        expect(result).to eq [domain, nil]
      end

      context "when the server is allowed to use the sender header" do
        let(:server) { create(:server, allow_sender: true) }

        it "rejects the message if any sender address is not authenticated" do
          result = authorizer.authorize(from: "someone@unverified.example",
                                        sender: "<someone@unverified.example>, <hello@#{domain.name}>")
          expect(result).to eq [nil, :unauthenticated_domain]
        end
      end
    end

    context "when parsing addresses" do
      let!(:domain) { create(:domain, owner: server) }

      it "accepts formats that are valid today" do
        [
          "hello@#{domain.name}",
          "Hello <hello@#{domain.name}>",
          "\"Smith, John\" <hello@#{domain.name}>",
          "Smith, John <hello@#{domain.name}>",
          "=?UTF-8?B?w4lyaWM=?= <hello@#{domain.name}>",
          "hello@#{domain.name} (Hello)",
          "Ériç <hello@#{domain.name}>".b,
          "\xC9ric <hello@#{domain.name}>".b, # Latin-1, which is not valid UTF-8
        ].each do |from|
          expect(authorizer.authorize(from: from, sender: nil)).to eq([domain, nil]), from.inspect
        end
      end

      it "rejects a header with no addresses" do
        expect(authorizer.authorize(from: "undisclosed-recipients:;", sender: nil)).to eq [nil, :unauthenticated_domain]
        expect(authorizer.authorize(from: "Smith", sender: nil)).to eq [nil, :unauthenticated_domain]
      end

      it "accepts a single address that cannot be parsed strictly, as before" do
        [
          "Joe [Work] <hello@#{domain.name}>",
          "x <hello@#{domain.name}> y",
          "<<hello@#{domain.name}",
        ].each do |from|
          expect(authorizer.authorize(from: from, sender: nil)).to eq([domain, nil]), from
        end
      end

      it "rejects a header that cannot be parsed and has more than one address" do
        [
          "Joe [Work] <someone@unverified.example>, <hello@#{domain.name}>",
          "<<someone@unverified.example>, <hello@#{domain.name}>",
          "Joe [Work] <hello@#{domain.name}>, <hello2@#{domain.name}>",
        ].each do |from|
          expect(authorizer.authorize(from: from, sender: nil)).to eq([nil, :unauthenticated_domain]), from
        end
      end
    end

    describe ".addresses_in" do
      it "returns every address in the header" do
        expect(described_class.addresses_in(["A <a@x.com>, b@y.com", "Smith, John <j@z.com>"])).to eq ["a@x.com", "b@y.com", "j@z.com"]
      end

      it "returns nothing for a missing header" do
        expect(described_class.addresses_in(nil)).to eq []
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

    context "when the credential is restricted to specific senders" do
      let!(:domain) { create(:domain, owner: server) }
      let(:credential) { create(:credential, server: server, allowed_senders_text: "alice@#{domain.name}") }

      it "accepts an allowed address" do
        expect(authorizer.authorize(from: "Alice <alice@#{domain.name}>", sender: nil)).to eq [domain, nil]
      end

      it "accepts an allowed address in a different case" do
        expect(authorizer.authorize(from: "ALICE@#{domain.name.upcase}", sender: nil)).to eq [domain, nil]
      end

      it "rejects another address on the same domain" do
        expect(authorizer.authorize(from: "bob@#{domain.name}", sender: nil)).to eq [nil, :sender_not_permitted]
      end

      it "rejects a tagged version of an allowed address" do
        expect(authorizer.authorize(from: "alice+news@#{domain.name}", sender: nil)).to eq [nil, :sender_not_permitted]
      end

      it "rejects a From header where only some addresses are allowed" do
        result = authorizer.authorize(from: "Bob <bob@#{domain.name}>, Alice <alice@#{domain.name}>", sender: nil)
        expect(result).to eq [nil, :sender_not_permitted]
      end

      it "rejects an allowed address on a domain the server can't send from" do
        credential.update!(allowed_senders_text: "alice@unverified.example")
        expect(authorizer.authorize(from: "alice@unverified.example", sender: nil)).to eq [nil, :unauthenticated_domain]
      end

      it "reports an unauthenticated domain when the address is neither allowed nor authenticated" do
        expect(authorizer.authorize(from: "eve@unverified.example", sender: nil)).to eq [nil, :unauthenticated_domain]
      end

      context "when the server has a domain that can be used for any address" do
        let!(:domain) { create(:domain, owner: server, use_for_any: true) }

        it "still only accepts allowed addresses" do
          expect(authorizer.authorize(from: "alice@#{domain.name}", sender: nil)).to eq [domain, nil]
          expect(authorizer.authorize(from: "bob@elsewhere.example", sender: nil)).to eq [nil, :sender_not_permitted]
        end
      end

      context "when the server is allowed to use the sender header" do
        let(:server) { create(:server, allow_sender: true) }

        it "accepts a message whose Sender is allowed" do
          result = authorizer.authorize(from: "bob@#{domain.name}", sender: "alice@#{domain.name}")
          expect(result).to eq [domain, nil]
        end

        it "rejects a message where neither From nor Sender is allowed" do
          result = authorizer.authorize(from: "bob@#{domain.name}", sender: "carol@#{domain.name}")
          expect(result).to eq [nil, :sender_not_permitted]
        end
      end

      context "when the server is not allowed to use the sender header" do
        it "ignores an allowed Sender" do
          result = authorizer.authorize(from: "bob@#{domain.name}", sender: "alice@#{domain.name}")
          expect(result).to eq [nil, :sender_not_permitted]
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
