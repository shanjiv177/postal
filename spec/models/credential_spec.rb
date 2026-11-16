# frozen_string_literal: true

require "rails_helper"

describe Credential do
  describe "allowed senders" do
    let(:credential) { build(:credential) }

    describe "normalisation" do
      it "strips, lowercases, removes blank lines and de-duplicates entries" do
        credential.allowed_senders_text = " Alice@Example.com \r\n\n  bob@example.com\nALICE@example.com\n"
        credential.valid?
        expect(credential.allowed_senders_text).to eq "alice@example.com\nbob@example.com"
      end

      it "stores nil when there are no entries" do
        credential.allowed_senders_text = " \r\n \n"
        credential.valid?
        expect(credential.allowed_senders_text).to be nil
      end
    end

    describe "validation" do
      it "is valid with no allowed senders" do
        expect(credential).to be_valid
      end

      it "is valid with full addresses" do
        credential.allowed_senders_text = "alice@example.com\nno-reply+news@mail.example.co.uk"
        expect(credential).to be_valid
      end

      [
        "example.com",
        "@example.com",
        "alice@",
        "alice@example",
        "alice@bob@example.com",
        "alice smith@example.com",
        "<alice@example.com>",
        "Alice <alice@example.com>",
        "alice@exa_mple.com",
      ].each do |entry|
        it "is invalid with #{entry.inspect}" do
          credential.allowed_senders_text = "valid@example.com\n#{entry}"
          expect(credential).not_to be_valid
          expect(credential.errors[:allowed_senders_text].join).to include entry.downcase
        end
      end
    end

    describe "#allowed_senders" do
      it "returns an empty array when unrestricted" do
        expect(credential.allowed_senders).to eq []
        expect(credential.restricted_senders?).to be false
      end

      it "returns the normalised entries" do
        credential.allowed_senders_text = "Alice@Example.com\nbob@example.com"
        expect(credential.allowed_senders).to eq ["alice@example.com", "bob@example.com"]
        expect(credential.restricted_senders?).to be true
      end

      it "is recalculated when the text changes" do
        credential.allowed_senders_text = "alice@example.com"
        expect(credential.allowed_senders).to eq ["alice@example.com"]
        credential.allowed_senders_text = "bob@example.com"
        expect(credential.allowed_senders).to eq ["bob@example.com"]
      end

      it "is recalculated when the credential is reloaded" do
        credential.allowed_senders_text = "alice@example.com"
        credential.save!
        expect(credential.allowed_senders).to eq ["alice@example.com"]
        Credential.where(id: credential.id).update_all(allowed_senders_text: "bob@example.com")
        expect(credential.reload.allowed_senders).to eq ["bob@example.com"]
      end
    end

    describe "#sender_allowed?" do
      before { credential.allowed_senders_text = "alice@example.com" }

      it "allows an address on the list, ignoring case" do
        expect(credential.sender_allowed?("alice@example.com")).to be true
        expect(credential.sender_allowed?("Alice@EXAMPLE.com")).to be true
      end

      it "does not allow other addresses on the same domain" do
        expect(credential.sender_allowed?("bob@example.com")).to be false
      end

      it "does not allow tagged versions of an address" do
        expect(credential.sender_allowed?("alice+news@example.com")).to be false
      end

      it "does not allow the address on a subdomain" do
        expect(credential.sender_allowed?("alice@mail.example.com")).to be false
      end
    end
  end
end
