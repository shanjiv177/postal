# frozen_string_literal: true

require "rails_helper"

RSpec.describe "CredentialsController", type: :request do
  let(:user) { create(:user, admin: true) }
  let(:organization) { create(:organization, owner: user) }
  let(:server) { create(:server, organization: organization) }
  let(:credentials_path) { "/org/#{organization.permalink}/servers/#{server.permalink}/credentials" }

  before do
    post "/login", params: { email_address: user.email_address, password: "passw0rd" }
  end

  describe "POST /org/:org/servers/:server/credentials" do
    it "saves the allowed senders" do
      post credentials_path, params: { credential: { type: "SMTP", name: "Newsletter", allowed_senders_text: "News@Example.com\r\n" } }
      expect(response).to redirect_to(credentials_path)
      expect(server.credentials.last.allowed_senders_text).to eq "news@example.com"
    end

    it "does not save invalid allowed senders" do
      expect do
        # The form is submitted with XHR and gets JSON back
        post credentials_path, params: { credential: { type: "SMTP", name: "Newsletter", allowed_senders_text: "example.com" } },
                               headers: { "Accept" => "application/json" }
      end.not_to change(Credential, :count)
      expect(response.status).to eq 422
      expect(JSON.parse(response.body)["form_errors"].join).to include("Allowed senders must only contain full e-mail addresses")
    end
  end

  describe "PATCH /org/:org/servers/:server/credentials/:credential" do
    let(:credential) { create(:credential, server: server, allowed_senders_text: "news@example.com") }

    it "updates the allowed senders" do
      patch "#{credentials_path}/#{credential.uuid}", params: { credential: { allowed_senders_text: "billing@example.com" } }
      expect(response).to redirect_to(credentials_path)
      expect(credential.reload.allowed_senders_text).to eq "billing@example.com"
    end

    it "removes the restriction when the allowed senders are cleared" do
      patch "#{credentials_path}/#{credential.uuid}", params: { credential: { allowed_senders_text: "" } }
      expect(credential.reload.allowed_senders_text).to be nil
    end
  end
end
