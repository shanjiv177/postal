# frozen_string_literal: true

require "rails_helper"

RSpec.describe "credentials/index", type: :view do
  let(:user) { create(:user, admin: true) }
  let(:organization) { create(:organization, owner: user) }
  let(:server) { create(:server, organization: organization) }

  before do
    assign(:organization, organization)
    assign(:server, server)
    without_partial_double_verification do
      allow(view).to receive(:organization).and_return(organization)
      allow(view).to receive(:current_user).and_return(user)
      allow(view).to receive(:page_title).and_return(["Postal"])
    end
  end

  it "labels only the credentials that are restricted to specific senders" do
    unrestricted = create(:credential, server: server, name: "Unrestricted")
    restricted = create(:credential, server: server, name: "Newsletter", allowed_senders_text: "news@example.com")
    assign(:credentials, [unrestricted, restricted])
    render
    expect(rendered.scan(">Restricted<").size).to eq 1
  end
end
